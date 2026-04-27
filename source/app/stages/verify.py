"""文件说明：验证阶段实现（差分验证 agent）。

执行模式（已锁定）：
- 不重新 clone 仓库，不重新构建第二个镜像
- 复用 BuildArtifact.docker_image_tag，挂载 workspace
- 两次独立的 docker run --rm，环境变量 PATCH_MODE=pre|post
- pre 模式：git reset --hard && bash build.sh && trigger
- post 模式：git reset --hard && git apply patch.diff && bash build.sh && trigger
- 两次执行的日志契约与 PoC 一致（target_binary= / execution_exit_code= / stdout_begin/end 等）
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ModuleNotFoundError:  # pragma: no cover
    Environment = None
    FileSystemLoader = None
    StrictUndefined = None

from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.schemas.poc_artifact import PoCArtifact
from app.schemas.verify_result import VerifyResult
from app.tools.docker_tools import DockerRunRequest, DockerTool
from app.tools.file_tools import FileTool
from app.tools.log_parsing import (
    extract_block,
    extract_execution_observation,
    match_patterns,
)
from app.tools.patch_tools import find_patch_diff
from app.tools.process_tools import ProcessTool


class VerifyStagePaths:
    """Centralized path layout for the verify stage."""

    def __init__(self, workspace: str) -> None:
        self.workspace_root = Path(workspace)
        self.repo_dir = self.workspace_root / "repo"
        self.artifacts_dir = self.workspace_root / "artifacts"
        self.build_dir = self.artifacts_dir / "build"
        self.poc_dir = self.artifacts_dir / "poc"
        self.verify_dir = self.artifacts_dir / "verify"

        # 输入参考
        self.run_verify_yaml = self.poc_dir / "run_verify.yaml"
        self.poc_artifact_yaml = self.poc_dir / "poc_artifact.yaml"
        self.build_artifact_yaml = self.build_dir / "build_artifact.yaml"

        # 输出
        self.verify_dockerfile = self.verify_dir / "Dockerfile"
        self.verify_run_script = self.verify_dir / "verify_run.sh"
        self.patch_diff_copy = self.verify_dir / "patch.diff"
        self.pre_patch_log = self.verify_dir / "pre_patch.log"
        self.post_patch_log = self.verify_dir / "post_patch.log"
        self.verify_context_yaml = self.verify_dir / "verify_context.yaml"
        self.verify_plan_yaml = self.verify_dir / "verify_plan.yaml"
        self.verify_result_yaml = self.verify_dir / "verify_result.yaml"


class VerifyContext(BaseModel):
    """Evidence aggregated from prior stages, used to plan verify."""

    cve_id: str
    docker_image_tag: str
    chosen_vulnerable_ref: str
    chosen_fixed_ref: str
    project_dir_inside_image: str = Field(
        default="",
        description="容器内仓库路径，来源于 BuildArtifact 推导或默认 ${PROJECT_DIR}",
    )
    build_script_in_image: str = Field(
        default="/workspace/artifacts/build/build.sh",
        description="容器内可调用的 build.sh 路径",
    )
    target_binary: str
    trigger_command: str
    expected_stdout_patterns: List[str] = Field(default_factory=list)
    expected_stderr_patterns: List[str] = Field(default_factory=list)
    expected_stack_keywords: List[str] = Field(default_factory=list)
    expected_exit_code: Optional[int] = None
    expected_crash_type: str = ""
    patch_diff_path: str
    poc_run_verify_eligible: bool = True
    poc_run_verify_reason: str = ""


class VerifyPlan(BaseModel):
    """Deterministic execution plan for pre/post verify runs."""

    image_tag: str
    pre_run_command: str
    post_run_command: str
    environment_variables: Dict[str, str] = Field(default_factory=dict)
    expected_stdout_patterns: List[str] = Field(default_factory=list)
    expected_stderr_patterns: List[str] = Field(default_factory=list)
    expected_stack_keywords: List[str] = Field(default_factory=list)
    expected_exit_code: Optional[int] = None
    expected_crash_type: str = ""
    patch_apply_command: str = "git apply /workspace/artifacts/verify/patch.diff"
    repo_reset_command: str = "git reset --hard && git clean -fd"
    rebuild_command: str = "bash /workspace/artifacts/build/build.sh"
    pre_log_path: str
    post_log_path: str


class VerifyStage:
    """Vulnerability verification orchestrator."""

    def __init__(
        self,
        docker_tool: DockerTool | None = None,
        process_tool: ProcessTool | None = None,
        file_tool: FileTool | None = None,
    ) -> None:
        self.process_tool = process_tool or ProcessTool()
        self.docker_tool = docker_tool or DockerTool(process_tool=self.process_tool)
        self.file_tool = file_tool or FileTool()

    # ----- 公共入口 -----
    def run(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        poc: PoCArtifact,
        workspace: str,
    ) -> VerifyResult:
        paths = VerifyStagePaths(workspace)
        self.file_tool.ensure_dir(str(paths.verify_dir))

        try:
            context = self.collect_verify_context(knowledge, build, poc, paths)
        except Exception as error:
            return self._stage_exception("collect_verify_context", error, paths)

        self.file_tool.safe_persist(
            str(paths.verify_context_yaml),
            yaml.safe_dump(context.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            description="verify_context.yaml",
        )

        short_circuit = self._short_circuit_if_ineligible(context, paths)
        if short_circuit is not None:
            self.file_tool.safe_persist(
                str(paths.verify_result_yaml),
                yaml.safe_dump(short_circuit.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
                description="verify_result.yaml (short-circuit)",
            )
            return short_circuit

        try:
            plan = self.plan_verify(context, paths)
        except Exception as error:
            return self._stage_exception("plan_verify", error, paths)

        self.file_tool.safe_persist(
            str(paths.verify_plan_yaml),
            yaml.safe_dump(plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            description="verify_plan.yaml",
        )

        try:
            self._render_dockerfile(context, paths)
            self._render_verify_run_script(context, plan, paths)
            self._copy_patch_diff(context, paths)
        except Exception as error:
            return self._stage_exception("render_or_copy", error, paths)

        try:
            execute_result = self._execute_verify(context, plan, paths)
        except Exception as error:
            return self._stage_exception("execute_verify", error, paths)

        try:
            result = self._decide_verdict(execute_result, context)
        except Exception as error:
            return self._stage_exception("decide_verdict", error, paths)

        self.file_tool.safe_persist(
            str(paths.verify_result_yaml),
            yaml.safe_dump(result.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            description="verify_result.yaml",
        )
        return result

    # ----- 五层结构 -----
    def collect_verify_context(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        poc: PoCArtifact,
        paths: VerifyStagePaths,
    ) -> VerifyContext:
        """Collect evidence for verify planning."""

        patch_diff = find_patch_diff(knowledge.cve_id)
        patch_diff_path = str(patch_diff) if patch_diff is not None else ""

        eligible, reason = self._read_run_verify_yaml(paths)

        return VerifyContext(
            cve_id=knowledge.cve_id,
            docker_image_tag=build.docker_image_tag or "",
            chosen_vulnerable_ref=build.chosen_vulnerable_ref or "",
            chosen_fixed_ref=build.chosen_fixed_ref or "",
            project_dir_inside_image="",  # 留空，模板内用 ${PROJECT_DIR}
            target_binary=poc.target_binary or build.binary_or_entrypoint or build.expected_binary_path or "",
            trigger_command=poc.trigger_command or "",
            expected_stdout_patterns=list(poc.expected_stdout_patterns),
            expected_stderr_patterns=list(poc.expected_stderr_patterns),
            expected_stack_keywords=list(knowledge.expected_stack_keywords),
            expected_exit_code=poc.expected_exit_code,
            expected_crash_type=poc.observed_crash_type or "",
            patch_diff_path=patch_diff_path,
            poc_run_verify_eligible=eligible,
            poc_run_verify_reason=reason,
        )

    def plan_verify(self, context: VerifyContext, paths: VerifyStagePaths) -> VerifyPlan:
        """Build a deterministic pre/post execution plan."""

        # TODO(verify-agent-llm): future LLM-based replanner stub
        # planner = build_chat_model("verify_agent")
        # 当前阶段使用确定性规则，不接 LLM。

        return VerifyPlan(
            image_tag=context.docker_image_tag,
            pre_run_command=context.trigger_command,
            post_run_command=context.trigger_command,
            environment_variables={},
            expected_stdout_patterns=list(context.expected_stdout_patterns),
            expected_stderr_patterns=list(context.expected_stderr_patterns),
            expected_stack_keywords=list(context.expected_stack_keywords),
            expected_exit_code=context.expected_exit_code,
            expected_crash_type=context.expected_crash_type,
            pre_log_path=str(paths.pre_patch_log),
            post_log_path=str(paths.post_patch_log),
        )

    def _execute_verify(
        self,
        context: VerifyContext,
        plan: VerifyPlan,
        paths: VerifyStagePaths,
    ) -> dict:
        pre_result = self._run_one_pass("pre", context, plan, paths)
        post_result = self._run_one_pass("post", context, plan, paths)
        return {"pre": pre_result, "post": post_result}

    def _decide_verdict(self, execute_result: dict, context: VerifyContext) -> VerifyResult:
        pre = execute_result["pre"]
        post = execute_result["post"]

        # patch apply 失败 → inconclusive
        patch_apply_exit_code = post.get("patch_apply_exit_code")
        patch_apply_success = patch_apply_exit_code == 0
        if patch_apply_exit_code is not None and not patch_apply_success:
            return self._build_result(
                pre=pre,
                post=post,
                verdict="inconclusive",
                reason=f"patch_apply_failed: exit_code={patch_apply_exit_code}",
                confidence="low",
                evidence_summary="post mode failed at git apply step; pre/post comparison skipped.",
                patch_apply_success=False,
                pre_triggered=False,
                post_clean=False,
            )

        # 任何一次脚本不 well_formed → inconclusive
        if not pre.get("log_well_formed") or not post.get("log_well_formed"):
            return self._build_result(
                pre=pre,
                post=post,
                verdict="inconclusive",
                reason="log_not_well_formed: pre={}, post={}".format(
                    pre.get("log_well_formed"), post.get("log_well_formed")
                ),
                confidence="low",
                evidence_summary="At least one pass produced an incomplete log; cannot compare reliably.",
                patch_apply_success=patch_apply_success,
                pre_triggered=False,
                post_clean=False,
            )

        # pre / post 触发判定
        pre_triggered = self._is_triggered(pre, context)
        post_triggered = self._is_triggered(post, context)
        post_clean = not post_triggered

        if pre_triggered and post_clean:
            verdict = "success"
            reason = "pre triggered, post clean — vulnerability reproduced and patch verified"
            confidence = self._compute_confidence(pre, post)
            evidence_summary = (
                f"pre crash_type={pre.get('crash_type')}, exit_code={pre.get('exit_code')}; "
                f"post exit_code={post.get('exit_code')}."
            )
        elif not pre_triggered:
            verdict = "failed"
            reason = "pre_not_triggered"
            confidence = "low"
            evidence_summary = "pre mode did not exhibit any expected error/keyword/crash signal."
        elif not post_clean:
            verdict = "failed"
            reason = "post_still_triggered"
            confidence = "medium"
            evidence_summary = "post mode still showed trigger signals after applying patch."
        else:
            verdict = "inconclusive"
            reason = "unexpected_state"
            confidence = "low"
            evidence_summary = "Decision logic reached an unexpected branch."

        return self._build_result(
            pre=pre,
            post=post,
            verdict=verdict,
            reason=reason,
            confidence=confidence,
            evidence_summary=evidence_summary,
            patch_apply_success=patch_apply_success,
            pre_triggered=pre_triggered,
            post_clean=post_clean,
        )

    # ----- 工具方法 -----
    def _render_dockerfile(self, context: VerifyContext, paths: VerifyStagePaths) -> None:
        rendered = self._render_template(
            "verify.Dockerfile.j2",
            {"base_image_tag": context.docker_image_tag},
        )
        # Dockerfile 是致命落盘，落盘失败要抛
        self.file_tool.write_text(str(paths.verify_dockerfile), rendered)

    def _render_verify_run_script(
        self,
        context: VerifyContext,
        plan: VerifyPlan,
        paths: VerifyStagePaths,
    ) -> None:
        rendered = self._render_template(
            "verify_run.sh.j2",
            {
                "target_binary": context.target_binary,
                "run_command": plan.pre_run_command,
                "repo_reset_command": plan.repo_reset_command,
                "rebuild_command": plan.rebuild_command,
                "patch_apply_command": plan.patch_apply_command,
                "project_dir_var": context.project_dir_inside_image or "${PROJECT_DIR}",
            },
        )
        self.file_tool.write_text(str(paths.verify_run_script), rendered)

    def _copy_patch_diff(self, context: VerifyContext, paths: VerifyStagePaths) -> None:
        src = Path(context.patch_diff_path)
        if not src.exists():
            raise FileNotFoundError(f"patch.diff vanished: {src}")
        self.file_tool.write_text(
            str(paths.patch_diff_copy),
            src.read_text(encoding="utf-8", errors="replace"),
        )

    def _run_one_pass(
        self,
        mode: str,
        context: VerifyContext,
        plan: VerifyPlan,
        paths: VerifyStagePaths,
    ) -> dict:
        """Run verify_run.sh once with PATCH_MODE=mode and return parsed observation."""

        request = DockerRunRequest(
            image_tag=plan.image_tag,
            command=["bash", "/workspace/artifacts/verify/verify_run.sh"],
            workspace=str(paths.workspace_root.resolve()),
            environment={"PATCH_MODE": mode},
        )
        docker_result = self.docker_tool.run_container(request)
        full_log = self._compose_pass_log(docker_result, mode, request)

        log_path = paths.pre_patch_log if mode == "pre" else paths.post_patch_log
        self.file_tool.safe_persist(
            str(log_path),
            full_log,
            description=f"{mode}_patch.log",
        )

        observation = extract_execution_observation(docker_result.stdout)
        haystack = observation["observed_stdout"] + "\n" + observation["observed_stderr"]
        matched_error = match_patterns(haystack, plan.expected_stderr_patterns)
        matched_stack = match_patterns(haystack, plan.expected_stack_keywords)

        required_markers = ("stdout_begin", "stdout_end", "stderr_begin", "stderr_end")
        log_well_formed = all(marker in docker_result.stdout for marker in required_markers)
        script_finished = "execution_exit_code=" in docker_result.stdout

        patch_apply_exit_code = (
            self._parse_patch_apply_exit_code(docker_result.stdout) if mode == "post" else None
        )
        build_rebuild_exit_code = self._parse_build_rebuild_exit_code(docker_result.stdout)

        return {
            "exit_code": observation["observed_exit_code"],
            "stdout": observation["observed_stdout"],
            "stderr": observation["observed_stderr"],
            "crash_type": observation["observed_crash_type"],
            "matched_error_patterns": matched_error,
            "matched_stack_keywords": matched_stack,
            "patch_apply_exit_code": patch_apply_exit_code,
            "build_rebuild_exit_code": build_rebuild_exit_code,
            "log_path": str(log_path),
            "raw_log": full_log,
            "log_well_formed": log_well_formed,
            "script_finished": script_finished,
        }

    def _compose_pass_log(self, docker_result, mode: str, request: DockerRunRequest) -> str:
        parts = [
            f"=== verify pass: {mode} ===",
            f"image_tag={request.image_tag}",
            f"command={request.command}",
            f"workspace={request.workspace}",
            f"environment={request.environment}",
            f"docker_exit_code={docker_result.exit_code}",
            f"docker_success={docker_result.success}",
            "=== stdout ===",
            docker_result.stdout,
            "=== stderr ===",
            docker_result.stderr,
        ]
        return "\n".join(parts)

    def _parse_patch_apply_exit_code(self, log: str) -> Optional[int]:
        match = re.search(r"^patch_apply_exit_code=(-?\d+)$", log, re.MULTILINE)
        return int(match.group(1)) if match else None

    def _parse_build_rebuild_exit_code(self, log: str) -> Optional[int]:
        match = re.search(r"^build_rebuild_exit_code=(-?\d+)$", log, re.MULTILINE)
        return int(match.group(1)) if match else None

    def _short_circuit_if_ineligible(
        self,
        context: VerifyContext,
        paths: VerifyStagePaths,
    ) -> Optional[VerifyResult]:
        if not context.poc_run_verify_eligible:
            return VerifyResult(
                pre_patch_triggered=False,
                post_patch_clean=False,
                verdict="inconclusive",
                reason=f"poc_run_verify_ineligible: {context.poc_run_verify_reason}",
                confidence="low",
                evidence_summary="Skipped pre/post execution because PoC run_verify reported ineligible.",
            )
        if not context.patch_diff_path:
            return VerifyResult(
                pre_patch_triggered=False,
                post_patch_clean=False,
                verdict="inconclusive",
                reason="patch_diff_not_found",
                confidence="low",
                evidence_summary="Skipped pre/post execution because patch.diff is unavailable.",
            )
        if not context.docker_image_tag:
            return VerifyResult(
                pre_patch_triggered=False,
                post_patch_clean=False,
                verdict="inconclusive",
                reason="docker_image_tag_missing_in_build_artifact",
                confidence="low",
                evidence_summary="Skipped pre/post execution because BuildArtifact has no docker_image_tag.",
            )
        return None

    def _is_triggered(self, pass_result: dict, context: VerifyContext) -> bool:
        """A pass is 'triggered' if any expected behavior is observed."""

        if pass_result.get("matched_error_patterns"):
            return True
        if pass_result.get("matched_stack_keywords"):
            return True
        crash_type = pass_result.get("crash_type", "") or ""
        expected = (context.expected_crash_type or "").strip().lower()
        if expected and crash_type and (expected in crash_type.lower() or crash_type.lower() in expected):
            return True
        if context.expected_exit_code is not None and pass_result.get("exit_code") == context.expected_exit_code:
            return True
        return False

    def _compute_confidence(self, pre: dict, post: dict) -> str:
        """Compute confidence based on signal richness."""

        pre_strong = bool(pre.get("matched_error_patterns")) or bool(pre.get("matched_stack_keywords"))
        post_silent = (
            not post.get("matched_error_patterns")
            and not post.get("matched_stack_keywords")
            and not post.get("crash_type")
        )
        if pre_strong and post_silent:
            return "high"
        if pre_strong or post_silent:
            return "medium"
        return "low"

    def _build_result(
        self,
        pre: dict,
        post: dict,
        verdict: str,
        reason: str,
        confidence: str,
        evidence_summary: str,
        patch_apply_success: bool,
        pre_triggered: bool,
        post_clean: bool,
    ) -> VerifyResult:
        pre_matched_error = list(pre.get("matched_error_patterns") or [])
        pre_matched_stack = list(pre.get("matched_stack_keywords") or [])
        post_matched_error = list(post.get("matched_error_patterns") or [])
        post_matched_stack = list(post.get("matched_stack_keywords") or [])

        # patch_apply_log: take a short excerpt
        patch_apply_log = ""
        post_raw_log = post.get("raw_log") or ""
        if "patch_apply_exit_code=" in post_raw_log:
            # capture surrounding lines for context
            lines = post_raw_log.splitlines()
            for idx, line in enumerate(lines):
                if line.startswith("patch_apply_exit_code="):
                    start = max(0, idx - 5)
                    end = min(len(lines), idx + 5)
                    patch_apply_log = "\n".join(lines[start:end])
                    break

        return VerifyResult(
            pre_patch_triggered=pre_triggered,
            post_patch_clean=post_clean,
            matched_error_patterns=pre_matched_error,
            matched_stack_keywords=pre_matched_stack,
            verdict=verdict,
            reason=reason,
            pre_patch_exit_code=pre.get("exit_code"),
            post_patch_exit_code=post.get("exit_code"),
            pre_patch_observed_stdout=pre.get("stdout") or "",
            pre_patch_observed_stderr=pre.get("stderr") or "",
            post_patch_observed_stdout=post.get("stdout") or "",
            post_patch_observed_stderr=post.get("stderr") or "",
            pre_patch_observed_crash_type=pre.get("crash_type") or "",
            post_patch_observed_crash_type=post.get("crash_type") or "",
            pre_patch_log_path=pre.get("log_path") or "",
            post_patch_log_path=post.get("log_path") or "",
            pre_patch_matched_error_patterns=pre_matched_error,
            pre_patch_matched_stack_keywords=pre_matched_stack,
            post_patch_matched_error_patterns=post_matched_error,
            post_patch_matched_stack_keywords=post_matched_stack,
            patch_apply_log=patch_apply_log,
            patch_apply_success=patch_apply_success,
            confidence=confidence,
            evidence_summary=evidence_summary,
        )

    def _read_run_verify_yaml(self, paths: VerifyStagePaths) -> tuple[bool, str]:
        if paths.run_verify_yaml.exists():
            try:
                payload = yaml.safe_load(paths.run_verify_yaml.read_text(encoding="utf-8")) or {}
                eligible = bool(payload.get("eligible_for_verify", True))
                reason = str(payload.get("eligibility_reason", ""))
                return eligible, reason
            except Exception:
                return True, "run_verify.yaml unreadable, treating as eligible"
        return True, "run_verify.yaml not found, treating as eligible (backward compatible)"

    def _stage_exception(self, where: str, error: Exception, paths: VerifyStagePaths) -> VerifyResult:
        result = VerifyResult(
            pre_patch_triggered=False,
            post_patch_clean=False,
            verdict="inconclusive",
            reason=f"stage_exception:{where}: {error}",
            confidence="low",
            evidence_summary=f"verify stage raised in {where}: {error}",
        )
        self.file_tool.safe_persist(
            str(paths.verify_result_yaml),
            yaml.safe_dump(result.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            description="verify_result.yaml (exception)",
        )
        return result

    def _render_template(self, template_name: str, context: dict[str, Any]) -> str:
        if Environment is not None and FileSystemLoader is not None and StrictUndefined is not None:
            template_dir = Path(__file__).resolve().parents[1] / "templates"
            env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                undefined=StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            return env.get_template(template_name).render(**context).strip() + "\n"

        if template_name == "verify.Dockerfile.j2":
            return f"FROM {context['base_image_tag']}\n\nWORKDIR /workspace\n"
        if template_name == "verify_run.sh.j2":
            return self._render_verify_run_fallback(context)
        raise RuntimeError(f"unsupported template without Jinja2: {template_name}")

    def _render_verify_run_fallback(self, context: dict[str, Any]) -> str:
        return "\n".join(
            [
                "#!/bin/bash",
                "set +e",
                f'PATCH_MODE="${{PATCH_MODE:-pre}}"',
                f'PROJECT_DIR_VAR="{context["project_dir_var"]}"',
                'cd "${PROJECT_DIR_VAR}"',
                f'{context["repo_reset_command"]}',
                'if [[ "${PATCH_MODE}" == "post" ]]; then',
                f'    {context["patch_apply_command"]}',
                '    echo "patch_apply_exit_code=$?"',
                'fi',
                f'{context["rebuild_command"]}',
                'echo "build_rebuild_exit_code=$?"',
                f'echo "target_binary={context["target_binary"]}"',
                f'echo "trigger_command={context["run_command"]}"',
                f'{context["run_command"]}',
                'echo "execution_exit_code=$?"',
                'echo "stdout_begin"; echo "stdout_end"',
                'echo "stderr_begin"; echo "stderr_end"',
                'exit 0',
                "",
            ]
        )


def verify_node(state):
    """LangGraph node: execute verify stage."""

    knowledge = state["knowledge"]
    build = state["build"]
    poc = state["poc"]
    workspace = state["workspace"]
    stage = VerifyStage()

    try:
        verify = stage.run(knowledge=knowledge, build=build, poc=poc, workspace=workspace)
    except Exception as error:
        verify = VerifyResult(
            pre_patch_triggered=False,
            post_patch_clean=False,
            verdict="inconclusive",
            reason=f"verify_node_exception: {error}",
            confidence="low",
        )

    history = list(state.get("stage_history", []))
    history.append({"stage": "verify", "status": verify.verdict})

    if verify.verdict == "success":
        final_status = "success"
    elif verify.verdict == "inconclusive":
        final_status = "inconclusive"
    else:
        final_status = "failed"

    return {
        "verify": verify,
        "final_status": final_status,
        "stage_history": history,
        "last_error": None if final_status == "success" else verify.reason,
    }
