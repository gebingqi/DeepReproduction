"""文件说明：PoC 生成与执行阶段实现。

这个模块负责“把漏洞知识和构建结果转成最小复现载荷，并执行它”。
它遵循与 build 阶段一致的结构：
- 收集本地证据
- 生成结构化 PoC 计划
- 写入 PoC 文件和运行脚本
- 在 Docker 中执行并提取观察结果
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import yaml
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ModuleNotFoundError:  # pragma: no cover
    Environment = None
    FileSystemLoader = None
    StrictUndefined = None

from app.config import build_chat_model
from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.schemas.poc_artifact import PoCArtifact
from app.stages.build import parse_llm_json_payload
from app.tools.docker_tools import DockerBuildRequest, DockerRunRequest, DockerTool
from app.tools.file_tools import FileTool
from app.tools.log_parsing import (
    extract_block as _extract_block_module,
    extract_execution_observation as _extract_execution_observation_module,
    match_patterns as _match_patterns_module,
)
from app.tools.patch_tools import find_patch_diff


class PocStagePaths:
    """Filesystem layout owned by the PoC stage."""

    def __init__(self, workspace: str) -> None:
        self.workspace_root = Path(workspace)
        self.repo_dir = self.workspace_root / "repo"
        self.artifacts_dir = self.workspace_root / "artifacts"
        self.build_dir = self.artifacts_dir / "build"
        self.poc_dir = self.artifacts_dir / "poc"
        self.verify_dir = self.artifacts_dir / "verify"
        self.payloads_dir = self.poc_dir / "payloads"
        self.inputs_dir = self.poc_dir / "inputs"
        self.poc_context_yaml = self.poc_dir / "poc_context.yaml"
        self.poc_plan_yaml = self.poc_dir / "poc_plan.yaml"
        self.dockerfile = self.poc_dir / "Dockerfile"
        self.run_script = self.poc_dir / "run.sh"
        self.poc_log = self.poc_dir / "poc.log"
        self.crash_report = self.poc_dir / "crash_report.txt"
        self.poc_artifact_yaml = self.poc_dir / "poc_artifact.yaml"
        self.run_verify_yaml = self.poc_dir / "run_verify.yaml"


class PocContext(BaseModel):
    """Collected local evidence consumed by the PoC planner."""

    cve_id: str = Field(..., description="Target CVE identifier.")
    repo_url: str = Field(default="", description="Repository URL.")
    resolved_ref: str = Field(default="", description="Resolved vulnerable ref.")
    repo_local_path: str = Field(default="", description="Local repository path.")
    build_system: str = Field(default="", description="Build system selected by build stage.")
    build_success: bool = Field(default=False, description="Whether build stage succeeded.")
    target_binary: str = Field(default="", description="Binary or entrypoint identified by build stage.")
    patch_diff_excerpt: str = Field(default="", description="Short patch excerpt.")
    patch_affected_files: list[str] = Field(default_factory=list, description="Files touched by patch.")
    patch_changed_functions: list[str] = Field(default_factory=list, description="Functions mentioned in patch hunks.")
    patch_added_checks: list[str] = Field(default_factory=list, description="Guard checks added by the patch.")
    patch_error_strings: list[str] = Field(default_factory=list, description="Interesting error strings or sanitizer markers.")
    inferred_input_modes: list[str] = Field(default_factory=list, description="Likely trigger input modes inferred from evidence.")
    knowledge_summary: str = Field(default="", description="Knowledge summary.")
    reproduction_hints: list[str] = Field(default_factory=list, description="Reproduction hints from knowledge.")
    expected_error_patterns: list[str] = Field(default_factory=list, description="Expected error patterns.")
    expected_stack_keywords: list[str] = Field(default_factory=list, description="Expected stack keywords.")
    candidate_entrypoints: list[str] = Field(default_factory=list, description="Candidate entrypoints.")
    candidate_trigger_files: list[str] = Field(default_factory=list, description="Files likely related to triggering.")
    candidate_cli_flags: list[str] = Field(default_factory=list, description="Command-line flags discovered from hints.")
    reference_poc_summaries: list[str] = Field(default_factory=list, description="Reference PoC summaries.")
    repo_evidence_blocks: list[str] = Field(default_factory=list, description="README/tests/examples excerpts.")
    previous_failure_kind: str = Field(default="", description="Previous PoC failure kind.")
    previous_execution_log: str = Field(default="", description="Previous PoC execution log excerpt.")
    planner_attempt: int = Field(default=1, description="Planner attempt number.")


class PocPlan(BaseModel):
    """Structured PoC plan produced by rules or the PoC LLM."""

    trigger_mode: str = Field(default="cli-file", description="Trigger mode.")
    target_binary: str = Field(default="", description="Binary or script used to trigger.")
    target_args: list[str] = Field(default_factory=list, description="Arguments passed to the target.")
    environment_variables: dict[str, str] = Field(default_factory=dict, description="Environment variables for execution.")
    payload_filename: str = Field(default="poc.txt", description="Primary payload filename.")
    payload_content: str = Field(default="", description="Primary payload content.")
    auxiliary_files: dict[str, str] = Field(default_factory=dict, description="Auxiliary files to write.")
    run_command: str = Field(default="", description="Command executed inside the container.")
    expected_exit_code: Optional[int] = Field(default=None, description="Expected exit code.")
    expected_stdout_patterns: list[str] = Field(default_factory=list, description="Expected stdout patterns.")
    expected_stderr_patterns: list[str] = Field(default_factory=list, description="Expected stderr patterns.")
    expected_stack_keywords: list[str] = Field(default_factory=list, description="Expected stack keywords.")
    expected_crash_type: str = Field(default="", description="Expected crash type.")
    source_of_truth: str = Field(default="heuristic", description="Primary evidence source.")
    confidence: str = Field(default="medium", description="Planner confidence.")
    rationale: str = Field(default="", description="Short rationale.")
    dockerfile_override: Optional[str] = Field(default=None, description="Optional full Dockerfile override.")
    run_script_override: Optional[str] = Field(default=None, description="Optional full run script override.")


class RunVerifyReport(BaseModel):
    """Minimum-eligibility report for one PoC execution.

    本报告回答一个问题：这一次 PoC 执行是否构成进入 verify agent 的资格。
    它不裁决漏洞是否被复现，只裁决 PoC 这一次"打到目标行为"的可信度。
    """

    script_finished: bool = Field(
        default=False,
        description="run.sh 是否完整跑完。从日志中观察到 execution_exit_code= 行即为 True。",
    )
    log_well_formed: bool = Field(
        default=False,
        description="日志契约是否完整：stdout_begin/end 与 stderr_begin/end 两对标记块是否都出现。",
    )
    target_binary_invoked: bool = Field(
        default=False,
        description="日志中是否出现 target_binary= 行，用于确认 run.sh 跑到了目标二进制调用前。",
    )
    exit_code_observed: Optional[int] = Field(
        default=None,
        description="观测到的 execution_exit_code 值；未观测到时为 None。",
    )
    error_pattern_hits: list[str] = Field(
        default_factory=list,
        description="实际命中的 expected_stderr_patterns 列表。",
    )
    stack_keyword_hits: list[str] = Field(
        default_factory=list,
        description="实际命中的 expected_stack_keywords 列表。",
    )
    crash_type_hit: str = Field(
        default="",
        description="日志里识别出的崩溃类型字符串；未识别为空字符串。",
    )
    crash_type_compatible: Optional[bool] = Field(
        default=None,
        description="crash_type_hit 是否与 plan.expected_crash_type 兼容（包含或被包含，大小写不敏感）。"
                    "expected_crash_type 为空时为 None。",
    )
    exit_code_match_expected: Optional[bool] = Field(
        default=None,
        description="exit_code_observed 是否等于 plan.expected_exit_code；"
                    "plan.expected_exit_code 为 None 时本字段为 None。",
    )
    eligible_for_verify: bool = Field(
        default=False,
        description="综合判定结果：这一次 PoC 是否构成进入 verify 的资格。",
    )
    eligibility_reason: str = Field(
        default="",
        description="eligible_for_verify 取值的简短原因，便于人工诊断。",
    )
    evidence_log_excerpt: str = Field(
        default="",
        description="关键日志摘录，最多 2048 字节。",
    )


class PocStage:
    """PoC 阶段协调器。"""

    MAX_REPLAN_ATTEMPTS = 3

    def __init__(self, file_tool: FileTool | None = None, docker_tool: DockerTool | None = None) -> None:
        self.file_tool = file_tool or FileTool()
        self.docker_tool = docker_tool or DockerTool()

    def build_plan(self, knowledge: KnowledgeModel, build: BuildArtifact, workspace: str) -> dict:
        """生成 PoC 阶段静态元数据。"""

        if not build.build_success:
            raise RuntimeError("build artifact must be successful before running poc stage")

        paths = PocStagePaths(workspace)
        return {
            "workspace": workspace,
            "repo_dir": str(paths.repo_dir),
            "poc_artifacts_dir": str(paths.poc_dir),
            "docker_image_tag": f"deeprepro-{knowledge.cve_id.lower()}-poc",
            "base_image_tag": build.docker_image_tag or "",
            "target_binary": build.binary_or_entrypoint or build.expected_binary_path or "",
        }

    def render_prompt(self, knowledge: KnowledgeModel, build: BuildArtifact, plan: dict) -> str:
        """为后续 LLM 规划保留接口。"""

        prompt = {
            "cve_id": knowledge.cve_id,
            "resolved_ref": build.resolved_ref,
            "workspace": plan["workspace"],
            "target_binary": plan["target_binary"],
        }
        return json.dumps(prompt, ensure_ascii=False)

    def collect_poc_context(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        workspace: str,
        planner_attempt: int = 1,
        previous_failure_kind: str = "",
        previous_execution_log: str = "",
    ) -> PocContext:
        """Collect local PoC evidence from dataset hints, patch, and build outputs."""

        paths = PocStagePaths(workspace)
        patch_diff_text = self._read_patch_diff(knowledge.cve_id)
        patch_affected_files = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", patch_diff_text, re.MULTILINE)))
        patch_metadata = self._extract_patch_metadata(patch_diff_text)
        candidate_entrypoints = [item for item in [build.binary_or_entrypoint, build.expected_binary_path] if item]
        candidate_entrypoints.extend(self._discover_candidate_binaries(paths.repo_dir))
        trigger_files = patch_affected_files or list(knowledge.affected_files)
        cli_flags = self._extract_candidate_cli_flags(knowledge.reproduction_hints)
        reference_poc_summaries = self._collect_reference_poc_summaries(knowledge.cve_id)
        repo_evidence_blocks = self._collect_repo_evidence(paths.repo_dir, trigger_files)
        inferred_input_modes = self._infer_input_modes(
            hints=knowledge.reproduction_hints,
            patch_diff_text=patch_diff_text,
            reference_poc_summaries=reference_poc_summaries,
        )
        return PocContext(
            cve_id=knowledge.cve_id,
            repo_url=knowledge.repo_url or "",
            resolved_ref=build.resolved_ref,
            repo_local_path=build.repo_local_path,
            build_system=build.build_system,
            build_success=build.build_success,
            target_binary=build.binary_or_entrypoint or build.expected_binary_path or "",
            patch_diff_excerpt=patch_diff_text[:4000],
            patch_affected_files=patch_affected_files or list(knowledge.affected_files),
            patch_changed_functions=patch_metadata["changed_functions"],
            patch_added_checks=patch_metadata["added_checks"],
            patch_error_strings=patch_metadata["error_strings"],
            inferred_input_modes=inferred_input_modes,
            knowledge_summary=knowledge.summary,
            reproduction_hints=list(knowledge.reproduction_hints),
            expected_error_patterns=list(knowledge.expected_error_patterns),
            expected_stack_keywords=list(knowledge.expected_stack_keywords),
            candidate_entrypoints=sorted(set(candidate_entrypoints)),
            candidate_trigger_files=trigger_files[:12],
            candidate_cli_flags=cli_flags,
            reference_poc_summaries=reference_poc_summaries,
            repo_evidence_blocks=repo_evidence_blocks,
            previous_failure_kind=previous_failure_kind,
            previous_execution_log=previous_execution_log[:6000],
            planner_attempt=planner_attempt,
        )

    def plan_poc(self, knowledge: KnowledgeModel, build: BuildArtifact, context: PocContext) -> PocPlan:
        """Generate the structured PoC plan."""

        llm_plan = self._try_llm_poc_plan(knowledge=knowledge, build=build, context=context)
        if llm_plan is not None:
            return self._normalize_poc_plan(llm_plan)
        return self._normalize_poc_plan(self._heuristic_poc_plan(knowledge=knowledge, build=build, context=context))

    def replan_after_failure(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        context: PocContext,
        previous_plan: PocPlan,
        previous_artifact: PoCArtifact,
    ) -> Optional[PocPlan]:
        """Ask the model to adjust the PoC plan after one failed execution."""

        retry_context = context.model_copy(
            update={
                "planner_attempt": context.planner_attempt + 1,
                "previous_failure_kind": self._classify_failure_kind(previous_artifact.execution_logs),
                "previous_execution_log": previous_artifact.execution_logs[:6000],
            }
        )
        return self._try_llm_poc_plan(
            knowledge=knowledge,
            build=build,
            context=retry_context,
            previous_plan=previous_plan,
            previous_artifact=previous_artifact,
        )

    def _prepare_workspace(self, paths: PocStagePaths) -> None:
        self.file_tool.ensure_dir(str(paths.workspace_root))
        self.file_tool.ensure_dir(str(paths.poc_dir))
        self.file_tool.ensure_dir(str(paths.payloads_dir))
        self.file_tool.ensure_dir(str(paths.inputs_dir))

    def _heuristic_poc_plan(self, knowledge: KnowledgeModel, build: BuildArtifact, context: PocContext) -> PocPlan:
        reference_poc = self._load_reference_poc(knowledge.cve_id)
        payload_filename = "poc.txt"
        payload_content = "trigger\n"
        source_of_truth = "heuristic"
        rationale = "Fallback PoC generated from knowledge hints and build artifact."

        if reference_poc is not None:
            payload_filename = reference_poc[0]
            payload_content = reference_poc[1]
            source_of_truth = "dataset_poc"
            rationale = "Adopted the dataset-provided PoC as the primary payload."

        target_binary = self._select_target_binary(build, context, payload_filename)
        target_args = self._select_target_args(knowledge, payload_filename, context, target_binary)
        run_command = self._build_run_command(target_binary, target_args)

        return PocPlan(
            trigger_mode=self._infer_trigger_mode(payload_filename, context),
            target_binary=target_binary,
            target_args=target_args,
            payload_filename=payload_filename,
            payload_content=payload_content,
            run_command=run_command,
            expected_exit_code=None,
            expected_stdout_patterns=[],
            expected_stderr_patterns=list(knowledge.expected_error_patterns),
            expected_stack_keywords=list(knowledge.expected_stack_keywords),
            expected_crash_type=self._infer_expected_crash_type(knowledge),
            source_of_truth=source_of_truth,
            confidence="medium" if reference_poc is None else "high",
            rationale=rationale,
        )

    def _try_llm_poc_plan(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        context: PocContext,
        previous_plan: Optional[PocPlan] = None,
        previous_artifact: Optional[PoCArtifact] = None,
    ) -> Optional[PocPlan]:
        try:
            model = build_chat_model("poc_agent", temperature=0)
        except Exception:
            return None

        prompt = self._build_llm_prompt(
            knowledge=knowledge,
            build=build,
            context=context,
            previous_plan=previous_plan,
            previous_artifact=previous_artifact,
        )
        try:
            response = model.invoke(
                [
                    SystemMessage(content="You return strict JSON only."),
                    HumanMessage(content=prompt),
                ]
            )
            parsed = parse_llm_json_payload(getattr(response, "content", response))
            if parsed is None:
                return None
            plan = PocPlan(**parsed)
            if not plan.target_binary and not plan.run_command:
                return None
            return plan
        except Exception:
            return None

    def _build_llm_prompt(
        self,
        knowledge: KnowledgeModel,
        build: BuildArtifact,
        context: PocContext,
        previous_plan: Optional[PocPlan],
        previous_artifact: Optional[PoCArtifact],
    ) -> str:
        sections = [
            "You are the PoC Agent for a vulnerability reproduction framework.",
            "Infer the most plausible minimal reproducer from patch context, repository evidence, build outputs, and existing hints.",
            "Give substantial weight to semantic understanding of the vulnerability and the likely trigger path.",
            "Prefer a minimal reproducible trigger over a large script.",
            "Adapt any existing PoC or hint to the current workspace layout inside Docker.",
            "The repository is mounted at /workspace/repo.",
            "Payload files should normally be written under /workspace/artifacts/poc/payloads/ and auxiliary files under /workspace/artifacts/poc/inputs/.",
            "Return exactly one JSON object and no markdown fences.",
            "Schema:",
            json.dumps(
                {
                    "trigger_mode": "cli-file|cli-stdin|cli-argv|script-driver|library-harness",
                    "target_binary": "string",
                    "target_args": ["string"],
                    "environment_variables": {"KEY": "VALUE"},
                    "payload_filename": "string",
                    "payload_content": "string",
                    "auxiliary_files": {"relative/path": "content"},
                    "run_command": "string",
                    "expected_exit_code": "integer or null",
                    "expected_stdout_patterns": ["string"],
                    "expected_stderr_patterns": ["string"],
                    "expected_stack_keywords": ["string"],
                    "expected_crash_type": "string",
                    "source_of_truth": "string",
                    "confidence": "low|medium|high",
                    "rationale": "string",
                    "dockerfile_override": "string or null",
                    "run_script_override": "string or null",
                },
                ensure_ascii=True,
            ),
            f"CVE: {knowledge.cve_id}",
            f"Repository: {knowledge.repo_url or ''}",
            f"Summary: {knowledge.summary}",
            f"Vulnerability type: {knowledge.vulnerability_type}",
            f"Resolved vulnerable ref: {build.resolved_ref}",
            f"Build system: {build.build_system}",
            f"Build target binary: {build.binary_or_entrypoint or build.expected_binary_path or ''}",
            f"Expected error patterns: {json.dumps(knowledge.expected_error_patterns, ensure_ascii=False)}",
            f"Expected stack keywords: {json.dumps(knowledge.expected_stack_keywords, ensure_ascii=False)}",
            f"Reproduction hints: {json.dumps(knowledge.reproduction_hints, ensure_ascii=False)}",
            f"Candidate entrypoints: {json.dumps(context.candidate_entrypoints, ensure_ascii=False)}",
            f"Candidate CLI flags: {json.dumps(context.candidate_cli_flags, ensure_ascii=False)}",
            f"Candidate trigger files: {json.dumps(context.candidate_trigger_files, ensure_ascii=False)}",
            f"Patch changed functions: {json.dumps(context.patch_changed_functions, ensure_ascii=False)}",
            f"Patch added checks: {json.dumps(context.patch_added_checks, ensure_ascii=False)}",
            f"Patch error strings: {json.dumps(context.patch_error_strings, ensure_ascii=False)}",
            f"Inferred input modes: {json.dumps(context.inferred_input_modes, ensure_ascii=False)}",
            "Patch excerpt:",
            context.patch_diff_excerpt or "<empty>",
            "Repository evidence excerpts:",
            "\n\n---\n\n".join(context.repo_evidence_blocks[:8]) or "<empty>",
            "Reference PoC excerpts:",
            "\n\n---\n\n".join(context.reference_poc_summaries[:4]) or "<empty>",
        ]

        if previous_plan is not None and previous_artifact is not None:
            sections.extend(
                [
                    "",
                    f"Previous failure kind: {context.previous_failure_kind or '<empty>'}",
                    "Previous plan:",
                    yaml.safe_dump(previous_plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
                    f"Observed exit code: {previous_artifact.observed_exit_code}",
                    f"Observed crash type: {previous_artifact.observed_crash_type}",
                    "Previous execution logs:",
                    context.previous_execution_log or "<empty>",
                    "Adjust the plan to improve the trigger while staying minimal.",
                ]
            )
        return "\n".join(sections)

    def _normalize_poc_plan(self, plan: PocPlan) -> PocPlan:
        if not plan.payload_filename:
            plan.payload_filename = "poc.txt"
        if not plan.payload_content:
            plan.payload_content = "trigger\n"
        plan.payload_filename = Path(plan.payload_filename).name
        plan.auxiliary_files = self._normalize_auxiliary_files(plan.auxiliary_files)
        plan.target_args = [self._normalize_workspace_arg(arg, plan.payload_filename) for arg in plan.target_args]
        if not plan.run_command:
            args = " ".join(self._shell_quote(item) for item in plan.target_args)
            plan.run_command = f"{self._shell_quote(plan.target_binary)} {args}".strip()
        else:
            plan.run_command = self._normalize_run_command(plan.run_command, plan.payload_filename)
        if not plan.expected_stderr_patterns and plan.expected_crash_type:
            plan.expected_stderr_patterns = [plan.expected_crash_type]
        plan.expected_stack_keywords = sorted(set(plan.expected_stack_keywords))
        return plan

    def _execute_poc_plan(self, paths: PocStagePaths, plan_meta: dict, plan: PocPlan) -> PoCArtifact:
        payload_path = paths.payloads_dir / plan.payload_filename
        self.file_tool.write_text(str(payload_path), plan.payload_content)

        auxiliary_paths: list[str] = []
        for name, content in plan.auxiliary_files.items():
            target_dir = paths.inputs_dir if "/" not in name else paths.poc_dir
            target_path = target_dir / name
            self.file_tool.write_text(str(target_path), content)
            auxiliary_paths.append(str(target_path))

        docker_context = {
            "base_image_tag": plan_meta["base_image_tag"],
            "workspace_root": "/workspace",
            "artifacts_root": "/workspace/artifacts",
            "poc_artifacts_dir": "/workspace/artifacts/poc",
        }
        script_context = {
            "workspace_root": "/workspace",
            "repo_dir": "/workspace/repo",
            "poc_artifacts_dir": "/workspace/artifacts/poc",
            "target_binary": plan.target_binary,
            "run_command": plan.run_command,
        }

        dockerfile_content = (
            plan.dockerfile_override.rstrip() + "\n"
            if plan.dockerfile_override
            else self._render_template("poc.Dockerfile.j2", docker_context)
        )
        run_script_content = (
            plan.run_script_override.rstrip() + "\n"
            if plan.run_script_override
            else self._render_template("poc_run.sh.j2", script_context)
        )
        self.file_tool.write_text(str(paths.dockerfile), dockerfile_content)
        self.file_tool.write_text(str(paths.run_script), run_script_content)

        workspace_root = str(paths.workspace_root.resolve())
        docker_build_result = self.docker_tool.build_image(
            DockerBuildRequest(
                workspace=workspace_root,
                dockerfile_path=str(paths.dockerfile.resolve()),
                image_tag=plan_meta["docker_image_tag"],
            )
        )
        if docker_build_result.success:
            run_result = self.docker_tool.run_container(
                DockerRunRequest(
                    image_tag=plan_meta["docker_image_tag"],
                    workspace=workspace_root,
                    command=["bash", "/workspace/artifacts/poc/run.sh"],
                    environment=plan.environment_variables,
                )
            )
        else:
            run_result = docker_build_result

        execution_logs = self._compose_poc_logs(docker_build_result, run_result if docker_build_result.success else None)
        self.file_tool.write_text(str(paths.poc_log), execution_logs)

        observation = self._extract_execution_observation(execution_logs)
        crash_report = observation["observed_stderr"] or observation["observed_stdout"]
        self.file_tool.write_text(str(paths.crash_report), crash_report)
        matched_error_patterns = self._match_patterns(
            observation["observed_stdout"] + "\n" + observation["observed_stderr"],
            plan.expected_stderr_patterns,
        )
        matched_stack_keywords = self._match_patterns(
            observation["observed_stdout"] + "\n" + observation["observed_stderr"],
            plan.expected_stack_keywords,
        )

        execution_success = docker_build_result.success and bool(run_result.success)
        run_verify_report = self._build_run_verify_report(
            plan=plan,
            observation=observation,
            execution_logs=execution_logs,
            matched_error_patterns=matched_error_patterns,
            matched_stack_keywords=matched_stack_keywords,
        )
        self.file_tool.safe_persist(
            str(paths.run_verify_yaml),
            yaml.safe_dump(run_verify_report.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            description="run_verify.yaml",
        )
        reproducer_verified = run_verify_report.eligible_for_verify
        return PoCArtifact(
            root_cause_analysis="",
            payload_generation_strategy=plan.rationale,
            trigger_mode=plan.trigger_mode,
            trigger_command=plan.run_command,
            target_binary=plan.target_binary,
            poc_filename=plan.payload_filename,
            poc_content=plan.payload_content,
            run_script_content=run_script_content,
            input_files=sorted(plan.auxiliary_files.keys()),
            input_file_paths=[str(payload_path)],
            auxiliary_file_paths=sorted(auxiliary_paths),
            expected_error_patterns=list(plan.expected_stderr_patterns),
            expected_stdout_patterns=list(plan.expected_stdout_patterns),
            expected_stderr_patterns=list(plan.expected_stderr_patterns),
            expected_exit_code=plan.expected_exit_code,
            crash_report_content=crash_report,
            observed_exit_code=observation["observed_exit_code"],
            observed_stdout=observation["observed_stdout"],
            observed_stderr=observation["observed_stderr"],
            observed_crash_type=observation["observed_crash_type"],
            matched_error_patterns=matched_error_patterns,
            matched_stack_keywords=matched_stack_keywords,
            reproducer_verified=reproducer_verified,
            execution_success=execution_success,
            execution_logs=execution_logs,
        )

    def run(self, knowledge: KnowledgeModel, build: BuildArtifact, workspace: str) -> PoCArtifact:
        """执行 PoC 阶段并返回 PoC 产物。"""

        plan_meta = self.build_plan(knowledge=knowledge, build=build, workspace=workspace)
        paths = PocStagePaths(workspace)
        self._prepare_workspace(paths)

        current_context = self.collect_poc_context(knowledge=knowledge, build=build, workspace=workspace, planner_attempt=1)
        self.file_tool.write_text(
            str(paths.poc_context_yaml),
            yaml.safe_dump(current_context.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        )

        artifact: PoCArtifact | None = None
        for attempt in range(self.MAX_REPLAN_ATTEMPTS):
            plan = self.plan_poc(knowledge=knowledge, build=build, context=current_context)
            self.file_tool.write_text(
                str(paths.poc_plan_yaml),
                yaml.safe_dump(plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            )
            artifact = self._execute_poc_plan(paths=paths, plan_meta=plan_meta, plan=plan)
            if artifact.execution_success or attempt + 1 >= self.MAX_REPLAN_ATTEMPTS:
                break
            replanned = self.replan_after_failure(
                knowledge=knowledge,
                build=build,
                context=current_context,
                previous_plan=plan,
                previous_artifact=artifact,
            )
            if replanned is not None:
                replanned = self._normalize_poc_plan(replanned)
                self.file_tool.write_text(
                    str(paths.poc_plan_yaml),
                    yaml.safe_dump(replanned.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
                )
                artifact = self._execute_poc_plan(paths=paths, plan_meta=plan_meta, plan=replanned)
                if artifact.execution_success or attempt + 1 >= self.MAX_REPLAN_ATTEMPTS:
                    break
            current_context = current_context.model_copy(
                update={
                    "planner_attempt": current_context.planner_attempt + 1,
                    "previous_failure_kind": self._classify_failure_kind(artifact.execution_logs),
                    "previous_execution_log": artifact.execution_logs[:6000],
                }
            )

        if artifact is None:
            raise RuntimeError("poc stage did not produce an artifact")

        self.file_tool.write_text(
            str(paths.poc_artifact_yaml),
            yaml.safe_dump(artifact.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        )
        return artifact

    def _read_patch_diff(self, cve_id: str) -> str:
        path = find_patch_diff(cve_id)
        if path is None:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def _discover_candidate_binaries(self, repo_dir: Path) -> list[str]:
        candidates: list[str] = []
        for relative in ("src", "bin", "build", "target/debug"):
            root = repo_dir / relative
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_file() and path.suffix in {"", ".sh", ".py", ".pl", ".lua"}:
                    candidates.append(str(path.relative_to(repo_dir)))
                if len(candidates) >= 6:
                    return candidates
        return candidates

    def _extract_candidate_cli_flags(self, hints: list[str]) -> list[str]:
        flags: list[str] = []
        for hint in hints:
            flags.extend(re.findall(r"(--?[A-Za-z0-9][A-Za-z0-9_-]*)", hint))
        return sorted(set(flags))

    def _extract_patch_metadata(self, patch_diff_text: str) -> dict[str, list[str]]:
        changed_functions = sorted(set(re.findall(r"^@@ .*? ([A-Za-z_][A-Za-z0-9_]*)\s*\(", patch_diff_text, re.MULTILINE)))
        added_checks = sorted(
            set(
                match.strip()
                for match in re.findall(r"^\+.*\b(if|assert|lua[LK]_[A-Za-z0-9_]+)\b.*$", patch_diff_text, re.MULTILINE)
                if match.strip()
            )
        )
        error_strings = sorted(
            set(
                token
                for token in re.findall(r"(AddressSanitizer:[^\n]+|heap-buffer-overflow|stack-overflow|segmentation fault|assert)", patch_diff_text, re.IGNORECASE)
            )
        )
        return {
            "changed_functions": changed_functions[:12],
            "added_checks": added_checks[:12],
            "error_strings": error_strings[:12],
        }

    def _infer_input_modes(self, hints: list[str], patch_diff_text: str, reference_poc_summaries: list[str]) -> list[str]:
        text = "\n".join(hints + [patch_diff_text] + reference_poc_summaries).lower()
        modes: list[str] = []
        if any(token in text for token in ("stdin", "pipe", "readline(")):
            modes.append("stdin")
        if any(token in text for token in ("argv", "option", "--", "command line")):
            modes.append("argv")
        if any(token in text for token in ("file", "dofile", "fopen", "loadfile", ".lua", ".txt", ".json", "payload")):
            modes.append("file")
        if any(token in text for token in ("socket", "http", "request")):
            modes.append("network")
        return modes or ["file"]

    def _collect_reference_poc_summaries(self, cve_id: str) -> list[str]:
        summaries: list[str] = []
        for prefix in ("Dataset", "source/Dataset"):
            poc_dir = Path(prefix) / cve_id / "vuln_data" / "vuln_pocs"
            if not poc_dir.exists():
                continue
            for path in sorted(poc_dir.iterdir()):
                if not path.is_file():
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                summaries.append(f"FILE: {path.name}\nCONTENT:\n{content[:3000]}")
        return summaries[:4]

    def _collect_repo_evidence(self, repo_dir: Path, trigger_files: list[str]) -> list[str]:
        evidence_paths: list[Path] = []
        for rel_path in trigger_files[:6]:
            candidate = repo_dir / rel_path
            if candidate.exists() and candidate.is_file():
                evidence_paths.append(candidate)

        for pattern in ("README*", "readme*", "docs/**/*", "examples/**/*", "tests/**/*", "test/**/*", "fuzz/**/*"):
            for path in repo_dir.glob(pattern):
                if path.is_file():
                    evidence_paths.append(path)
                if len(evidence_paths) >= 10:
                    break
            if len(evidence_paths) >= 10:
                break

        blocks: list[str] = []
        seen: set[str] = set()
        for path in evidence_paths:
            rel = str(path.relative_to(repo_dir))
            if rel in seen:
                continue
            seen.add(rel)
            blocks.append(f"FILE: {rel}\nCONTENT:\n{path.read_text(encoding='utf-8', errors='replace')[:2500]}")
            if len(blocks) >= 10:
                break
        return blocks

    def _load_reference_poc(self, cve_id: str) -> Optional[tuple[str, str]]:
        for prefix in ("Dataset", "source/Dataset"):
            poc_dir = Path(prefix) / cve_id / "vuln_data" / "vuln_pocs"
            if not poc_dir.exists():
                continue
            for path in sorted(poc_dir.iterdir()):
                if path.is_file():
                    return path.name, path.read_text(encoding="utf-8", errors="replace")
        return None

    def _select_target_binary(self, build: BuildArtifact, context: PocContext, payload_filename: str = "") -> str:
        if build.binary_or_entrypoint:
            return build.binary_or_entrypoint
        if build.expected_binary_path:
            return build.expected_binary_path
        interpreter = self._interpreter_for_payload(payload_filename)
        if interpreter:
            return interpreter
        if context.candidate_entrypoints:
            return context.candidate_entrypoints[0]
        return "./target"

    def _select_target_args(self, knowledge: KnowledgeModel, payload_filename: str, context: PocContext, target_binary: str) -> list[str]:
        payload_path = f"/workspace/artifacts/poc/payloads/{payload_filename}"
        for hint in knowledge.reproduction_hints:
            if "{payload}" in hint:
                hint = hint.replace("{payload}", payload_path)
                parts = hint.split()
                if parts and self._looks_like_binary(parts[0], target_binary):
                    return parts[1:]
                return parts
        if "stdin" in context.inferred_input_modes:
            return [f"< {payload_path}"]
        return [payload_path]

    def _infer_trigger_mode(self, payload_filename: str, context: PocContext) -> str:
        suffix = Path(payload_filename).suffix.lower()
        if suffix in {".sh", ".py", ".pl"}:
            return "script-driver"
        if "stdin" in context.inferred_input_modes:
            return "cli-stdin"
        if "argv" in context.inferred_input_modes:
            return "cli-argv"
        return "cli-file"

    def _build_run_command(self, target_binary: str, target_args: list[str]) -> str:
        segments = [self._shell_quote(target_binary)]
        segments.extend(self._shell_quote(item) for item in target_args)
        return " ".join(item for item in segments if item).strip()

    def _infer_expected_crash_type(self, knowledge: KnowledgeModel) -> str:
        joined = " ".join(knowledge.expected_error_patterns + knowledge.reproduction_hints).lower()
        for marker in ("segmentation fault", "assert", "abort", "stack-overflow", "heap-buffer-overflow"):
            if marker in joined:
                return marker
        return knowledge.vulnerability_type

    def _interpreter_for_payload(self, payload_filename: str) -> str:
        mapping = {
            ".py": "python3",
            ".sh": "bash",
            ".pl": "perl",
        }
        return mapping.get(Path(payload_filename).suffix.lower(), "")

    def _looks_like_binary(self, token: str, target_binary: str) -> bool:
        if not token or not target_binary:
            return False
        token_name = Path(token).name
        target_name = Path(target_binary).name
        return token_name == target_name

    def _normalize_auxiliary_files(self, auxiliary_files: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, content in auxiliary_files.items():
            safe_name = str(Path(name))
            while safe_name.startswith("../"):
                safe_name = safe_name[3:]
            if safe_name.startswith("/"):
                safe_name = safe_name.lstrip("/")
            if not safe_name:
                continue
            normalized[safe_name] = content
        return normalized

    def _normalize_workspace_arg(self, arg: str, payload_filename: str) -> str:
        payload_path = f"/workspace/artifacts/poc/payloads/{payload_filename}"
        if arg == "{payload}":
            return payload_path
        return arg.replace("./payloads/", "/workspace/artifacts/poc/payloads/")

    def _normalize_run_command(self, run_command: str, payload_filename: str) -> str:
        payload_path = f"/workspace/artifacts/poc/payloads/{payload_filename}"
        return run_command.replace("{payload}", payload_path).replace("./payloads/", "/workspace/artifacts/poc/payloads/")

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
        if template_name == "poc.Dockerfile.j2":
            return self._render_poc_dockerfile_fallback(context)
        if template_name == "poc_run.sh.j2":
            return self._render_poc_run_script_fallback(context)
        raise RuntimeError(f"unsupported template without Jinja2: {template_name}")

    def _render_poc_dockerfile_fallback(self, context: dict[str, Any]) -> str:
        base_image_tag = context.get("base_image_tag") or "ubuntu:20.04"
        lines = [
            f"FROM {base_image_tag}",
            "",
            'SHELL ["/bin/bash", "-o", "pipefail", "-c"]',
            "",
            "WORKDIR /workspace",
            "COPY artifacts/poc /workspace/artifacts/poc",
            "",
        ]
        return "\n".join(lines)

    def _render_poc_run_script_fallback(self, context: dict[str, Any]) -> str:
        return "\n".join(
            [
                "#!/bin/bash",
                "set +e",
                "",
                f'POC_ARTIFACTS_DIR="{context.get("poc_artifacts_dir", "/workspace/artifacts/poc")}"',
                f'REPO_DIR="{context.get("repo_dir", "/workspace/repo")}"',
                'mkdir -p "${POC_ARTIFACTS_DIR}"',
                'cd "${REPO_DIR}"',
                'echo "target_binary=' + self._escape_for_echo(context.get("target_binary", "")) + '"',
                'echo "trigger_command=' + self._escape_for_echo(context.get("run_command", "")) + '"',
                'stdout_file="${POC_ARTIFACTS_DIR}/stdout.txt"',
                'stderr_file="${POC_ARTIFACTS_DIR}/stderr.txt"',
                context["run_command"] + ' >"${stdout_file}" 2>"${stderr_file}"',
                'execution_exit_code=$?',
                'echo "execution_exit_code=${execution_exit_code}"',
                'echo "stdout_begin"',
                'cat "${stdout_file}" 2>/dev/null || true',
                'echo "stdout_end"',
                'echo "stderr_begin"',
                'cat "${stderr_file}" 2>/dev/null || true',
                'echo "stderr_end"',
                'exit 0',
                "",
            ]
        )

    def _compose_poc_logs(self, docker_build_result: Any, run_result: Any | None) -> str:
        parts = [
            f"image_build_success={docker_build_result.success}",
            f"image_build_exit_code={docker_build_result.exit_code}",
            "",
            "[docker_build_stdout]",
            docker_build_result.stdout.strip(),
            "",
            "[docker_build_stderr]",
            docker_build_result.stderr.strip(),
        ]
        if run_result is not None:
            parts.extend(
                [
                    "",
                    f"container_run_success={run_result.success}",
                    f"container_run_exit_code={run_result.exit_code}",
                    "",
                    "[container_run_stdout]",
                    run_result.stdout.strip(),
                    "",
                    "[container_run_stderr]",
                    run_result.stderr.strip(),
                ]
            )
        return "\n".join(parts).strip() + "\n"

    def _extract_execution_observation(self, execution_logs: str) -> dict[str, Any]:
        return _extract_execution_observation_module(execution_logs)

    def _extract_block(self, text: str, begin: str, end: str) -> str:
        return _extract_block_module(text, begin, end)

    def _match_patterns(self, haystack: str, patterns: list[str]) -> list[str]:
        return _match_patterns_module(haystack, patterns)

    def _build_run_verify_report(
        self,
        plan: PocPlan,
        observation: dict[str, Any],
        execution_logs: str,
        matched_error_patterns: list[str],
        matched_stack_keywords: list[str],
    ) -> RunVerifyReport:
        """Compute the minimum-eligibility report for one PoC execution."""

        # 3.1 script_finished
        script_finished = "execution_exit_code=" in execution_logs

        # 3.2 log_well_formed
        required_markers = ("stdout_begin", "stdout_end", "stderr_begin", "stderr_end")
        log_well_formed = all(marker in execution_logs for marker in required_markers)

        # 3.3 target_binary_invoked
        target_binary_invoked = "target_binary=" in execution_logs

        # 3.4 exit_code_observed
        exit_code_observed = observation.get("observed_exit_code")

        # 3.5 hits
        error_pattern_hits = list(matched_error_patterns)
        stack_keyword_hits = list(matched_stack_keywords)

        # 3.6 crash_type_hit
        crash_type_hit = observation.get("observed_crash_type") or ""

        # 3.7 crash_type_compatible
        expected_crash = (plan.expected_crash_type or "").strip().lower()
        observed_crash_lower = crash_type_hit.strip().lower()
        if not expected_crash:
            crash_type_compatible: Optional[bool] = None
        elif not observed_crash_lower:
            crash_type_compatible = False
        else:
            crash_type_compatible = (expected_crash in observed_crash_lower) or (observed_crash_lower in expected_crash)

        # 3.8 exit_code_match_expected
        if plan.expected_exit_code is None:
            exit_code_match_expected: Optional[bool] = None
        elif exit_code_observed is None:
            exit_code_match_expected = False
        else:
            exit_code_match_expected = (exit_code_observed == plan.expected_exit_code)

        # 3.9 eligible_for_verify
        eligible_for_verify = False
        eligibility_reason = ""
        if not script_finished:
            eligibility_reason = "script_did_not_finish: missing execution_exit_code marker"
        elif not log_well_formed:
            eligibility_reason = "log_not_well_formed: stdout/stderr block markers missing"
        else:
            if error_pattern_hits:
                eligible_for_verify = True
                eligibility_reason = f"error_pattern_hit: {error_pattern_hits[0]}"
            elif stack_keyword_hits:
                eligible_for_verify = True
                eligibility_reason = f"stack_keyword_hit: {stack_keyword_hits[0]}"
            elif crash_type_compatible is True:
                eligible_for_verify = True
                eligibility_reason = f"crash_type_compatible: observed={crash_type_hit}"
            elif exit_code_match_expected is True:
                eligible_for_verify = True
                eligibility_reason = f"exit_code_match: {exit_code_observed}"
            else:
                eligible_for_verify = False
                eligibility_reason = "no_target_behavior_observed"

        # 3.10 evidence_log_excerpt
        MAX_EXCERPT_BYTES = 2048
        stderr_block = self._extract_block(execution_logs, "stderr_begin", "stderr_end")
        if stderr_block:
            excerpt = stderr_block
        else:
            excerpt = execution_logs
        excerpt_bytes = excerpt.encode("utf-8", errors="replace")
        if len(excerpt_bytes) > MAX_EXCERPT_BYTES:
            excerpt_bytes = excerpt_bytes[-MAX_EXCERPT_BYTES:]
            excerpt = excerpt_bytes.decode("utf-8", errors="replace")
        evidence_log_excerpt = excerpt

        return RunVerifyReport(
            script_finished=script_finished,
            log_well_formed=log_well_formed,
            target_binary_invoked=target_binary_invoked,
            exit_code_observed=exit_code_observed,
            error_pattern_hits=error_pattern_hits,
            stack_keyword_hits=stack_keyword_hits,
            crash_type_hit=crash_type_hit,
            crash_type_compatible=crash_type_compatible,
            exit_code_match_expected=exit_code_match_expected,
            eligible_for_verify=eligible_for_verify,
            eligibility_reason=eligibility_reason,
            evidence_log_excerpt=evidence_log_excerpt,
        )

    def _classify_failure_kind(self, execution_logs: str) -> str:
        if "image_build_success=False" in execution_logs:
            return "docker_build"
        if "container_run_success=False" in execution_logs:
            return "container_run"
        return "non_triggering"

    def _shell_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    def _escape_for_echo(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')


def poc_node(state):
    """LangGraph 节点：执行 PoC 生成与执行阶段。"""

    knowledge = state["knowledge"]
    build = state["build"]
    workspace = state["workspace"]
    retry_count = dict(state.get("retry_count", {}))
    history = list(state.get("stage_history", []))
    stage = PocStage()

    try:
        poc = stage.run(knowledge=knowledge, build=build, workspace=workspace)
        if poc.execution_success:
            history.append({"stage": "poc", "status": "success"})
            return {
                "poc": poc,
                "current_stage": "verify",
                "stage_history": history,
                "last_error": None,
            }

        retry_count["poc"] = retry_count.get("poc", 0) + 1
        history.append({"stage": "poc", "status": "failed", "error": poc.execution_logs})
        return {
            "poc": poc,
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": "poc stage completed without a successful execution",
        }
    except Exception as error:
        retry_count["poc"] = retry_count.get("poc", 0) + 1
        history.append({"stage": "poc", "status": "failed", "error": str(error)})
        return {
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": str(error),
        }
