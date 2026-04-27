"""文件说明：环境构建阶段实现。

这个模块负责把知识阶段的候选线索收敛为“确认后的构建事实”。
它会先 clone 仓库并读取真实源码中的构建文件、README、CI 配置和 patch，
再把这些本地证据交给模型规划构建方案；若模型不可用，则回退到规则规划。
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
except ModuleNotFoundError:  # pragma: no cover - exercised only in minimal envs.
    Environment = None
    FileSystemLoader = None
    StrictUndefined = None

from app.config import build_chat_model
from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.tools.docker_tools import DockerBuildRequest, DockerRunRequest, DockerTool
from app.tools.file_tools import FileTool
from app.tools.git_tools import GitTool
from app.tools.patch_tools import find_patch_diff
from app.tools.process_tools import ProcessRequest, ProcessTool


class BuildStagePaths:
    """Filesystem layout owned by the build stage."""

    def __init__(self, workspace: str) -> None:
        self.workspace_root = Path(workspace)
        self.repo_dir = self.workspace_root / "repo"
        self.artifacts_dir = self.workspace_root / "artifacts"
        self.build_dir = self.artifacts_dir / "build"
        self.poc_dir = self.artifacts_dir / "poc"
        self.verify_dir = self.artifacts_dir / "verify"
        self.dockerfile = self.build_dir / "Dockerfile"
        self.build_script = self.build_dir / "build.sh"
        self.build_log = self.build_dir / "build.log"
        self.build_plan_yaml = self.build_dir / "build_plan.yaml"
        self.build_context_yaml = self.build_dir / "build_context.yaml"
        self.build_artifact_yaml = self.build_dir / "build_artifact.yaml"
        self.build_verify_yaml = self.build_dir / "build_verify.yaml"


class RefSnapshot(BaseModel):
    """Repository snapshot collected from one candidate ref."""

    label: str = Field(..., description="Human-readable label such as vulnerable_ref or fixed_parent.")
    requested_ref: str = Field(..., description="Requested git ref string.")
    resolved_ref: str = Field(default="", description="Resolved commit SHA.")
    build_files: list[str] = Field(default_factory=list, description="Detected build files.")
    evidence_files: list[str] = Field(default_factory=list, description="Detected README or INSTALL files.")
    ci_files: list[str] = Field(default_factory=list, description="Detected CI configuration files.")
    file_excerpts: list[str] = Field(default_factory=list, description="Short excerpts from key files at this ref.")


class BuildPlan(BaseModel):
    """Structured build plan produced by rules or the build LLM."""

    chosen_vulnerable_ref: str = Field(..., description="Chosen vulnerable ref to build.")
    chosen_fixed_ref: Optional[str] = Field(default=None, description="Chosen fixed ref used for comparison.")
    build_system: str = Field(default="unknown", description="Chosen build system.")
    install_packages: list[str] = Field(default_factory=list, description="System packages to install in Docker.")
    configure_commands: list[str] = Field(default_factory=list, description="Configure commands to run before building.")
    clean_commands: list[str] = Field(default_factory=list, description="Cleanup commands to run before building.")
    build_commands: list[str] = Field(default_factory=list, description="Main build commands.")
    expected_binary_path: Optional[str] = Field(default=None, description="Expected output binary or entrypoint path.")
    dockerfile_override: Optional[str] = Field(default=None, description="Optional full Dockerfile override.")
    build_script_override: Optional[str] = Field(default=None, description="Optional full build script override.")
    source_of_truth: str = Field(default="manual_fallback", description="Primary evidence source behind the plan.")
    confidence: str = Field(default="medium", description="Planner confidence level.")
    rationale: str = Field(default="", description="Short explanation for the decision.")


class BuildContext(BaseModel):
    """Collected local evidence consumed by the planner."""

    cve_id: str = Field(..., description="Target CVE identifier.")
    repo_url: str = Field(default="", description="Repository URL.")
    task_vulnerable_ref: Optional[str] = Field(default=None, description="Task or knowledge vulnerable ref.")
    task_fixed_ref: Optional[str] = Field(default=None, description="Task or knowledge fixed ref.")
    patch_diff_excerpt: str = Field(default="", description="Short excerpt from patch.diff.")
    patch_affected_files: list[str] = Field(default_factory=list, description="Files touched by patch.diff.")
    knowledge_summary: str = Field(default="", description="Knowledge-stage summary.")
    knowledge_build_hints: list[str] = Field(default_factory=list, description="Build-related hints from knowledge.")
    knowledge_reproduction_hints: list[str] = Field(default_factory=list, description="Reproduction hints from knowledge.")
    snapshots: list[RefSnapshot] = Field(default_factory=list, description="Candidate ref snapshots.")
    planner_attempt: int = Field(default=1, description="Current planning attempt number.")
    previous_failure_kind: str = Field(default="", description="Failure kind such as docker_build or container_run.")
    previous_build_failure: str = Field(default="", description="Previous build failure logs for replanning.")


class BuildStage:
    """构建阶段协调器。"""

    BUILD_FILE_PATTERNS = (
        "Makefile",
        "makefile",
        "CMakeLists.txt",
        "configure",
        "configure.ac",
        "meson.build",
        "build.ninja",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "package.json",
    )
    README_PATTERNS = ("README", "README.md", "README.txt", "INSTALL", "INSTALL.md")
    MAX_REPLAN_ATTEMPTS = 3
    REQUIRED_DOCKER_PACKAGES = ("git",)

    def __init__(
        self,
        file_tool: FileTool | None = None,
        process_tool: ProcessTool | None = None,
        git_tool: GitTool | None = None,
        docker_tool: DockerTool | None = None,
    ) -> None:
        self.file_tool = file_tool or FileTool()
        self.process_tool = process_tool or ProcessTool()
        self.git_tool = git_tool or GitTool(process_tool=self.process_tool)
        self.docker_tool = docker_tool or DockerTool(process_tool=self.process_tool)

    def build_plan(self, knowledge: KnowledgeModel, workspace: str) -> dict:
        """生成构建阶段最初的静态计划。"""

        if not knowledge.repo_url:
            raise RuntimeError("knowledge.repo_url is required for build stage")
        if not knowledge.vulnerable_ref and not knowledge.fixed_ref:
            raise RuntimeError("knowledge.vulnerable_ref or knowledge.fixed_ref is required for build stage")

        paths = BuildStagePaths(workspace)
        project_name = self._derive_project_name(knowledge.repo_url)
        return {
            "repo_url": knowledge.repo_url,
            "workspace": workspace,
            "project_name": project_name,
            "project_dir_name": project_name,
            "repo_dir": str(paths.repo_dir),
            "artifacts_dir": str(paths.artifacts_dir),
            "build_artifacts_dir": str(paths.build_dir),
            "poc_artifacts_dir": str(paths.poc_dir),
            "verify_artifacts_dir": str(paths.verify_dir),
            "docker_image_tag": f"deeprepro-{knowledge.cve_id.lower()}-build",
        }

    def render_prompt(self, knowledge: KnowledgeModel, plan: dict) -> str:
        """生成 build planner 提示词。"""

        prompt = {
            "cve_id": knowledge.cve_id,
            "repo_url": plan["repo_url"],
            "workspace": plan["workspace"],
        }
        return json.dumps(prompt, ensure_ascii=False)

    def run(self, knowledge: KnowledgeModel, workspace: str) -> BuildArtifact:
        """执行构建阶段并返回构建产物。"""

        plan_meta = self.build_plan(knowledge=knowledge, workspace=workspace)
        paths = BuildStagePaths(workspace)
        self._prepare_workspace(paths)

        repo = self.git_tool.clone_repo(plan_meta["repo_url"], plan_meta["repo_dir"])
        context = self.collect_build_context(knowledge=knowledge, repo_path=Path(repo.local_path), planner_attempt=1)
        self.file_tool.write_text(
            str(paths.build_context_yaml),
            yaml.safe_dump(context.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        )

        current_plan = self.plan_build(knowledge=knowledge, context=context, project_name=plan_meta["project_name"])
        current_context = context
        artifact: BuildArtifact | None = None

        for attempt in range(self.MAX_REPLAN_ATTEMPTS):
            current_plan = self._normalize_build_plan(Path(repo.local_path), current_plan)
            self.file_tool.write_text(
                str(paths.build_plan_yaml),
                yaml.safe_dump(current_plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            )

            checkout = self.git_tool.checkout_ref(repo.local_path, current_plan.chosen_vulnerable_ref)
            artifact = self._execute_build_plan(
                repo_path=Path(repo.local_path),
                paths=paths,
                plan_meta=plan_meta,
                build_plan=current_plan,
                resolved_ref=checkout.current_ref,
            )
            if artifact.build_success or attempt + 1 >= self.MAX_REPLAN_ATTEMPTS:
                break

            replanned = self.replan_after_failure(
                knowledge=knowledge,
                context=current_context,
                project_name=plan_meta["project_name"],
                previous_plan=current_plan,
                build_logs=artifact.build_logs,
                failure_kind=self._classify_failure_kind(artifact.build_logs),
            )
            if replanned is None:
                break
            replanned = self._normalize_build_plan(Path(repo.local_path), replanned)
            if replanned.model_dump(mode="json") == current_plan.model_dump(mode="json"):
                break
            current_context = current_context.model_copy(
                update={
                    "planner_attempt": current_context.planner_attempt + 1,
                    "previous_failure_kind": self._classify_failure_kind(artifact.build_logs),
                    "previous_build_failure": artifact.build_logs[:6000],
                }
            )
            current_plan = replanned

        if artifact is None:
            raise RuntimeError("build stage did not produce an artifact")

        self.file_tool.write_text(
            str(paths.build_artifact_yaml),
            yaml.safe_dump(artifact.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        )

        try:
            verify_payload = self._verify_build_artifact(
                artifact=artifact,
                paths=paths,
                plan_meta=plan_meta,
                cve_id=knowledge.cve_id,
            )
        except Exception as error:
            verify_payload = {
                "verify_status": "verify_self_failed",
                "verify_error": str(error),
            }
        self.file_tool.write_text(
            str(paths.build_verify_yaml),
            yaml.safe_dump(verify_payload, sort_keys=False, allow_unicode=True),
        )

        return artifact

    def collect_build_context(self, knowledge: KnowledgeModel, repo_path: Path, planner_attempt: int = 1) -> BuildContext:
        """Collect local build evidence from repo snapshots, patch diff, and knowledge outputs."""

        patch_diff_path = find_patch_diff(knowledge.cve_id)
        patch_diff_text = ""
        if patch_diff_path is not None:
            patch_diff_text = patch_diff_path.read_text(encoding="utf-8", errors="replace")
        patch_affected_files = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", patch_diff_text, re.MULTILINE)))

        snapshots: list[RefSnapshot] = []
        for label, requested_ref in self._candidate_refs(repo_path, knowledge).items():
            snapshot = self._collect_ref_snapshot(repo_path, label=label, requested_ref=requested_ref, affected_files=patch_affected_files)
            if snapshot is not None:
                snapshots.append(snapshot)

        return BuildContext(
            cve_id=knowledge.cve_id,
            repo_url=knowledge.repo_url or "",
            task_vulnerable_ref=knowledge.vulnerable_ref,
            task_fixed_ref=knowledge.fixed_ref,
            patch_diff_excerpt=patch_diff_text[:4000],
            patch_affected_files=patch_affected_files or list(knowledge.affected_files),
            knowledge_summary=knowledge.summary,
            knowledge_build_hints=list(knowledge.build_hints),
            knowledge_reproduction_hints=list(knowledge.reproduction_hints),
            snapshots=snapshots,
            planner_attempt=planner_attempt,
        )

    def plan_build(self, knowledge: KnowledgeModel, context: BuildContext, project_name: str) -> BuildPlan:
        """Plan the build using an LLM when available, otherwise use deterministic heuristics."""

        llm_plan = self._try_llm_build_plan(knowledge=knowledge, context=context, project_name=project_name)
        if llm_plan is not None:
            return llm_plan
        return self._heuristic_build_plan(knowledge=knowledge, context=context, project_name=project_name)

    def replan_after_failure(
        self,
        knowledge: KnowledgeModel,
        context: BuildContext,
        project_name: str,
        previous_plan: BuildPlan,
        build_logs: str,
        failure_kind: str,
    ) -> Optional[BuildPlan]:
        """Give the model one chance to adjust the plan after a build failure."""

        retry_context = context.model_copy(
            update={
                "planner_attempt": context.planner_attempt + 1,
                "previous_failure_kind": failure_kind,
                "previous_build_failure": build_logs[:6000],
            }
        )
        llm_plan = self._try_llm_build_plan(
            knowledge=knowledge,
            context=retry_context,
            project_name=project_name,
            previous_plan=previous_plan,
        )
        if llm_plan is None:
            return None
        return llm_plan

    def _prepare_workspace(self, paths: BuildStagePaths) -> None:
        self.file_tool.ensure_dir(str(paths.workspace_root))
        self.file_tool.ensure_dir(str(paths.build_dir))
        self.file_tool.ensure_dir(str(paths.poc_dir))
        self.file_tool.ensure_dir(str(paths.verify_dir))

    def _normalize_build_plan(self, repo_path: Path, build_plan: BuildPlan) -> BuildPlan:
        build_plan.chosen_vulnerable_ref = self._resolve_existing_ref(repo_path, build_plan.chosen_vulnerable_ref)
        if build_plan.chosen_fixed_ref:
            build_plan.chosen_fixed_ref = self._resolve_existing_ref(repo_path, build_plan.chosen_fixed_ref)
        build_plan.install_packages = self._ensure_required_docker_packages(build_plan.install_packages)
        if build_plan.dockerfile_override:
            build_plan.dockerfile_override = self._ensure_dockerfile_override_has_required_tools(
                build_plan.dockerfile_override,
                build_plan.install_packages,
            )
        return build_plan

    def _execute_build_plan(
        self,
        repo_path: Path,
        paths: BuildStagePaths,
        plan_meta: dict,
        build_plan: BuildPlan,
        resolved_ref: str,
    ) -> BuildArtifact:
        repo_scan = self._scan_repo(repo_path)
        docker_context = {
            "repo_url": plan_meta["repo_url"],
            "vulnerable_ref": build_plan.chosen_vulnerable_ref,
            "project_name": plan_meta["project_name"],
            "project_dir_name": plan_meta["project_dir_name"],
            "project_dir": f"/src/{plan_meta['project_dir_name']}",
            "workspace_root": "/workspace",
            "artifacts_root": "/workspace/artifacts",
            "build_artifacts_dir": "/workspace/artifacts/build",
            "poc_artifacts_dir": "/workspace/artifacts/poc",
            "verify_artifacts_dir": "/workspace/artifacts/verify",
            "apt_packages": build_plan.install_packages,
        }
        script_context = {
            "project_name": plan_meta["project_name"],
            "project_dir_name": plan_meta["project_dir_name"],
            "project_dir": f"/src/{plan_meta['project_dir_name']}",
            "workspace_root": "/workspace",
            "artifacts_root": "/workspace/artifacts",
            "build_artifacts_dir": "/workspace/artifacts/build",
            "cc": self._select_compiler(build_plan),
            "cxx": self._select_cxx(build_plan),
            "configure_commands": build_plan.configure_commands,
            "clean_commands": build_plan.clean_commands,
            "build_commands": build_plan.build_commands,
        }

        dockerfile_content = (
            build_plan.dockerfile_override.rstrip() + "\n"
            if build_plan.dockerfile_override
            else self._render_template("Dockerfile.j2", docker_context)
        )
        build_script_content = (
            build_plan.build_script_override.rstrip() + "\n"
            if build_plan.build_script_override
            else self._render_template("build.sh.j2", script_context)
        )
        self.file_tool.write_text(str(paths.dockerfile), dockerfile_content)
        self.file_tool.write_text(str(paths.build_script), build_script_content)

        workspace_root = str(paths.workspace_root.resolve())
        docker_build_result = self.docker_tool.build_image(
            DockerBuildRequest(
                workspace=workspace_root,
                dockerfile_path=str(paths.dockerfile.resolve()),
                image_tag=plan_meta["docker_image_tag"],
            )
        )
        if docker_build_result.success:
            build_result = self.docker_tool.run_container(
                DockerRunRequest(
                    image_tag=plan_meta["docker_image_tag"],
                    workspace=workspace_root,
                    command=["bash", "/workspace/artifacts/build/build.sh"],
                )
            )
        else:
            build_result = docker_build_result

        build_logs = self._compose_build_logs(
            docker_build_result=docker_build_result,
            run_result=build_result if docker_build_result.success else None,
        )
        self.file_tool.write_text(str(paths.build_log), build_logs)

        return BuildArtifact(
            dockerfile_content=dockerfile_content,
            build_script_content=build_script_content,
            install_packages=build_plan.install_packages,
            build_commands=build_plan.build_commands,
            expected_binary_path=build_plan.expected_binary_path,
            repo_local_path=str(repo_path),
            resolved_ref=resolved_ref,
            build_system=build_plan.build_system,
            detected_build_files=repo_scan["build_files"],
            dependency_sources=self._build_dependency_sources(repo_scan),
            source_of_truth=build_plan.source_of_truth,
            binary_or_entrypoint=build_plan.expected_binary_path,
            docker_image_tag=plan_meta["docker_image_tag"],
            sanitizer_enabled=self._sanitizer_enabled(build_script_content),
            build_success=docker_build_result.success and build_result.success,
            build_logs=build_logs,
            chosen_vulnerable_ref=build_plan.chosen_vulnerable_ref,
            chosen_fixed_ref=build_plan.chosen_fixed_ref,
        )

    def _candidate_refs(self, repo_path: Path, knowledge: KnowledgeModel) -> dict[str, str]:
        refs: dict[str, str] = {}
        if knowledge.vulnerable_ref:
            refs["knowledge_vulnerable"] = knowledge.vulnerable_ref
        if knowledge.fixed_ref:
            refs["knowledge_fixed"] = knowledge.fixed_ref
            fixed_parent = self._maybe_resolve_ref(repo_path, f"{knowledge.fixed_ref}^")
            if fixed_parent:
                refs["fixed_parent"] = fixed_parent
        return refs

    def _collect_ref_snapshot(
        self,
        repo_path: Path,
        label: str,
        requested_ref: str,
        affected_files: list[str],
    ) -> Optional[RefSnapshot]:
        try:
            checkout = self.git_tool.checkout_ref(str(repo_path), requested_ref)
        except Exception:
            return None

        repo_scan = self._scan_repo(repo_path)
        key_files = self._choose_key_files(repo_scan, affected_files)
        excerpts = [self._read_excerpt(repo_path / rel_path) for rel_path in key_files]
        excerpts = [block for block in excerpts if block]
        return RefSnapshot(
            label=label,
            requested_ref=requested_ref,
            resolved_ref=checkout.current_ref,
            build_files=repo_scan["build_files"],
            evidence_files=repo_scan["evidence_files"],
            ci_files=repo_scan["ci_files"],
            file_excerpts=excerpts,
        )

    def _scan_repo(self, repo_dir: Path) -> dict[str, list[str]]:
        build_files: list[str] = []
        evidence_files: list[str] = []
        ci_files: list[str] = []

        for pattern in self.BUILD_FILE_PATTERNS:
            for path in repo_dir.rglob(pattern):
                if path.is_file():
                    build_files.append(str(path.relative_to(repo_dir)))
        for pattern in self.README_PATTERNS:
            for path in repo_dir.rglob(pattern):
                if path.is_file():
                    evidence_files.append(str(path.relative_to(repo_dir)))

        workflow_dir = repo_dir / ".github" / "workflows"
        if workflow_dir.exists():
            for path in workflow_dir.rglob("*"):
                if path.is_file():
                    ci_files.append(str(path.relative_to(repo_dir)))
        gitlab_ci = repo_dir / ".gitlab-ci.yml"
        if gitlab_ci.exists():
            ci_files.append(str(gitlab_ci.relative_to(repo_dir)))

        return {
            "build_files": sorted(set(build_files)),
            "evidence_files": sorted(set(evidence_files)),
            "ci_files": sorted(set(ci_files)),
        }

    def _choose_key_files(self, repo_scan: dict[str, list[str]], affected_files: list[str]) -> list[str]:
        selected: list[str] = []
        for rel_path in affected_files:
            if rel_path not in selected:
                selected.append(rel_path)
        for group in ("build_files", "evidence_files", "ci_files"):
            for rel_path in repo_scan[group]:
                if rel_path not in selected:
                    selected.append(rel_path)
                if len(selected) >= 8:
                    return selected
        return selected[:8]

    def _read_excerpt(self, path: Path, limit: int = 1600) -> str:
        if not path.exists() or not path.is_file():
            return ""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        header = f"FILE: {path.name}\nPATH: {path}\n"
        return header + content[:limit]

    def _try_llm_build_plan(
        self,
        knowledge: KnowledgeModel,
        context: BuildContext,
        project_name: str,
        previous_plan: Optional[BuildPlan] = None,
    ) -> Optional[BuildPlan]:
        try:
            model = build_chat_model("build_agent", temperature=0)
        except Exception:
            return None

        prompt = self._build_llm_prompt(knowledge=knowledge, context=context, project_name=project_name, previous_plan=previous_plan)
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
            plan = BuildPlan(**parsed)
            if not plan.build_commands:
                return None
            return plan
        except Exception:
            return None

    def _build_llm_prompt(
        self,
        knowledge: KnowledgeModel,
        context: BuildContext,
        project_name: str,
        previous_plan: Optional[BuildPlan],
    ) -> str:
        sections = [
            "You are the Build Agent for a vulnerability reproduction framework.",
            "Your job is to choose the best vulnerable build target and produce a concrete build plan from local repository evidence.",
            "Prefer real repo evidence over hints. Use fixed_ref^ when it is a better vulnerable baseline than knowledge.vulnerable_ref.",
            "Read the patch, affected files, Makefile/CMakeLists/README/CI excerpts, and choose a plan that has the best chance to compile.",
            "When replanning after failure, distinguish between docker image build failures and container runtime build failures.",
            "If previous_failure_kind is docker_build, prioritize fixing Dockerfile steps, install_packages, base image choice, and dockerfile_override.",
            "If previous_failure_kind is container_run, prioritize fixing build_commands, configure_commands, clean_commands, compiler choice, and build_script_override.",
            "Any Dockerfile used for build execution must preserve the ability to clone the target repository inside the image.",
            "Do not remove required base packages such as git from install_packages or dockerfile_override.",
            "Return exactly one JSON object and no markdown fences.",
            "Schema:",
            json.dumps(
                {
                    "chosen_vulnerable_ref": "string",
                    "chosen_fixed_ref": "string or null",
                    "build_system": "string",
                    "install_packages": ["string"],
                    "configure_commands": ["string"],
                    "clean_commands": ["string"],
                    "build_commands": ["string"],
                    "expected_binary_path": "string or null",
                    "dockerfile_override": "string or null",
                    "build_script_override": "string or null",
                    "source_of_truth": "string",
                    "confidence": "low|medium|high",
                    "rationale": "string",
                },
                ensure_ascii=True,
            ),
            f"CVE: {knowledge.cve_id}",
            f"Repository: {knowledge.repo_url or ''}",
            f"Knowledge summary: {knowledge.summary}",
            f"Knowledge vulnerable_ref: {knowledge.vulnerable_ref or ''}",
            f"Knowledge fixed_ref: {knowledge.fixed_ref or ''}",
            f"Knowledge build_hints: {json.dumps(knowledge.build_hints, ensure_ascii=False)}",
            f"Knowledge reproduction_hints: {json.dumps(knowledge.reproduction_hints, ensure_ascii=False)}",
            f"Patch affected files: {json.dumps(context.patch_affected_files, ensure_ascii=False)}",
            "Patch excerpt:",
            context.patch_diff_excerpt or "<empty>",
        ]

        for snapshot in context.snapshots:
            sections.extend(
                [
                    "",
                    f"Snapshot label: {snapshot.label}",
                    f"Requested ref: {snapshot.requested_ref}",
                    f"Resolved ref: {snapshot.resolved_ref}",
                    f"Build files: {json.dumps(snapshot.build_files, ensure_ascii=False)}",
                    f"Evidence files: {json.dumps(snapshot.evidence_files, ensure_ascii=False)}",
                    f"CI files: {json.dumps(snapshot.ci_files, ensure_ascii=False)}",
                    "Excerpts:",
                    "\n\n---\n\n".join(snapshot.file_excerpts[:6]) or "<empty>",
                ]
            )

        if previous_plan is not None:
            sections.extend(
                [
                    "",
                    f"Previous failure kind: {context.previous_failure_kind or '<empty>'}",
                    "Previous plan:",
                    yaml.safe_dump(previous_plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
                    "Previous failure logs:",
                    context.previous_build_failure or "<empty>",
                ]
            )
        return "\n".join(sections)

    def _heuristic_build_plan(self, knowledge: KnowledgeModel, context: BuildContext, project_name: str) -> BuildPlan:
        snapshots = {item.label: item for item in context.snapshots}
        chosen_snapshot = snapshots.get("fixed_parent") or snapshots.get("knowledge_vulnerable") or next(iter(snapshots.values()), None)
        build_system = self._select_build_system(knowledge, chosen_snapshot.build_files if chosen_snapshot else [])
        build_commands = self._select_build_commands(knowledge, build_system)
        expected_binary = self._guess_binary_or_entrypoint(build_system, project_name)

        chosen_vulnerable_ref = (
            (chosen_snapshot.resolved_ref if chosen_snapshot else None)
            or knowledge.vulnerable_ref
            or context.task_vulnerable_ref
            or ""
        )
        return BuildPlan(
            chosen_vulnerable_ref=chosen_vulnerable_ref,
            chosen_fixed_ref=knowledge.fixed_ref or context.task_fixed_ref,
            build_system=build_system,
            install_packages=self._select_install_packages(build_system, knowledge),
            configure_commands=self._select_configure_commands(build_system),
            clean_commands=self._select_clean_commands(build_system),
            build_commands=build_commands,
            expected_binary_path=expected_binary,
            dockerfile_override=None,
            build_script_override=None,
            source_of_truth="repo_scan" if chosen_snapshot and chosen_snapshot.build_files else "knowledge_hint",
            confidence="medium",
            rationale="Heuristic plan based on cloned repository scan, patch-affected files, and knowledge hints.",
        )

    def _select_build_system(self, knowledge: KnowledgeModel, detected_files: list[str]) -> str:
        mapping = [
            ("Cargo.toml", "cargo"),
            ("go.mod", "go"),
            ("CMakeLists.txt", "cmake"),
            ("meson.build", "meson"),
            ("configure.ac", "autotools"),
            ("configure", "autotools"),
            ("Makefile", "make"),
            ("makefile", "make"),
            ("pom.xml", "maven"),
            ("build.gradle", "gradle"),
            ("build.gradle.kts", "gradle"),
            ("package.json", "npm"),
        ]
        lowered = {item.lower() for item in detected_files}
        for filename, system in mapping:
            if filename.lower() in lowered or any(path.endswith(filename) for path in detected_files):
                return system
        if knowledge.build_systems:
            return knowledge.build_systems[0]
        return "unknown"

    def _select_build_commands(self, knowledge: KnowledgeModel, build_system: str) -> list[str]:
        if knowledge.build_commands:
            return list(knowledge.build_commands)
        defaults = {
            "cmake": ["cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug", "cmake --build build -j$(nproc)"],
            "make": ["make clean || true", "make -j$(nproc)"],
            "autotools": ["./configure", "make -j$(nproc)"],
            "cargo": ["cargo build"],
            "go": ["go build ./..."],
            "meson": ["meson setup build", "ninja -C build"],
            "maven": ["mvn package -DskipTests"],
            "gradle": ["./gradlew build -x test"],
            "npm": ["npm install", "npm run build"],
            "unknown": ['echo "[build] build_commands unresolved after repo scan; please confirm build entrypoint." >&2', "exit 2"],
        }
        return defaults.get(build_system, defaults["unknown"])

    def _select_configure_commands(self, build_system: str) -> list[str]:
        if build_system == "autotools":
            return ["autoreconf -fi || true"]
        return []

    def _select_clean_commands(self, build_system: str) -> list[str]:
        if build_system in {"make", "autotools"}:
            return ["make clean || true"]
        if build_system == "cargo":
            return ["cargo clean || true"]
        if build_system == "cmake":
            return ["rm -rf build"]
        return []

    def _select_install_packages(self, build_system: str, knowledge: KnowledgeModel) -> list[str]:
        packages = {
            "cmake": ["build-essential", "clang", "cmake", "git", "make", "pkg-config"],
            "make": ["build-essential", "clang", "git", "make", "pkg-config"],
            "autotools": ["autoconf", "automake", "build-essential", "clang", "git", "libtool", "make", "pkg-config"],
            "cargo": ["build-essential", "cargo", "clang", "git", "pkg-config", "rustc"],
            "go": ["build-essential", "clang", "git", "golang"],
            "meson": ["build-essential", "clang", "git", "meson", "ninja-build", "pkg-config"],
            "maven": ["git", "maven", "openjdk-17-jdk"],
            "gradle": ["git", "gradle", "openjdk-17-jdk"],
            "npm": ["git", "nodejs", "npm"],
            "unknown": ["build-essential", "clang", "git", "make", "pkg-config"],
        }.get(build_system, ["build-essential", "clang", "git", "make", "pkg-config"])
        for command in knowledge.install_commands:
            lower = command.lower()
            if "zlib" in lower and "zlib1g-dev" not in packages:
                packages.append("zlib1g-dev")
            if "openssl" in lower or "libssl" in lower:
                if "libssl-dev" not in packages:
                    packages.append("libssl-dev")
        return self._ensure_required_docker_packages(sorted(set(packages)))

    def _guess_binary_or_entrypoint(self, build_system: str, project_name: str) -> Optional[str]:
        guesses = {
            "cmake": f"build/{project_name}",
            "make": project_name,
            "autotools": f"src/{project_name}",
            "cargo": f"target/debug/{project_name}",
            "go": project_name,
        }
        return guesses.get(build_system)

    def _select_compiler(self, build_plan: BuildPlan) -> str:
        joined = " ".join(build_plan.build_commands).lower()
        if "gcc" in joined:
            return "gcc"
        return "clang"

    def _select_cxx(self, build_plan: BuildPlan) -> str:
        joined = " ".join(build_plan.build_commands).lower()
        if "g++" in joined or "gcc" in joined:
            return "g++"
        return "clang++"

    def _build_dependency_sources(self, repo_scan: dict[str, list[str]]) -> list[str]:
        sources: list[str] = []
        if repo_scan["build_files"]:
            sources.append("repo_scan:build_files")
        if repo_scan["evidence_files"]:
            sources.append("repo_scan:readme_install")
        if repo_scan["ci_files"]:
            sources.append("repo_scan:ci")
        return sources

    def _maybe_resolve_ref(self, repo_path: Path, requested_ref: str) -> Optional[str]:
        result = self.process_tool.run(ProcessRequest(command=["git", "rev-parse", requested_ref], cwd=str(repo_path)))
        if not result.success:
            return None
        return result.stdout.strip()

    def _resolve_existing_ref(self, repo_path: Path, requested_ref: str) -> str:
        resolved = self._maybe_resolve_ref(repo_path, requested_ref)
        if resolved:
            return resolved
        return requested_ref

    def _derive_project_name(self, repo_url: str) -> str:
        name = repo_url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return re.sub(r"[^A-Za-z0-9._-]+", "-", name) or "target"

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

        if template_name == "Dockerfile.j2":
            return self._render_dockerfile_fallback(context)
        if template_name == "build.sh.j2":
            return self._render_build_script_fallback(context)
        raise RuntimeError(f"unsupported template without Jinja2: {template_name}")

    def _render_dockerfile_fallback(self, context: dict[str, Any]) -> str:
        apt_packages = context.get("apt_packages") or []
        lines = [
            f"FROM {context.get('base_image', 'ubuntu:20.04')}",
            "",
            'SHELL ["/bin/bash", "-o", "pipefail", "-c"]',
            "",
            "ENV DEBIAN_FRONTEND=noninteractive",
            f"ENV WORKSPACE_ROOT={context.get('workspace_root', '/workspace')}",
            f"ENV ARTIFACTS_ROOT={context.get('artifacts_root', '/workspace/artifacts')}",
            f"ENV BUILD_ARTIFACTS_DIR={context.get('build_artifacts_dir', '/workspace/artifacts/build')}",
            f"ENV POC_ARTIFACTS_DIR={context.get('poc_artifacts_dir', '/workspace/artifacts/poc')}",
            f"ENV VERIFY_ARTIFACTS_DIR={context.get('verify_artifacts_dir', '/workspace/artifacts/verify')}",
            'ENV SRC_ROOT=/src',
            f"ENV PROJECT_DIR={context.get('project_dir', '/src/target')}",
            "",
            "RUN apt-get update && \\",
            f"    apt-get install -y --no-install-recommends {' '.join(apt_packages)} && \\",
            "    apt-get clean && \\",
            "    rm -rf /var/lib/apt/lists/*",
            "",
            "RUN mkdir -p ${SRC_ROOT} ${WORKSPACE_ROOT} ${ARTIFACTS_ROOT} ${BUILD_ARTIFACTS_DIR} ${POC_ARTIFACTS_DIR} ${VERIFY_ARTIFACTS_DIR}",
            "",
            "RUN set -eux; \\",
            f'    git clone "{context["repo_url"]}" "${{PROJECT_DIR}}" && \\',
            '    cd "${PROJECT_DIR}" && \\',
            f'    git checkout "{context["vulnerable_ref"]}" && \\',
            "    git rev-parse HEAD",
            "",
            "COPY artifacts/build ${BUILD_ARTIFACTS_DIR}",
            "COPY artifacts/poc ${POC_ARTIFACTS_DIR}",
            "COPY artifacts/verify ${VERIFY_ARTIFACTS_DIR}",
            "",
            "WORKDIR ${PROJECT_DIR}",
            "",
        ]
        return "\n".join(lines)

    def _render_build_script_fallback(self, context: dict[str, Any]) -> str:
        build_commands = context.get("build_commands") or []
        configure_commands = context.get("configure_commands") or []
        clean_commands = context.get("clean_commands") or []
        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "",
            "log() {",
            "    printf '[build] %s\\n' \"$*\" >&2",
            "}",
            "",
            f'PROJECT_DIR="{context["project_dir"]}"',
            f'BUILD_ARTIFACTS_DIR="{context.get("build_artifacts_dir", "artifacts/build")}"',
            'mkdir -p "${BUILD_ARTIFACTS_DIR}"',
            'cd "${PROJECT_DIR}"',
            'log "project_dir=$(pwd)"',
            'log "build_artifacts_dir=${BUILD_ARTIFACTS_DIR}"',
            'log "running clean step"',
        ]
        lines.extend(clean_commands)
        lines.extend(["", 'log "running configure step"'])
        lines.extend(configure_commands)
        lines.extend(["", 'log "running build step"'])
        lines.extend(build_commands)
        lines.append("")
        return "\n".join(lines)

    def _compose_build_logs(self, docker_build_result: Any, run_result: Any | None) -> str:
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

    def _classify_failure_kind(self, build_logs: str) -> str:
        if "image_build_success=False" in build_logs:
            return "docker_build"
        if "container_run_success=False" in build_logs:
            return "container_run"
        return "unknown"

    def _ensure_required_docker_packages(self, packages: list[str]) -> list[str]:
        merged = list(packages)
        for package in self.REQUIRED_DOCKER_PACKAGES:
            if package not in merged:
                merged.append(package)
        return sorted(set(merged))

    def _ensure_dockerfile_override_has_required_tools(self, dockerfile_content: str, install_packages: list[str]) -> str:
        lower = dockerfile_content.lower()
        if "apt-get install" in lower and " git" not in f" {' '.join(install_packages)} ":
            install_packages = self._ensure_required_docker_packages(install_packages)
        if "apt-get install" in lower and "git" not in lower:
            lines = dockerfile_content.splitlines()
            updated: list[str] = []
            replaced = False
            for line in lines:
                if not replaced and "apt-get install" in line:
                    if "--no-install-recommends" in line:
                        line = line.replace("--no-install-recommends ", f"--no-install-recommends {' '.join(install_packages)} ", 1)
                    else:
                        line = line.replace("apt-get install -y ", f"apt-get install -y {' '.join(install_packages)} ", 1)
                    replaced = True
                updated.append(line)
            dockerfile_content = "\n".join(updated)
        return dockerfile_content.rstrip() + "\n"

    def _sanitizer_enabled(self, build_script_content: str) -> bool:
        return "-fsanitize=" in build_script_content

    def _verify_build_artifact(
        self,
        artifact: BuildArtifact,
        paths: BuildStagePaths,
        plan_meta: dict,
        cve_id: str,
    ) -> dict:
        """对 build 阶段产物做事实型自检，不裁决漏洞、不影响 build_success。"""

        result: dict[str, Any] = {}
        verify_notes: list[str] = []

        # 4.14 timestamp
        result["verify_status"] = "ok"  # placeholder, updated at the end
        result["verified_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # 4.2 image_present / image_digest
        try:
            if not artifact.docker_image_tag:
                result["image_present"] = False
                result["image_digest"] = None
                verify_notes.append("docker_image_tag missing in BuildArtifact")
            else:
                inspect_result = self.docker_tool.process_tool.run(
                    ProcessRequest(
                        command=["docker", "image", "inspect", artifact.docker_image_tag, "--format", "{{.Id}}"],
                        timeout_seconds=30,
                    )
                )
                if inspect_result.success:
                    result["image_present"] = True
                    result["image_digest"] = inspect_result.stdout.strip() or None
                else:
                    result["image_present"] = False
                    result["image_digest"] = None
        except Exception:
            result["image_present"] = False
            result["image_digest"] = None

        # 4.3 workspace_layout_ok
        try:
            missing_dirs: list[str] = []
            for directory in (paths.workspace_root, paths.repo_dir, paths.build_dir):
                if not directory.is_dir():
                    missing_dirs.append(str(directory))
            result["workspace_layout_ok"] = len(missing_dirs) == 0
            result["workspace_layout_missing"] = missing_dirs
        except Exception:
            result["workspace_layout_ok"] = False
            result["workspace_layout_missing"] = []

        # 4.4 dockerfile_present
        try:
            result["dockerfile_present"] = (
                paths.dockerfile.exists() and paths.dockerfile.is_file() and paths.dockerfile.stat().st_size > 0
            )
        except Exception:
            result["dockerfile_present"] = False

        # 4.5 build_script_present
        try:
            result["build_script_present"] = (
                paths.build_script.exists() and paths.build_script.is_file() and paths.build_script.stat().st_size > 0
            )
        except Exception:
            result["build_script_present"] = False

        # 4.6 build_log_present
        try:
            result["build_log_present"] = paths.build_log.exists() and paths.build_log.is_file()
        except Exception:
            result["build_log_present"] = False

        # 4.7 image_build_success / container_run_success
        try:
            result["image_build_success"] = "image_build_success=True" in artifact.build_logs
            if "container_run_success=True" in artifact.build_logs:
                result["container_run_success"] = True
            elif "container_run_success=False" in artifact.build_logs:
                result["container_run_success"] = False
            else:
                result["container_run_success"] = None
        except Exception:
            result["image_build_success"] = False
            result["container_run_success"] = None

        # 4.8 binary_in_container
        try:
            if not artifact.expected_binary_path:
                result["binary_in_container"] = {
                    "checked": False,
                    "reason": "expected_binary_path is empty",
                }
                verify_notes.append("expected_binary_path is empty")
            elif not result.get("image_present"):
                result["binary_in_container"] = {
                    "checked": False,
                    "reason": "image not present, cannot check binary",
                }
            else:
                check_cmd = (
                    f'test -x "${{PROJECT_DIR}}/{artifact.expected_binary_path}" '
                    f'&& echo BINARY_FOUND || echo BINARY_MISSING'
                )
                bin_result = self.docker_tool.run_container(
                    DockerRunRequest(
                        image_tag=artifact.docker_image_tag,
                        command=["bash", "-lc", check_cmd],
                    )
                )
                log_excerpt = (bin_result.stdout + "\n" + bin_result.stderr).strip()[:800]
                exists: Optional[bool] = None
                if "BINARY_FOUND" in bin_result.stdout:
                    exists = True
                elif "BINARY_MISSING" in bin_result.stdout:
                    exists = False
                result["binary_in_container"] = {
                    "checked": True,
                    "exit_code": bin_result.exit_code,
                    "exists": exists,
                    "expected_path": artifact.expected_binary_path,
                    "log_excerpt": log_excerpt,
                }
        except Exception:
            result["binary_in_container"] = {
                "checked": False,
                "reason": "exception during binary check",
            }

        # 4.9 patch_appliable_in_container
        try:
            patch_diff_path = find_patch_diff(cve_id)
            if patch_diff_path is None:
                result["patch_appliable_in_container"] = {
                    "checked": False,
                    "reason": "patch.diff not found",
                }
                verify_notes.append("patch.diff not found")
            elif not result.get("image_present"):
                result["patch_appliable_in_container"] = {
                    "checked": False,
                    "reason": "image not present, cannot check patch",
                }
            else:
                patch_diff_host_path = str(patch_diff_path.resolve())
                command = [
                    "docker", "run", "--rm",
                    "-v", f"{patch_diff_host_path}:/tmp/patch.diff:ro",
                    artifact.docker_image_tag,
                    "bash", "-lc",
                    'cd "${PROJECT_DIR}" && git apply --check /tmp/patch.diff',
                ]
                patch_result = self.docker_tool.process_tool.run(
                    ProcessRequest(command=command, timeout_seconds=120)
                )
                log_excerpt = (patch_result.stdout + "\n" + patch_result.stderr).strip()[:1200]
                result["patch_appliable_in_container"] = {
                    "checked": True,
                    "applied": patch_result.success,
                    "exit_code": patch_result.exit_code,
                    "patch_diff_path": str(patch_diff_path),
                    "log_excerpt": log_excerpt,
                }
        except Exception:
            result["patch_appliable_in_container"] = {
                "checked": False,
                "reason": "exception during patch check",
            }

        # 4.11 repo_ref_in_container
        try:
            if not result.get("image_present"):
                result["repo_ref_in_container"] = {
                    "checked": False,
                    "reason": "image not present, cannot check ref",
                }
            else:
                ref_result = self.docker_tool.run_container(
                    DockerRunRequest(
                        image_tag=artifact.docker_image_tag,
                        command=["bash", "-lc", 'cd "${PROJECT_DIR}" && git rev-parse HEAD'],
                    )
                )
                observed_head = ref_result.stdout.strip()
                expected_ref = artifact.chosen_vulnerable_ref
                matches: Optional[bool] = None
                if expected_ref and len(expected_ref) >= 7 and re.fullmatch(r"[0-9a-fA-F]+", expected_ref):
                    matches = observed_head.startswith(expected_ref) or expected_ref.startswith(observed_head)
                result["repo_ref_in_container"] = {
                    "checked": True,
                    "expected_ref": expected_ref,
                    "observed_head": observed_head,
                    "matches": matches,
                    "exit_code": ref_result.exit_code,
                }
        except Exception:
            result["repo_ref_in_container"] = {
                "checked": False,
                "reason": "exception during ref check",
            }

        # 4.12 verify_notes
        result["verify_notes"] = verify_notes

        # 4.13 verify_status
        must_pass = [
            result.get("image_present"),
            result.get("workspace_layout_ok"),
            result.get("dockerfile_present"),
            result.get("build_script_present"),
            result.get("build_log_present"),
        ]

        if artifact.build_success:
            must_pass.append(result.get("image_build_success"))
            must_pass.append(result.get("container_run_success"))

        if artifact.expected_binary_path and artifact.build_success:
            bin_info = result.get("binary_in_container", {})
            if bin_info.get("checked"):
                must_pass.append(bin_info.get("exists"))

        patch_info = result.get("patch_appliable_in_container", {})
        if patch_info.get("checked"):
            must_pass.append(patch_info.get("applied"))

        if all(item is True for item in must_pass):
            result["verify_status"] = "ok"
        else:
            result["verify_status"] = "partial"

        return result


def build_node(state):
    """LangGraph 节点：执行环境构建阶段。"""

    knowledge = state["knowledge"]
    workspace = state["workspace"]
    retry_count = dict(state.get("retry_count", {}))
    history = list(state.get("stage_history", []))
    stage = BuildStage()

    try:
        build = stage.run(knowledge=knowledge, workspace=workspace)
        if build.build_success:
            history.append({"stage": "build", "status": "success"})
            return {
                "build": build,
                "current_stage": "poc",
                "stage_history": history,
                "last_error": None,
            }

        retry_count["build"] = retry_count.get("build", 0) + 1
        history.append({"stage": "build", "status": "failed", "error": build.build_logs})
        return {
            "build": build,
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": "build stage completed without a successful build",
        }
    except Exception as error:
        retry_count["build"] = retry_count.get("build", 0) + 1
        history.append({"stage": "build", "status": "failed", "error": str(error)})
        return {
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": str(error),
        }


def parse_llm_json_payload(content) -> Optional[dict]:
    """Parse a JSON object from an LLM response payload."""

    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
            elif isinstance(item, str):
                text_parts.append(item)
        content = "\n".join(text_parts)

    if not isinstance(content, str):
        return None

    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)

    try:
        return json.loads(stripped)
    except Exception:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None
