"""Verify stage tests. Validates the differential verification agent."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from app.orchestrator import routers
from app.schemas.build_artifact import BuildArtifact
from app.schemas.knowledge import KnowledgeModel
from app.schemas.poc_artifact import PoCArtifact
from app.schemas.verify_result import VerifyResult
from app.stages import verify as verify_module


def make_context(**overrides):
    payload = {
        "cve_id": "CVE-2022-0000",
        "docker_image_tag": "demo:build",
        "chosen_vulnerable_ref": "abc1234",
        "chosen_fixed_ref": "fff5678",
        "target_binary": "src/lua",
        "trigger_command": "src/lua /workspace/artifacts/poc/payloads/poc.lua",
        "expected_stdout_patterns": [],
        "expected_stderr_patterns": ["heap-buffer-overflow"],
        "expected_stack_keywords": ["singlevar"],
        "expected_exit_code": None,
        "expected_crash_type": "heap-buffer-overflow",
        "patch_diff_path": "/tmp/patch.diff",
        "poc_run_verify_eligible": True,
        "poc_run_verify_reason": "",
    }
    payload.update(overrides)
    return verify_module.VerifyContext(**payload)


def make_pass(
    exit_code=139,
    stdout="",
    stderr="",
    crash_type="",
    matched_error_patterns=None,
    matched_stack_keywords=None,
    patch_apply_exit_code=None,
    build_rebuild_exit_code=0,
    log_well_formed=True,
    script_finished=True,
    raw_log="",
    log_path="",
):
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "crash_type": crash_type,
        "matched_error_patterns": matched_error_patterns or [],
        "matched_stack_keywords": matched_stack_keywords or [],
        "patch_apply_exit_code": patch_apply_exit_code,
        "build_rebuild_exit_code": build_rebuild_exit_code,
        "log_path": log_path,
        "raw_log": raw_log,
        "log_well_formed": log_well_formed,
        "script_finished": script_finished,
    }


# ===== Case 1 =====
def test_decide_verdict_success_when_pre_triggered_post_clean():
    stage = verify_module.VerifyStage()
    pre = make_pass(
        exit_code=139,
        crash_type="heap-buffer-overflow",
        matched_error_patterns=["heap-buffer-overflow"],
        matched_stack_keywords=["singlevar"],
    )
    post = make_pass(
        exit_code=0,
        crash_type="",
        matched_error_patterns=[],
        matched_stack_keywords=[],
        patch_apply_exit_code=0,
    )
    context = make_context()

    result = stage._decide_verdict({"pre": pre, "post": post}, context)

    assert result.verdict == "success"
    assert result.confidence == "high"
    assert result.pre_patch_triggered is True
    assert result.post_patch_clean is True


# ===== Case 2 =====
def test_decide_verdict_failed_when_pre_not_triggered():
    stage = verify_module.VerifyStage()
    pre = make_pass(exit_code=0, matched_error_patterns=[], matched_stack_keywords=[])
    post = make_pass(exit_code=0, patch_apply_exit_code=0)
    context = make_context()

    result = stage._decide_verdict({"pre": pre, "post": post}, context)

    assert result.verdict == "failed"
    assert result.reason == "pre_not_triggered"
    assert result.confidence == "low"


# ===== Case 3 =====
def test_decide_verdict_failed_when_post_still_triggered():
    stage = verify_module.VerifyStage()
    pre = make_pass(
        exit_code=139,
        matched_error_patterns=["heap-buffer-overflow"],
    )
    post = make_pass(
        exit_code=139,
        matched_error_patterns=["heap-buffer-overflow"],
        patch_apply_exit_code=0,
    )
    context = make_context()

    result = stage._decide_verdict({"pre": pre, "post": post}, context)

    assert result.verdict == "failed"
    assert result.reason == "post_still_triggered"
    assert result.confidence == "medium"


# ===== Case 4 =====
def test_decide_verdict_inconclusive_when_patch_apply_failed():
    stage = verify_module.VerifyStage()
    pre = make_pass(matched_error_patterns=["heap-buffer-overflow"])
    post = make_pass(patch_apply_exit_code=1)
    context = make_context()

    result = stage._decide_verdict({"pre": pre, "post": post}, context)

    assert result.verdict == "inconclusive"
    assert result.reason.startswith("patch_apply_failed")
    assert result.patch_apply_success is False
    assert result.confidence == "low"


# ===== Case 5 =====
def test_decide_verdict_inconclusive_when_log_not_well_formed():
    stage = verify_module.VerifyStage()
    pre = make_pass(
        log_well_formed=False,
        matched_error_patterns=["heap-buffer-overflow"],
    )
    post = make_pass(patch_apply_exit_code=0)
    context = make_context()

    result = stage._decide_verdict({"pre": pre, "post": post}, context)

    assert result.verdict == "inconclusive"
    assert result.reason.startswith("log_not_well_formed")


# ===== Case 6 =====
def test_short_circuit_when_run_verify_ineligible(tmp_path):
    workspace = tmp_path / "ws"
    paths = verify_module.VerifyStagePaths(str(workspace))
    paths.poc_dir.mkdir(parents=True, exist_ok=True)
    paths.run_verify_yaml.write_text(
        yaml.safe_dump(
            {"eligible_for_verify": False, "eligibility_reason": "no_target_behavior_observed"}
        ),
        encoding="utf-8",
    )

    knowledge = KnowledgeModel(
        cve_id="CVE-2022-0000",
        summary="demo",
        vulnerability_type="heap-overflow",
        repo_url="https://example.com/demo.git",
        vulnerable_ref="abc1234",
    )
    build = BuildArtifact(
        dockerfile_content="FROM ubuntu\n",
        build_script_content="#!/bin/bash\n",
        build_success=True,
        docker_image_tag="demo:build",
        chosen_vulnerable_ref="abc1234",
        chosen_fixed_ref="fff5678",
    )
    poc = PoCArtifact(
        poc_filename="poc.lua",
        poc_content="boom",
        run_script_content="#!/bin/bash\n",
        target_binary="src/lua",
        trigger_command="src/lua poc.lua",
        execution_success=True,
    )

    fake_docker = MagicMock()
    fake_docker.run_container = MagicMock()
    stage = verify_module.VerifyStage(docker_tool=fake_docker)

    result = stage.run(knowledge=knowledge, build=build, poc=poc, workspace=str(workspace))

    assert result.verdict == "inconclusive"
    assert result.reason.startswith("poc_run_verify_ineligible")
    assert fake_docker.run_container.call_count == 0
    assert paths.verify_result_yaml.exists()


# ===== Case 7 =====
def test_run_one_pass_parses_pre_log_correctly(tmp_path):
    workspace = tmp_path / "ws"
    paths = verify_module.VerifyStagePaths(str(workspace))
    paths.verify_dir.mkdir(parents=True, exist_ok=True)

    pre_stdout = (
        "build_rebuild_exit_code=0\n"
        "target_binary=src/lua\n"
        "trigger_command=src/lua poc.lua\n"
        "execution_exit_code=139\n"
        "stdout_begin\n\nstdout_end\n"
        "stderr_begin\nAddressSanitizer: heap-buffer-overflow at singlevar\nstderr_end\n"
    )

    fake_docker_result = MagicMock()
    fake_docker_result.stdout = pre_stdout
    fake_docker_result.stderr = ""
    fake_docker_result.exit_code = 0
    fake_docker_result.success = True

    fake_docker = MagicMock()
    fake_docker.run_container = MagicMock(return_value=fake_docker_result)
    stage = verify_module.VerifyStage(docker_tool=fake_docker)

    context = make_context()
    plan = verify_module.VerifyPlan(
        image_tag="demo:build",
        pre_run_command="src/lua poc.lua",
        post_run_command="src/lua poc.lua",
        expected_stderr_patterns=["heap-buffer-overflow"],
        expected_stack_keywords=["singlevar"],
        pre_log_path=str(paths.pre_patch_log),
        post_log_path=str(paths.post_patch_log),
    )

    result = stage._run_one_pass("pre", context, plan, paths)

    assert result["exit_code"] == 139
    assert result["log_well_formed"] is True
    assert result["script_finished"] is True
    assert result["patch_apply_exit_code"] is None
    assert result["build_rebuild_exit_code"] == 0
    assert "heap-buffer-overflow" in result["matched_error_patterns"]
    assert "singlevar" in result["matched_stack_keywords"]


# ===== Case 8 =====
def test_verify_node_returns_inconclusive_on_stage_exception(monkeypatch):
    class FakeStage:
        def run(self, knowledge, build, poc, workspace):
            raise RuntimeError("boom")

    monkeypatch.setattr(verify_module, "VerifyStage", FakeStage)

    state = {
        "knowledge": KnowledgeModel(
            cve_id="CVE-2022-0000",
            summary="demo",
            vulnerability_type="heap-overflow",
        ),
        "build": BuildArtifact(
            dockerfile_content="FROM ubuntu\n",
            build_script_content="#!/bin/bash\n",
            build_success=True,
        ),
        "poc": PoCArtifact(
            poc_filename="poc.lua",
            poc_content="boom",
            run_script_content="#!/bin/bash\n",
        ),
        "workspace": "workspaces/CVE-2022-0000",
        "stage_history": [],
    }

    result = verify_module.verify_node(state)

    assert result["verify"].verdict == "inconclusive"
    assert result["verify"].reason.startswith("verify_node_exception")
    assert result["final_status"] == "inconclusive"


# ===== Case 9 =====
def test_verify_run_template_renders_post_with_git_apply():
    stage = verify_module.VerifyStage()
    rendered = stage._render_template(
        "verify_run.sh.j2",
        {
            "target_binary": "src/lua",
            "run_command": "src/lua poc.lua",
            "repo_reset_command": "git reset --hard && git clean -fd",
            "rebuild_command": "bash /workspace/artifacts/build/build.sh",
            "patch_apply_command": "git apply /workspace/artifacts/verify/patch.diff",
            "project_dir_var": "${PROJECT_DIR}",
        },
    )

    assert "git apply" in rendered
    assert "target_binary=" in rendered
    assert "execution_exit_code=" in rendered
    assert "PATCH_MODE" in rendered


# ===== Case 10 =====
def test_route_after_verify_three_way():
    success_state = {"verify": VerifyResult(
        pre_patch_triggered=True, post_patch_clean=True, verdict="success", reason="ok"
    )}
    failed_state = {"verify": VerifyResult(
        pre_patch_triggered=False, post_patch_clean=True, verdict="failed", reason="x"
    )}
    inconclusive_state = {"verify": VerifyResult(
        pre_patch_triggered=False, post_patch_clean=False, verdict="inconclusive", reason="y"
    )}
    none_state = {}

    assert routers.route_after_verify(success_state) == "success"
    assert routers.route_after_verify(failed_state) == "failed"
    assert routers.route_after_verify(inconclusive_state) == "inconclusive"
    assert routers.route_after_verify(none_state) == "failed"
