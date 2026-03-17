"""计划功能：验证阶段节点，负责调用 verifier agent 并回写最终验证结果与任务状态。"""
from app.agents.verifier_agent import VerifierAgent


def verify_node(state):
    knowledge = state["knowledge"]
    poc = state["poc"]
    agent = VerifierAgent()

    verify = agent.run(
        knowledge=knowledge,
        poc=poc,
        workspace=state["workspace"],
    )

    history = state.get("stage_history", [])
    history.append({"stage": "verify", "status": verify.verdict})

    final_status = "success" if verify.verdict == "success" else "failed"

    return {
        "verify": verify,
        "stage_history": history,
        "final_status": final_status,
        "last_error": None if final_status == "success" else verify.reason,
    }
