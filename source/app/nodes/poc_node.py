"""计划功能：PoC 阶段节点，负责调用 PoC agent 生成并执行复现载荷，处理重试信息。"""
from app.agents.poc_agent import PoCAgent


def poc_node(state):
    knowledge = state["knowledge"]
    build = state["build"]
    retry_count = state.get("retry_count", {})
    history = state.get("stage_history", [])

    agent = PoCAgent()

    try:
        poc = agent.run(
            knowledge=knowledge,
            build=build,
            workspace=state["workspace"],
        )
        history.append({"stage": "poc", "status": "success"})
        return {
            "poc": poc,
            "stage_history": history,
            "last_error": None,
        }
    except Exception as e:
        retry_count["poc"] = retry_count.get("poc", 0) + 1
        history.append({"stage": "poc", "status": "failed", "error": str(e)})
        return {
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": str(e),
        }
