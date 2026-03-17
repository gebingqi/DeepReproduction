"""计划功能：构建阶段节点，负责调用 builder agent 生成构建产物并记录成功或失败状态。"""
from app.agents.builder_agent import BuilderAgent


def build_node(state):
    knowledge = state["knowledge"]
    retry_count = state.get("retry_count", {})
    history = state.get("stage_history", [])

    agent = BuilderAgent()

    try:
        build = agent.run(knowledge=knowledge, workspace=state["workspace"])
        history.append({"stage": "build", "status": "success"})
        return {
            "build": build,
            "stage_history": history,
            "last_error": None,
        }
    except Exception as e:
        retry_count["build"] = retry_count.get("build", 0) + 1
        history.append({"stage": "build", "status": "failed", "error": str(e)})
        return {
            "retry_count": retry_count,
            "stage_history": history,
            "last_error": str(e),
        }
