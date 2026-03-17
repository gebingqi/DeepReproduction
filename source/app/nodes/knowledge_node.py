"""计划功能：知识阶段节点，负责调用知识采集 agent 并产出后续阶段可消费的漏洞知识。"""
from app.agents.kb_agent import KBAgent


def knowledge_node(state):
    task = state["task"]
    agent = KBAgent()

    knowledge = agent.run(task=task, workspace=state["workspace"])

    history = state.get("stage_history", [])
    history.append({"stage": "knowledge", "status": "success"})

    return {
        "knowledge": knowledge,
        "current_stage": "build",
        "stage_history": history,
        "last_error": None,
    }
