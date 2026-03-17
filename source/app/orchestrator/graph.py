"""计划功能：组装漏洞复现主流程图，串联 knowledge、build、poc、verify 四个阶段。"""
from langgraph.graph import StateGraph, END

from app.orchestrator.state import AppState
from app.orchestrator.routers import route_after_build, route_after_poc, route_after_verify
from app.nodes.knowledge_node import knowledge_node
from app.nodes.build_node import build_node
from app.nodes.poc_node import poc_node
from app.nodes.verify_node import verify_node


def build_app_graph():
    graph = StateGraph(AppState)

    graph.add_node("knowledge", knowledge_node)
    graph.add_node("build", build_node)
    graph.add_node("poc", poc_node)
    graph.add_node("verify", verify_node)

    graph.set_entry_point("knowledge")

    graph.add_edge("knowledge", "build")

    graph.add_conditional_edges(
        "build",
        route_after_build,
        {
            "poc": "poc",
            "build": "build",
            "failed": END,
        },
    )

    graph.add_conditional_edges(
        "poc",
        route_after_poc,
        {
            "verify": "verify",
            "poc": "poc",
            "failed": END,
        },
    )

    graph.add_conditional_edges(
        "verify",
        route_after_verify,
        {
            "success": END,
            "failed": END,
        },
    )

    return graph.compile()
