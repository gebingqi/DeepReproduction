"""文件说明：主流程图构建器。

这里统一定义 DeepReproduction 的主执行链路：
knowledge -> build -> poc -> verify

这个文件只负责流程结构本身：
- 注册节点
- 指定入口
- 声明边关系
- 绑定路由函数

它不处理阶段实现，也不处理模型、Docker 或文件系统细节。
"""

from langgraph.graph import END, StateGraph

from app.orchestrator.routers import route_after_build, route_after_poc, route_after_verify
from app.orchestrator.state import AppState
from app.stages.build import build_node
from app.stages.knowledge import knowledge_node
from app.stages.poc import poc_node
from app.stages.verify import verify_node


def build_app_graph():
    """构造并编译主流程图。"""

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
            "inconclusive": END,
        },
    )

    return graph.compile()
