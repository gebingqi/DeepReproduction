"""计划功能：项目命令行入口，负责加载任务、初始化运行状态并启动 LangGraph 主流程。"""
import yaml

from app.orchestrator.graph import build_app_graph
from app.schemas.task import TaskModel


def main():
    with open("data/tasks/demo.yaml", "r", encoding="utf-8") as f:
        task_data = yaml.safe_load(f)

    task = TaskModel(**task_data)

    graph = build_app_graph()

    initial_state = {
        "task": task,
        "workspace": f"workspaces/{task.task_id}",
        "retry_count": {},
        "stage_history": [],
        "current_stage": "knowledge",
        "final_status": "running",
    }

    result = graph.invoke(initial_state)
    print(result)


if __name__ == "__main__":
    main()
