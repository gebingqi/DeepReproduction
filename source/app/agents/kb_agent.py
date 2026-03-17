"""计划功能：知识采集智能体，负责聚合漏洞资料并生成结构化的 KnowledgeModel。"""
from app.schemas.task import TaskModel
from app.schemas.knowledge import KnowledgeModel


class KBAgent:
    def render_prompt(self, task: TaskModel, documents: str) -> str:
        return f"""
You are a security research assistant.
Analyze the following vulnerability documents and return structured data.

CVE ID: {task.cve_id}
DOCUMENTS:
{documents}
""".strip()

    def run(self, task: TaskModel, workspace: str) -> KnowledgeModel:
        # 1. fetch pages
        # 2. clean pages
        # 3. merge documents
        # 4. call model with structured output
        # 5. save artifacts into workspace
        raise NotImplementedError
