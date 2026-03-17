"""计划功能：PoC 生成智能体，负责基于漏洞知识和构建产物生成最小复现代码与运行脚本。"""
from app.schemas.knowledge import KnowledgeModel
from app.schemas.build_artifact import BuildArtifact
from app.schemas.poc_artifact import PoCArtifact


class PoCAgent:
    def render_prompt(self, knowledge: KnowledgeModel, build: BuildArtifact) -> str:
        return f"""
You are a vulnerability reproduction agent.
Generate a minimal PoC.

KNOWLEDGE:
{knowledge.model_dump_json(indent=2)}

BUILD:
{build.model_dump_json(indent=2)}
""".strip()

    def run(self, knowledge: KnowledgeModel, build: BuildArtifact, workspace: str) -> PoCArtifact:
        # 1. call model
        # 2. save poc/run.sh
        # 3. execute poc
        # 4. capture logs
        raise NotImplementedError
