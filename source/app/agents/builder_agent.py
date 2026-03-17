"""计划功能：构建环境智能体，负责生成 Dockerfile、构建脚本并组织漏洞版本的编译过程。"""
from app.schemas.knowledge import KnowledgeModel
from app.schemas.build_artifact import BuildArtifact


class BuilderAgent:
    def render_prompt(self, knowledge: KnowledgeModel) -> str:
        return f"""
You are a build environment generation agent.
Generate Dockerfile and build script from the following knowledge:

{knowledge.model_dump_json(indent=2)}
""".strip()

    def run(self, knowledge: KnowledgeModel, workspace: str) -> BuildArtifact:
        # 1. call model
        # 2. write Dockerfile/build.sh
        # 3. invoke docker tools
        # 4. collect logs
        raise NotImplementedError
