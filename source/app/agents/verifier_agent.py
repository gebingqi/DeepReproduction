"""计划功能：验证阶段智能体，负责综合前后版本运行日志判断漏洞是否被稳定触发与修复。"""
from app.schemas.knowledge import KnowledgeModel
from app.schemas.poc_artifact import PoCArtifact
from app.schemas.verify_result import VerifyResult


class VerifierAgent:
    def render_prompt(self, pre_log: str, post_log: str, knowledge: KnowledgeModel) -> str:
        return f"""
You are a vulnerability verification agent.

EXPECTED ERROR PATTERNS:
{knowledge.expected_error_patterns}

EXPECTED STACK KEYWORDS:
{knowledge.expected_stack_keywords}

PRE PATCH LOG:
{pre_log}

POST PATCH LOG:
{post_log}
""".strip()

    def run(self, knowledge: KnowledgeModel, poc: PoCArtifact, workspace: str) -> VerifyResult:
        # 1. load pre/post logs
        # 2. call model or deterministic matcher
        # 3. return structured result
        raise NotImplementedError
