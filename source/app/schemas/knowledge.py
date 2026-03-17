"""计划功能：定义漏洞知识结构，作为 knowledge 阶段输出及 build/poc/verify 阶段的统一输入。"""
from pydantic import BaseModel, Field
from typing import List, Optional


class KnowledgeModel(BaseModel):
    """
    知识提取结果
    """

    cve_id: str

    summary: str = Field(
        description="漏洞摘要"
    )

    vulnerability_type: str = Field(
        description="漏洞类型"
    )

    repo_url: Optional[str] = None

    vulnerable_ref: Optional[str] = None

    fixed_ref: Optional[str] = None

    affected_files: List[str] = Field(
        default_factory=list
    )

    reproduction_hints: List[str] = Field(
        default_factory=list
    )

    expected_error_patterns: List[str] = Field(
        default_factory=list
    )

    expected_stack_keywords: List[str] = Field(
        default_factory=list
    )

    references: List[str] = Field(
        default_factory=list
    )
