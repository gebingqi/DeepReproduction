"""计划功能：定义验证阶段输出结构，描述漏洞在修复前后是否可触发以及最终判定理由。"""
from pydantic import BaseModel, Field
from typing import List


class VerifyResult(BaseModel):

    pre_patch_triggered: bool

    post_patch_clean: bool

    matched_error_patterns: List[str] = Field(default_factory=list)

    matched_stack_keywords: List[str] = Field(default_factory=list)

    verdict: str

    reason: str
