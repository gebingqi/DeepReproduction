"""计划功能：定义任务输入结构，承载单个 CVE 任务的基础信息、仓库信息和参考链接。"""
from pydantic import BaseModel, Field
from typing import List, Optional


class TaskModel(BaseModel):
    """
    输入任务模型
    """

    task_id: str = Field(..., description="唯一任务ID")

    cve_id: str = Field(..., description="漏洞编号")

    cve_url: Optional[str] = Field(
        None,
        description="CVE详情页面URL"
    )

    repo_url: Optional[str] = Field(
        None,
        description="漏洞对应源码仓库"
    )

    vulnerable_ref: Optional[str] = Field(
        None,
        description="漏洞版本commit/tag"
    )

    fixed_ref: Optional[str] = Field(
        None,
        description="修复版本commit/tag"
    )

    language: Optional[str] = Field(
        None,
        description="项目语言，例如 C/C++/Python"
    )

    references: List[str] = Field(
        default_factory=list,
        description="参考链接"
    )
