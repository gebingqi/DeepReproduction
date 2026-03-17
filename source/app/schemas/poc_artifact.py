"""计划功能：定义 PoC 阶段产物结构，记录复现代码、运行脚本、输入文件与执行结果。"""
from pydantic import BaseModel, Field
from typing import List


class PoCArtifact(BaseModel):

    poc_filename: str

    poc_content: str

    run_script_content: str

    input_files: List[str] = Field(default_factory=list)

    expected_error_patterns: List[str] = Field(default_factory=list)

    execution_success: bool = False

    execution_logs: str = ""
