"""计划功能：定义构建阶段产物结构，记录 Dockerfile、构建脚本、构建命令和构建结果。"""
from pydantic import BaseModel, Field
from typing import List, Optional


class BuildArtifact(BaseModel):

    dockerfile_content: str

    build_script_content: str

    install_packages: List[str] = Field(default_factory=list)

    build_commands: List[str] = Field(default_factory=list)

    expected_binary_path: Optional[str] = None

    sanitizer_enabled: bool = False

    build_success: bool = False

    build_logs: str = ""
