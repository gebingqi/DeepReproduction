"""计划功能：集中定义流程阶段与状态相关枚举，避免字符串常量在各模块中分散。"""
from enum import Enum


class Stage(str, Enum):
    KNOWLEDGE = "knowledge"
    BUILD = "build"
    POC = "poc"
    VERIFY = "verify"
    SUCCESS = "success"
    FAILED = "failed"
