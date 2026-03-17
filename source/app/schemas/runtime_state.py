"""计划功能：定义可持久化的运行时状态模型，便于保存任务阶段进度、错误和工作区信息。"""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class RuntimeState(BaseModel):

    task_id: str

    current_stage: str = "knowledge"

    retry_count: Dict[str, int] = Field(default_factory=dict)

    stage_history: List[dict] = Field(default_factory=list)

    last_error: Optional[str] = None

    workspace: Optional[str] = None

    final_status: str = "running"
