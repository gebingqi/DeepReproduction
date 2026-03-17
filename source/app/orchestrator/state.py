"""计划功能：定义 LangGraph 运行时共享状态，作为各阶段节点之间传递信息的统一容器。"""
from typing import Optional, Dict, List, TypedDict

from app.schemas.task import TaskModel
from app.schemas.knowledge import KnowledgeModel
from app.schemas.build_artifact import BuildArtifact
from app.schemas.poc_artifact import PoCArtifact
from app.schemas.verify_result import VerifyResult


class AppState(TypedDict, total=False):
    task: TaskModel
    knowledge: KnowledgeModel
    build: BuildArtifact
    poc: PoCArtifact
    verify: VerifyResult

    current_stage: str
    retry_count: Dict[str, int]
    stage_history: List[dict]
    last_error: Optional[str]
    workspace: str
    final_status: str
