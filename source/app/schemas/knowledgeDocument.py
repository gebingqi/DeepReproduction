"""计划功能：定义清洗后的知识文档结构，作为网页抓取结果与知识提取阶段之间的中间接口。"""
from pydantic import BaseModel


class KnowledgeDocument(BaseModel):

    url: str

    title: str

    cleaned_text: str
