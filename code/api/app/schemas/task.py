# app/schemas/task.py
from pydantic import BaseModel, Field
from typing import Optional


class AgentModelsSchema(BaseModel):
    scanner: str
    attacker: str
    reporter: str

class TaskRequest(BaseModel):
    target_url: str
    category: str
    attack_type: Optional[str] 
    agent_models: Optional[AgentModelsSchema] = None

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str