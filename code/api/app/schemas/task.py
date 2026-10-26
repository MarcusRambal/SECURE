from pydantic import BaseModel
from typing import Optional


class AgentModelsSchema(BaseModel):
    scanner: str
    attacker: str
    reporter: str


class TaskRequest(BaseModel):
    target_url: str
    category: str
    attack_type: Optional[str] = None
    agent_models: Optional[AgentModelsSchema] = None
    # JWT de sesión para ataques A07 (jwt). Vacío para SQLi/XSS/etc.
    token: Optional[str] = None


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str