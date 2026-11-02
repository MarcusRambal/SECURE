from pydantic import BaseModel
from typing import Optional




class TaskRequest(BaseModel):
    target_url: str
    category: str
    attack_type: str
    # JWT de sesión para ataques A07 (jwt). Vacío para SQLi/XSS/etc.
    token: Optional[str] = None


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str