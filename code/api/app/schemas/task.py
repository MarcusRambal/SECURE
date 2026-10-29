# app/schemas/task.py
from pydantic import BaseModel, Field
from typing import Optional



class TaskRequest(BaseModel):
    target_url: str
    category: str
    attack_type: str

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str