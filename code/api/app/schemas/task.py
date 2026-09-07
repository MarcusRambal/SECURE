# app/schemas/task.py
from pydantic import BaseModel, Field
from typing import Optional

class TaskRequest(BaseModel):
    target_url: str = Field(
        ..., 
        example="http://juice-shop:3000/#/login",
        description="URL o IP del objetivo a analizar"
    )
    attack_type: Optional[str] = Field(
        default="full", 
        example="full",
        description="Tipo de ataque a realizar (ej: full, sql_injection, xss)"
    )

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str