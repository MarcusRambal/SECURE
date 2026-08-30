from pydantic import BaseModel, Field
from typing import List, Optional

class FormInput(BaseModel):
    name_or_id: Optional[str] = Field(None, description="ID, nombre o selector del campo")
    input_type: str = Field(description="Tipo de input (email, text, password, etc.)")

class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "sql_injection"

from pydantic import BaseModel
from typing import Dict, Any, Optional

class DiscoveredEntryPoint(BaseModel):
    target_url: str                 # Endpoint de la API (ej: http://juice-shop:3000/rest/user/login)
    http_method: str = "POST"       # Método HTTP (POST, GET, etc.)
    entry_point_type: str           # Ej: sql_injection
    headers: Dict[str, str] = {}    # Headers (ej: {"Content-Type": "application/json"})
    payload_template: Dict[str, Any]# Esquema base (ej: {"email": "", "password": ""})
    target_field: str               # Campo a testear (ej: email)

    
class ValidationResponse(BaseModel):
    target_url: str
    vulnerable: bool
    payload_used: str
    details: str