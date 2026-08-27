from pydantic import BaseModel, Field
from typing import Optional

class ScanRequest(BaseModel):
    target_url: str = Field(
        ..., 
        example="http://webgoat-target:8080/WebGoat",
        description="URL o IP del objetivo a analizar"
    )
    scan_type: Optional[str] = Field(
        default="full", 
        example="full",
        description="Tipo de escaneo (recon, web, full)"
    )

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str