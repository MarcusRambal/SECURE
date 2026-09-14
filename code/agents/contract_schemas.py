from pydantic import BaseModel, Field
from typing import List, Dict, Any, Literal, Optional

# ============================================================================
# 1. MODELOS DEL AGENTE DE RECONOCIMIENTO (RECON)
# ============================================================================


class DiscoveredEndpoint(BaseModel):
    url: str = Field(..., description="URL completa del endpoint o ruta descubierta")
    method: str = Field(default="GET", description="Método HTTP asociado (GET, POST, etc.)")
    parameters: List[str] = Field(
        default_factory=list, description="Parámetros detectados en la URL o body"
    )
    source: Optional[str] = Field(
        None,
        description="Herramienta MCP que descubrió este endpoint (ej: katana, zap_ajax_spider)",
    )
    notes: Optional[str] = Field(
        None, description="Detalles adicionales (ej. formulario de login, campo de búsqueda)"
    )


class ReconOutput(BaseModel):
    target_url: str = Field(..., description="URL raíz del objetivo auditado")
    endpoints: List[DiscoveredEndpoint] = Field(
        default_factory=list, description="Lista de endpoints descubiertos"
    )
    technologies: List[str] = Field(
        default_factory=list,
        description="Tecnologías/cabeceras detectadas (ej. Express, React, Nginx)",
    )
    passive_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Hallazgos pasivos (ej. cabeceras faltantes, cookies sin Secure flag)",
    )
    scan_started_at: Optional[str] = Field(
        None, description="Timestamp de inicio del reconocimiento (ISO 8601)"
    )
    scan_finished_at: Optional[str] = Field(
        None, description="Timestamp de finalización del reconocimiento (ISO 8601)"
    )


# ============================================================================
# 2. MODELOS DEL AGENTE DE VALIDACIÓN (VALIDATE)
# ============================================================================


class Vulnerability(BaseModel):
    type: str = Field(
        ..., description="Tipo de vulnerabilidad (ej: SQL Injection, XSS, OS Command Injection)"
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(
        ..., description="Severidad estimada del hallazgo"
    )
    endpoint: str = Field(..., description="Endpoint o URL específica afectada")
    parameter: Optional[str] = Field(
        None, description="Parámetro o campo vulnerable en la petición"
    )
    evidence: str = Field(
        ...,
        description="Fragmento de respuesta anómala, error SQL o comportamiento que confirma el hallazgo",
    )
    reproducible_command: str = Field(
        ...,
        description="Comando CLI exacto (curl, sqlmap, dalfox) para reproducir la vulnerabilidad",
    )
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Nivel de certeza de la validación"
    )
    tools_used: List[str] = Field(
        default_factory=list, description="Herramientas MCP utilizadas para la confirmación"
    )


class ValidateOutput(BaseModel):
    target_url: str = Field(..., description="URL raíz del objetivo")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Lista de vulnerabilidades confirmadas"
    )
    unconfirmed_findings: List[Dict[str, Any]] = Field(
        default_factory=list, description="Pruebas ejecutadas sin evidencia suficiente"
    )
    scan_started_at: Optional[str] = Field(
        None, description="Timestamp de inicio de validación (ISO 8601)"
    )
    scan_finished_at: Optional[str] = Field(
        None, description="Timestamp de finalización de validación (ISO 8601)"
    )


# ============================================================================
# 3. MODELOS DEL AGENTE REPORTADOR (REPORTER)
# ============================================================================


class ReporterInput(BaseModel):
    task_id: str = Field(..., description="UUID único de la tarea de auditoría")
    target_url: str = Field(..., description="URL objetivo")
    attack_type: str = Field(
        default="full",
        description="Tipo de auditoría solicitada (full, sql_injection, xss, command_injection)",
    )
    recon_used_fallback: bool = Field(
        default=False, description="Indica si el Recon-Agent utilizó mecanismo de respaldo"
    )
    validate_used_fallback: bool = Field(
        default=False, description="Indica si el Validate-Agent utilizó mecanismo de respaldo"
    )
    recon_data: ReconOutput = Field(..., description="Datos consolidados de reconocimiento")
    validation_data: ValidateOutput = Field(..., description="Datos consolidados de validación")
