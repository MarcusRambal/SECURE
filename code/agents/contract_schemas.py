from pydantic import BaseModel, Field
from typing import List, Dict, Any, Literal, Optional

# ============================================================================
# 1. MODELOS DEL AGENTE DE RECONOCIMIENTO (RECON)
# ============================================================================


class ReconSummary(BaseModel):
    target_url: str = Field(..., description="URL raíz del objetivo analizado")
    attack_type_filter: str = Field(..., description="Tipo de ataque solicitado")
    total_targets_identified: int = Field(
        ..., description="Cantidad de objetivos de validación identificados"
    )
    total_requests_captured: int = Field(
        default=0, description="Cantidad de solicitudes observadas por reconocimiento"
    )

class HighPriorityTarget(BaseModel):
    target_id: str = Field(..., description="Identificador único del objetivo")
    request_id: str = Field(
        default="", description="ID real de la solicitud capturada, o vacío si no existe"
    )
    vulnerability_target: str = Field(
        ..., description="Motivo basado en evidencia para priorizar este objetivo"
    )
    endpoint: str = Field(..., description="URL observada del endpoint")
    method: str = Field(..., description="Método HTTP observado")
    request: Optional[Dict[str, Any]] = Field(
        default=None, description="Detalles de la solicitud capturada, si existen"
    )
    recommended_tool: str = Field(
        ..., description="Herramienta disponible recomendada para futura validación"
    )

class ReconPlannerOutput(BaseModel):
    recon_summary: ReconSummary = Field(..., description="Resumen de reconocimiento")
    high_priority_targets: List[HighPriorityTarget] = Field(
        ..., description="Objetivos priorizados con evidencia de reconocimiento"
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


class ValidateFindingSubmission(BaseModel):
    type: str = Field(..., description="Tipo de vulnerabilidad confirmada")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(
        ..., description="Severidad estimada del hallazgo"
    )
    endpoint: str = Field(..., description="Endpoint o URL afectada")
    parameter: Optional[str] = Field(
        None, description="Parámetro o campo vulnerable en la petición"
    )
    evidence: str = Field(..., description="Evidencia concreta de la confirmación")
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Nivel de certeza de la validación"
    )
    tools_used: List[str] = Field(
        default_factory=list, description="Herramientas MCP utilizadas"
    )


class ValidateSubmission(BaseModel):
    target_url: str = Field(..., description="URL raíz del objetivo")
    vulnerabilities: List[ValidateFindingSubmission] = Field(
        default_factory=list, description="Hallazgos confirmados por el agente"
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
    recon_data: ReconPlannerOutput = Field(..., description="Datos consolidados de reconocimiento")
    validation_data: ValidateOutput = Field(..., description="Datos consolidados de validación")
