import operator
from typing import TypedDict, Annotated, List, Dict, Any, Optional

class Vulnerability(TypedDict):
    id: str
    type: str
    endpoint: str
    severity: str
    details: str
    raw_output: Optional[str]  # Salida cruda del contenedor efímero
    analysis: Optional[str]    # Reporte/Análisis generado por Gemini

class AgentState(TypedDict):
    scan_id: str               # UUID único generado en la API
    target_url: str
    endpoints_found: List[str]
    vulnerabilities: Annotated[List[Vulnerability], operator.add]
    attack_results: List[Dict[str, Any]]
    logs: Annotated[List[str], operator.add]
    current_node: str
    is_finished: bool