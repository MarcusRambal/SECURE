from typing import TypedDict, Annotated, List, Dict, Any
import operator

class Vulnerability(TypedDict):
    id: str
    type: str
    endpoint: str
    severity: str
    details: str

class AgentState(TypedDict):
    target_url: str
    endpoints_found: List[str]
    vulnerabilities: List[Vulnerability]
    attack_results: List[Dict[str, Any]]
    logs: Annotated[List[str], operator.add]
    current_node: str
    is_finished: bool