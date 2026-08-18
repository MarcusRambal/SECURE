#Este es nuestro cerebro

from core.state import AgentState

def orchestrator_router(state: AgentState) -> str:
    """
    Evalúa el estado global y determina el siguiente nodo a ejecutar.
    Actúa como regulador y guardián del flujo de auditoría.
    """
    if state.get("is_finished", False):
        return "END"
        
    if not state.get("endpoints_found"):
        return "recon_node"
    elif not state.get("vulnerabilities"):
        return "scan_node"
    elif not state.get("attack_results"):
        return "attack_node"
    else:
        return "report_node"