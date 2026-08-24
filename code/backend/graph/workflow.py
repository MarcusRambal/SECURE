import asyncio
import logging

from graph.core.state import AgentState
from graph.agents.scan_agent import scan_node
from backend.database import update_scan_status, save_tool_finding

logger = logging.getLogger(__name__)

async def run_audit_workflow(scan_id: str, target_url: str, attack_type: str):
    """
    Punto de entrada invocado por el BackgroundTask de FastAPI.
    """
    await _execute_workflow(scan_id, target_url, attack_type)

async def _execute_workflow(scan_id: str, target_url: str, attack_type: str):
    print("\n" + "="*60)
    print("🚀 [ORCHESTRATOR] Nueva auditoría iniciada desde la API")
    print(f"🆔 Scan ID:    {scan_id}")
    print(f"🎯 Target URL: {target_url}")
    print(f"⚔️  Attack Type: {attack_type}")
    print("="*60 + "\n")
    
    initial_state: AgentState = {
        "scan_id": scan_id,
        "target_url": target_url,
        "endpoints_found": [],
        "vulnerabilities": [],
        "attack_results": [],
        "logs": [f"Iniciada solicitud {attack_type} sobre {target_url}"],
        "current_node": "init",
        "is_finished": False
    }
    
    try:
        # Ejecutar según la estrategia solicitada
        if attack_type == "scanWeb":
            result_state = await scan_node(initial_state)
            
            # Recuperar hallazgos del estado y guardarlos en PostgreSQL
            vulnerabilities = result_state.get("vulnerabilities", [])
            if vulnerabilities:
                latest = vulnerabilities[-1]
                print("\n🤖 [GEMINI AUDIT REPORT]:")
                print("-" * 50)
                print(latest.get("analysis", "Sin análisis"))
                print("-" * 50 + "\n")
                
                # Persistencia en la tabla tool_findings
                await save_tool_finding(
                    scan_id=scan_id,
                    tool_name="scanWeb_agent",
                    raw_output=str(latest.get("raw_output", "")),
                    parsed_json=latest
                )

        # Marcar el escaneo como completado en la BD
        await update_scan_status(scan_id, "COMPLETED")
        print(f"✅ Auditoría {scan_id} completada con éxito.\n")

    except Exception as e:
        logger.error(f"❌ Error durante la ejecución del workflow ({scan_id}): {e}")
        await update_scan_status(scan_id, "FAILED")