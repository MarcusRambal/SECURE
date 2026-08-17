
#Inicializa el AgentState con la URL y el attack_type, y arranca la ejecucion del grafo

import asyncio
from core.state import AgentState
from agents.scan_agent import scan_node

def run_audit_workflow(target_url: str, attack_type: str):
    """
    Inicia la ejecución del workflow de auditoría de forma asíncrona.
    """
    asyncio.run(_execute_workflow(target_url, attack_type))

async def _execute_workflow(target_url: str, attack_type: str):
    print("\n" + "="*60)
    print(f"🚀 [ORCHESTRATOR] Nueva auditoría iniciada desde la API")
    print(f"🎯 Target URL:  {target_url}")
    print(f"⚔️  Attack Type: {attack_type}")
    print("="*60 + "\n")
    
    initial_state: AgentState = {
        "target_url": target_url,
        "endpoints_found": [],
        "vulnerabilities": [],
        "attack_results": [],
        "logs": [f"Iniciada solicitud {attack_type} sobre {target_url}"],
        "current_node": "init",
        "is_finished": False
    }
    
    # Si el ataque solicitado es 'scanWeb', ejecutamos el scan_node
    if attack_type == "scanWeb":
        result_state = await scan_node(initial_state)
        
        # Mostrar el análisis estructurado por Gemini en los logs del contenedor
        vulnerabilities = result_state.get("vulnerabilities", [])
        if vulnerabilities:
            latest = vulnerabilities[-1]
            print("\n🤖 [GEMINI AUDIT REPORT]:")
            print("-" * 50)
            print(latest["analysis"])
            print("-" * 50 + "\n")
            
    print("✅ Auditoría completada con éxito.\n")