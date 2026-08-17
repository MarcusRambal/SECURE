import os
import warnings
# Ocultar advertencias secundarias de Google Gemini
warnings.filterwarnings("ignore", category=UserWarning)

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from core.state import AgentState
from mcp_client.client import call_mcp_tool

# Inicialización del modelo
llm = ChatGoogleGenerativeAI(
    model="gemini-3.6-flash",
    temperature=0.2,
    google_api_key=os.getenv("GEMINI_API_KEY")
)

async def scan_node(state: AgentState) -> dict:
    target_url = state.get("target_url", "")
    
    print(f"\n🔍 [SCAN AGENT] Iniciando escaneo de seguridad en: {target_url}")
    
    # 1. Invocación de Nikto mediante el Cliente MCP
    raw_scan_results = await call_mcp_tool(
        tool_name="nikto_scan",
        arguments={"target_url": target_url}
    )
    
    print("⚙️ [SCAN AGENT] Escaneo de Nikto completado. Analizando resultados con Gemini...")
    
    # 2. Prompts claros para Gemini
    system_prompt = (
        "Eres un analista experto en ciberseguridad. A continuación recibirás la salida "
        "en texto plano de un escaneo ejecutado por la herramienta Nikto sobre una aplicación web.\n\n"
        "Tu objetivo es:\n"
        "1. Clasificar los hallazgos en niveles de riesgo: ALTO, MEDIO, BAJO e INFORMATIVO.\n"
        "2. Explicar brevemente el impacto de cada falla encontrada.\n"
        "3. Dar recomendaciones prácticas para solucionar las vulnerabilidades."
    )
    
    user_prompt = f"Aquí está la salida de Nikto para el objetivo '{target_url}':\n\n```text\n{str(raw_scan_results)}\n```"
    
    try:
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ])
        
        # Extraer solo el texto plano retornado por el LLM
        if isinstance(response.content, list):
            llm_analysis = "".join([block.get("text", "") for block in response.content if isinstance(block, dict)])
        else:
            llm_analysis = str(response.content)
            
    except Exception as e:
        llm_analysis = f"Error al procesar el análisis con Gemini: {str(e)}"

    print("✅ [SCAN AGENT] Análisis finalizado.")
    
    return {
        "vulnerabilities": state.get("vulnerabilities", []) + [
            {
                "tool": "nikto",
                "analysis": llm_analysis
            }
        ],
        "logs": state.get("logs", []) + [f"[SCAN] Completado escaneo Nikto sobre {target_url}"],
        "current_node": "scan_node"
    }