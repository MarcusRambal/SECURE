# agents/scan_agent.py


#ESTO ES UNA PRUEBA PARA PROBAR EL FLUJO ESTE CODIGO VA A CAMBIAR TOTALMENTE
import json
from typing import Dict, Any, List
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

from core.state import AgentState
from core.mcp_client import get_available_tools, call_mcp_tool

# Inicializamos el modelo de Gemini (asegúrate de tener GOOGLE_API_KEY en tu .env)
llm = ChatGoogleGenerativeAI(
    model="gemini-3.6-flash",
    temperature=0.2
)

async def scan_node(state: AgentState) -> AgentState:
    """
    Nodo de LangGraph que orquesta el escaneo web autónomo utilizando herramientas MCP.
    """
    target_url = state["target_url"]
    print(f"🤖 [SCAN AGENT] Iniciando análisis autónomo sobre: {target_url}")

    # 1. Obtenemos las herramientas expuestas por el Servidor MCP
    mcp_tools_schema = await get_available_tools()
    
    if not mcp_tools_schema:
        print("⚠️ [SCAN AGENT] No se encontraron herramientas registradas en el Servidor MCP.")
        state["logs"].append("Error: No hay herramientas MCP disponibles.")
        state["is_finished"] = True
        return state

    # Convertimos los schemas recibidos del servidor MCP al formato que espera LangChain/Gemini
    formatted_tools = []
    for tool in mcp_tools_schema:
        formatted_tools.append({
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["parameters"]
        })

    # 2. Bindeamos las herramientas al modelo de Gemini
    llm_with_tools = llm.bind_tools(formatted_tools)

    # 3. Construimos el contexto de conversación/prompt inicial
    messages = [
        HumanMessage(content=(
            f"Eres un agente experto en auditoría de ciberseguridad. Tu objetivo es realizar un escaneo de "
            f"vulnerabilidades en la siguiente URL objetivo: {target_url}.\n\n"
            f"Tienes acceso a un conjunto de herramientas de seguridad MCP. Selecciona la herramienta adecuada "
            f"para analizar el objetivo. Una vez que recibas los resultados del escaneo, analiza detalladamente "
            f"las vulnerabilidades encontradas, su impacto y proporciona recomendaciones de mitigación."
        ))
    ]

    # Bucle de interacción Agente <-> Herramientas (ReAct Loop)
    max_turns = 5
    for turn in range(max_turns):
        print(f"🔄 [SCAN AGENT] Turno {turn + 1}: Invocando a Gemini...")
        
        # Invocamos el modelo con el historial de mensajes
        response: AIMessage = await llm_with_tools.ainvoke(messages)
        messages.append(response)

        # Verificar si Gemini quiere ejecutar alguna herramienta
        if response.tool_calls:
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                tool_call_id = tool_call["id"]

                print(f"🛠️ [SCAN AGENT] Gemini decidió ejecutar: '{tool_name}' con args: {tool_args}")
                state["logs"].append(f"Ejecutando herramienta {tool_name} sobre {target_url}")

                # 4. Invocamos la herramienta en el servidor MCP remoto
                tool_result_text = await call_mcp_tool(tool_name, tool_args)

                # Creamos el mensaje con el resultado de la herramienta para devolvérselo a Gemini
                tool_message = ToolMessage(
                    content=tool_result_text,
                    tool_call_id=tool_call_id
                )
                messages.append(tool_message)
        else:
            # Si Gemini no pide ejecutar herramientas, significa que ya analizó los resultados y dio su informe
            final_analysis = response.content
            print("✨ [SCAN AGENT] Análisis completado por Gemini.")

            # Actualizamos el estado del grafo
            state["vulnerabilities"].append({
                "target": target_url,
                "analysis": final_analysis
            })
            state["logs"].append("Escaneo y reporte de auditoría completado con éxito.")
            state["current_node"] = "scan_node"
            state["is_finished"] = True
            
            return state

    print("⚠️ [SCAN AGENT] Se alcanzó el límite máximo de turnos sin finalizar.")
    state["is_finished"] = True
    return state