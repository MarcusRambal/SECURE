# agents/scan_agent.py
import json
from typing import Dict, Any
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, ToolMessage
from core.state import AgentState
from core.mcp_client import get_available_tools, call_mcp_tool

llm = ChatGoogleGenerativeAI(
    model="gemini-3.6-flash",
    temperature=0.2
)

async def scan_node(state: AgentState) -> AgentState:
    """
    Nodo de LangGraph que orquesta el flujo de auditoría (Recon -> Intercept -> Attack)
    usando Gemini para llamar a las herramientas MCP especializadas.
    """
    target_url = state["target_url"]
    print(f"🤖 [SCAN AGENT] Iniciando auditoría inteligente en: {target_url}")

    mcp_tools_schema = await get_available_tools()
    
    if not mcp_tools_schema:
        state["logs"].append("Error: Servidor MCP no disponible.")
        state["is_finished"] = True
        return state

    formatted_tools = [
        {
            "name": tool["name"],
            "description": tool["description"],
            "parameters": tool["parameters"]
        }
        for tool in mcp_tools_schema
    ]

    llm_with_tools = llm.bind_tools(formatted_tools)

    messages = [
        HumanMessage(content=(
            f"Eres el agente supervisor de auditoría de ciberseguridad SECURE.\n"
            f"Objetivo: Evaluar {target_url} siguiendo el pipeline:\n"
            f"1. Descubrimiento de endpoints usando Katana.\n"
            f"2. Intercepción de peticiones clave (como formularios de login) con Playwright.\n"
            f"3. Análisis de inyección SQL con sqlmap sobre las peticiones capturadas.\n\n"
            f"Usa las herramientas MCP disponibles para completar cada fase y finalmente genera un informe final."
        ))
    ]

    max_turns = 8
    for turn in range(max_turns):
        print(f"🔄 [SCAN AGENT] Turno {turn + 1}")
        response = await llm_with_tools.ainvoke(messages)
        messages.append(response)

        if response.tool_calls:
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["args"]
                tool_call_id = tool_call["id"]

                print(f"🛠️ [SCAN AGENT] Invocando MCP Tool: '{tool_name}'")
                state["logs"].append(f"Ejecutando {tool_name}")

                tool_result_text = await call_mcp_tool(tool_name, tool_args)

                messages.append(ToolMessage(
                    content=tool_result_text,
                    tool_call_id=tool_call_id
                ))
        else:
            state["vulnerabilities"].append({
                "target": target_url,
                "report": response.content
            })
            state["logs"].append("Pipeline de auditoría finalizado exitosamente.")
            state["is_finished"] = True
            return state

    state["is_finished"] = True
    return state