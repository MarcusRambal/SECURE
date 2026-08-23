# core/mcp_client/client.py
import os
import httpx
from typing import Dict, Any, List

MCP_SERVER_URL = os.getenv("tools-library", "http://tools-library:5000")

async def get_available_tools() -> List[Dict[str, Any]]:
    """Obtiene el catálogo de herramientas expuestas por el servidor MCP."""
    endpoint = f"{MCP_SERVER_URL}/tools"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(endpoint)
            if response.status_code == 200:
                return response.json().get("tools", [])
            print(f"❌ Error obteniendo tools ({response.status_code}): {response.text}")
            return []
    except Exception as e:
        print(f"❌ Error conectando con MCP Server para listar tools: {e}")
        return []

async def call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    # Tu función actual se queda exactamente igual
    endpoint = f"{MCP_SERVER_URL}/call_tool"
    payload = {"name": tool_name, "arguments": arguments}
    print(f"📡 [MCP CLIENT] Invocando {tool_name}")
    
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(endpoint, json=payload)
            if response.status_code == 200:
                return response.json().get("result", "Sin respuesta.")
            return f"Error en MCP Server ({response.status_code}): {response.text}"
    except httpx.TimeoutException:
        return f"Timeout: '{tool_name}' superó el tiempo límite."
    except Exception as e:
        return f"Error inesperado: {str(e)}"