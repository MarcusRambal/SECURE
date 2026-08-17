import os
import httpx
from typing import Dict, Any

# Dirección interna del contenedor en la red de Docker (sec-net)
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp-tools-server:5000")

async def call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    """
    Cliente genérico para invocar herramientas en el servidor MCP remoto.
    
    :param tool_name: Nombre de la herramienta expuesta en el MCP server (ej: 'nikto_scan')
    :param arguments: Diccionario con los parámetros requeridos por la herramienta
    :return: Resultado en texto producido por la herramienta
    """
    endpoint = f"{MCP_SERVER_URL}/call_tool"
    
    payload = {
        "name": tool_name,
        "arguments": arguments
    }
    
    print(f"📡 [MCP CLIENT] Enviando petición a {endpoint} -> Tool: {tool_name}")
    
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(endpoint, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("result", "Sin respuesta de la herramienta.")
            else:
                return f"Error en MCP Server ({response.status_code}): {response.text}"
                
    except httpx.ConnectError:
        return f"Error de conexión: No se pudo contactar con el Servidor MCP en {MCP_SERVER_URL}."
    except httpx.TimeoutException:
        return f"Timeout: La herramienta '{tool_name}' superó el tiempo límite de respuesta."
    except Exception as e:
        return f"Error inesperado invocando herramienta MCP: {str(e)}"