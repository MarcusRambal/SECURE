# backend/core/mcp_client/client.py

import httpx
from typing import Dict, Any

class MCPClient:
    def __init__(self, base_url: str = "http://tools-library:5000"):
        self.base_url = base_url

    async def get_available_tools(self) -> list:
        """Obtiene la lista de schemas de herramientas desde el microservicio."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/tools")
            response.raise_for_status()
            return response.json().get("tools", [])

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Solicita la ejecución de una herramienta específica."""
        payload = {"name": name, "arguments": arguments}
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(f"{self.base_url}/call_tool", json=payload)
            response.raise_for_status()
            return response.json()