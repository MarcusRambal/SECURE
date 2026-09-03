import logging
from mcp.server.fastmcp import FastMCP
from tools.nikto_tool import register_nikto_tool

logging.basicConfig(level=logging.INFO)

# Instanciamos el Servidor MCP
mcp = FastMCP("Security-Skills-Controller", host="0.0.0.0", port=8001)

# Registramos las herramientas disponibles
register_nikto_tool(mcp)

if __name__ == "__main__":
    # Inicia el servidor MCP exponiendo transporte SSE
    mcp.run(transport="sse")