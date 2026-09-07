from tools.docker_runner import run_ephemeral_container

def register_katana_tool(mcp_server):
    @mcp_server.tool()
    def run_katana_scan(target_url: str) -> str:
        """
        Ejecuta un crawling/rastreo de rutas con Katana sobre una URL objetivo.
        :param target_url: URL completa a rastrear (ej. http://juice-shop:3000)
        """
        # Command para ejecutar Katana en modo silencioso y retornar URLs encontradas
        command = f"-u {target_url} -silent -jc"
        return run_ephemeral_container(
            image="projectdiscovery/katana:latest",
            command=command
        )