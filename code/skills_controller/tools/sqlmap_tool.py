from tools.docker_runner import run_ephemeral_container

def register_sqlmap_tool(mcp_server):
    @mcp_server.tool()
    def run_sqlmap_scan(target_url: str, param: str = "") -> str:
        """
        Ejecuta una evaluación pasiva/básica de inyección SQL con SQLMap sobre un endpoint.
        :param target_url: URL o endpoint objetivo a analizar.
        :param param: Parámetro específico a probar (opcional).
        """
        param_flag = f"-p {param}" if param else ""
        command = f"-u \"{target_url}\" {param_flag} --batch --risk=1 --level=1"
        return run_ephemeral_container(
            image="sqlmapproject/sqlmap:latest",
            command=command
        )