from code.skills_controller.docker_runner import run_ephemeral_container

def register_nikto_tool(mcp_server):
    @mcp_server.tool()
    def run_nikto_scan(target_url: str) -> str:
        """
        Ejecuta un escaneo de vulnerabilidades web Nikto contra una URL en la red sec-net.
        :param target_url: URL objetivo completa o host (ej. http://webgoat-target:8080/WebGoat)
        """
        command = f"-h {target_url} -Tuning 1,2,3b"
        return run_ephemeral_container(
            image="frapsoft/nikto:latest",
            command=command
        )