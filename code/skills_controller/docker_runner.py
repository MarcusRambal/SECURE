import docker
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_NETWORK = os.getenv("DOCKER_NETWORK", "sec-net")
REQUESTS_VOLUME = os.getenv("REQUESTS_VOLUME", "secure-requests-data")


class EphemeralDockerRunner:
    def __init__(self):
        self.client = docker.from_env()

    async def execute_tool(
        self,
        image: str,
        command: str,
        timeout: int = 300,
        network_name: str = None,
        success_exit_codes: list = None,
    ) -> dict:
        target_network = network_name or DEFAULT_NETWORK
        valid_exit_codes = success_exit_codes if success_exit_codes is not None else [0]

        def decode(value) -> str:
            if not value:
                return ""
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        def combine_output(stdout, stderr) -> str:
            stdout_text = decode(stdout)
            stderr_text = decode(stderr)
            if stdout_text and stderr_text:
                return f"{stdout_text}\n\n[stderr]\n{stderr_text}"
            return stdout_text or stderr_text

        logger.info(f"🐳 [DOCKER] Spawneando contenedor efímero: {image} (Red: {target_network})")
        logger.info(f"👉 Comando: {command}")

        loop = asyncio.get_running_loop()

        def _run_docker_sync():
            try:
                logs = self.client.containers.run(
                    image=image,
                    command=command,
                    network=target_network,
                    volumes={
                        REQUESTS_VOLUME: {
                            "bind": "/app/captured_requests",
                            "mode": "rw",
                        }
                    },
                    detach=False,
                    remove=True,
                    stdout=True,
                    stderr=True,
                    mem_limit="1024m",
                    shm_size="1g",
                    environment={
                        "HTTP_PROXY": "",
                        "HTTPS_PROXY": "",
                        "ALL_PROXY": "",
                        "http_proxy": "",
                        "https_proxy": "",
                        "all_proxy": "",
                        "NO_PROXY": "localhost,127.0.0.1",
                        "no_proxy": "localhost,127.0.0.1",
                    },
                )
                return {"status": "SUCCESS", "output": decode(logs)}
            except docker.errors.ContainerError as ce:
                # Verificar si el código de salida está en la lista permitida para esta herramienta
                if ce.exit_status in valid_exit_codes:
                    logger.info(
                        f"⚠️ {image} finalizó con estado {ce.exit_status} (permitido como éxito)."
                    )
                    output_text = combine_output(
                        getattr(ce, "stdout", None), getattr(ce, "stderr", None)
                    )
                    return {
                        "status": "SUCCESS",
                        "output": output_text
                        or f"Escaneo completado con código de estado {ce.exit_status}.",
                    }

                logger.error(
                    f"❌ {image} falló con código de salida no permitido: {ce.exit_status}"
                )
                return {
                    "status": "ERROR",
                    "output": combine_output(
                        getattr(ce, "stdout", None), getattr(ce, "stderr", None)
                    )
                    or str(ce),
                }
            except Exception as e:
                logger.error(f"Fallo invocando el Engine de Docker: {e}")
                return {"status": "FAILED", "output": str(e)}

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _run_docker_sync), timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.error(f"⏰ Timeout de ejecución excedido ({timeout}s) para la imagen {image}")
            return {
                "status": "TIMEOUT",
                "output": f"La herramienta superó el tiempo máximo permitido ({timeout}s).",
            }


docker_runner = EphemeralDockerRunner()
