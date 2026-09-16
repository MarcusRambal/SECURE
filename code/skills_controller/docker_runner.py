import docker
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_NETWORK = os.getenv("DOCKER_NETWORK", "sec-net")


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

        logger.info(f"🐳 [DOCKER] Spawneando contenedor efímero: {image} (Red: {target_network})")
        logger.info(f"👉 Comando: {command}")

        loop = asyncio.get_running_loop()

        def _run_docker_sync():
            try:
                logs = self.client.containers.run(
                    image=image,
                    command=command,
                    network=target_network,
                    detach=False,
                    remove=True,
                    stdout=True,
                    stderr=True,
                    mem_limit="1024m",
                )
                return {"status": "SUCCESS", "output": logs.decode("utf-8", errors="ignore")}
            except docker.errors.ContainerError as ce:
                # Verificar si el código de salida está en la lista permitida para esta herramienta
                if ce.exit_status in valid_exit_codes:
                    logger.info(
                        f"⚠️ {image} finalizó con estado {ce.exit_status} (permitido como éxito)."
                    )
                    output_text = ce.stderr.decode("utf-8", errors="ignore") if ce.stderr else ""
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
                    "output": ce.stderr.decode("utf-8", errors="ignore") if ce.stderr else str(ce),
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
