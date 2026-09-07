#skills_controller/docker_runner.py
import docker
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_NETWORK = os.getenv("DOCKER_NETWORK", "sec-net")

class EphemeralDockerRunner:
    def __init__(self):
        self.client = docker.from_env()

    async def execute_tool(self, image: str, command: str, timeout: int = 300, network_name: str = None) -> dict:
        target_network = network_name or DEFAULT_NETWORK
        logger.info(f"🐳 [DOCKER] Spawneando contenedor efímero: {image} (Red: {target_network})")
        logger.info(f"👉 Comando: {command}")

        loop = asyncio.get_running_loop()

        def _run_docker_sync():
            try:
                # 1. Agregamos mem_limit="1g" para controlar el consumo de RAM
                logs = self.client.containers.run(
                    image=image,
                    command=command,
                    network=target_network,
                    detach=False,
                    remove=True,
                    stdout=True,
                    stderr=True,
                    mem_limit="1024m"  # <--- Limita la memoria RAM a 1 GB por contenedor efímero
                )
                return {
                    "status": "SUCCESS",
                    "output": logs.decode("utf-8", errors="ignore")
                }
            except docker.errors.ContainerError as ce:
                # 1, 2 = Hallazgos detectados, 3 = Advertencias/Salidas de reporte
                if ce.exit_status in (1, 2, 3):
                    logger.info(f"⚠️ ZAP finalizó con estado {ce.exit_status}.")
                    output_text = ce.stderr.decode("utf-8", errors="ignore") if ce.stderr else ""
                    
                    return {
                        "status": "SUCCESS",
                        "output": output_text or f"Escaneo completado con código de estado ZAP {ce.exit_status}."
                    }

                logger.error(f"Error durante la ejecución del contenedor efímero: {ce}")
                return {
                    "status": "ERROR",
                    "output": ce.stderr.decode("utf-8", errors="ignore") if ce.stderr else str(ce)
                }
            except Exception as e:
                logger.error(f"Fallo invocando el Engine de Docker: {e}")
                return {
                    "status": "FAILED",
                    "output": str(e)
                }

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _run_docker_sync),
                timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.error(f"⏰ Timeout de ejecución excedido ({timeout}s) para la imagen {image}")
            return {
                "status": "TIMEOUT",
                "output": f"La herramienta superó el tiempo máximo permitido ({timeout}s)."
            }

docker_runner = EphemeralDockerRunner()