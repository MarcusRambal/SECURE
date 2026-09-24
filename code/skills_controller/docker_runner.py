import asyncio
import io
import logging
import os
import tarfile
import docker

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
        input_files: dict[str, str] | None = None,
    ) -> dict:
        target_network = network_name or DEFAULT_NETWORK
        valid_exit_codes = success_exit_codes if success_exit_codes is not None else [0]

        def decode(value) -> str:
            if not value:
                return ""
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        logger.info("🐳 [DOCKER Runner] Iniciando tarea en contenedor efímero.")
        logger.info(f"  ├─ Imagen: {image}")
        logger.info(f"  ├─ Red: {target_network}")
        logger.info(f"  ├─ Timeout: {timeout}s")
        logger.info(f"  ├─ Códigos de salida válidos: {valid_exit_codes}")
        logger.info(f"  └─ Comando: {command}")

        loop = asyncio.get_running_loop()

        def _run_docker_sync():
            container = None
            logs_output = []
            try:
                # 1. Creación del contenedor
                logger.debug(f"🛠️ [DOCKER Sync] Creando contenedor con la imagen '{image}'...")
                container = self.client.containers.create(
                    image=image,
                    command=command,
                    network=target_network,
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
                        "PYTHONUNBUFFERED": "1", # Forza salida de logs sin buffer para Python
                    },
                )
                logger.debug(f"📦 [DOCKER Sync] Contenedor creado. ID: {container.short_id}")

                # 2. Inyección de archivos temporales
                if input_files:
                    logger.debug(f"📂 [DOCKER Sync] Copiando {len(input_files)} archivo(s)...")
                    for filename, content in input_files.items():
                        target_dir = os.path.dirname(filename) or "/"
                        file_name_only = os.path.basename(filename)

                        archive = io.BytesIO()
                        with tarfile.open(fileobj=archive, mode="w") as tar:
                            data = content.encode("utf-8")
                            info = tarfile.TarInfo(name=file_name_only)
                            info.size = len(data)
                            tar.addfile(info, io.BytesIO(data))
                        archive.seek(0)

                        container.put_archive(target_dir, archive.read())
                        logger.debug(f"  └─ Archivo '{file_name_only}' copiado en '{target_dir}'")

                # 3. Arrancar contenedor
                logger.info(f"🚀 [DOCKER Sync] Arrancando contenedor {container.short_id}...")
                container.start()

                # 4. Lectura de Logs en TIEMPO REAL (Streaming)
                logger.info(f"📺 [DOCKER Stream] === INICIO DE LOGS ({container.short_id}) ===")
                
                # Obtener el generador de logs en tiempo real
                log_stream = container.logs(stream=True, follow=True, stdout=True, stderr=True)
                
                for chunk in log_stream:
                    line = decode(chunk).rstrip()
                    if line:
                        logger.info(f"  [{container.short_id}] {line}")
                        logs_output.append(line)

                logger.info(f"📺 [DOCKER Stream] === FIN DE LOGS ({container.short_id}) ===")

                # 5. Esperar el código de salida final
                result = container.wait()
                exit_code = result.get("StatusCode", 1)
                full_output = "\n".join(logs_output)

                logger.info(f"🏁 [DOCKER Sync] Contenedor {container.short_id} finalizó con Exit Code: {exit_code}")

                if exit_code in valid_exit_codes:
                    return {"status": "SUCCESS", "output": full_output}

                return {"status": "ERROR", "output": full_output or f"Código de salida: {exit_code}"}

            except Exception as e:
                logger.error(f"💥 [DOCKER Sync] Error en ejecución Docker: {e}", exc_info=True)
                return {"status": "FAILED", "output": "\n".join(logs_output) or str(e)}

            finally:
                if container is not None:
                    try:
                        logger.debug(f"🧹 [DOCKER Sync] Eliminando contenedor efímero {container.short_id}...")
                        container.remove(force=True)
                    except Exception as clean_err:
                        logger.debug(f"⚠️ [DOCKER Sync] No se pudo eliminar contenedor: {clean_err}")

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _run_docker_sync), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"⏰ [DOCKER Runner] Timeout excedido ({timeout}s) para {image}")
            return {
                "status": "TIMEOUT",
                "output": f"La herramienta superó el tiempo máximo permitido ({timeout}s).",
            }


docker_runner = EphemeralDockerRunner()