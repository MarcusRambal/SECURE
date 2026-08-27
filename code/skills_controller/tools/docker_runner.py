import docker
import logging

logger = logging.getLogger(__name__)

def run_ephemeral_container(image: str, command: str, network: str = "sec-net") -> str:
    """
    Ejecuta un contenedor efímero con la imagen y comando especificados
    conectado a la red `sec-net` y retorna su salida estándar.
    """
    client = docker.from_env()
    
    # Asegurar que la imagen existe localmente, si no, descargarla
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        logger.info(f"Descargando imagen Docker: {image}...")
        client.images.pull(image)

    logger.info(f"Ejecutando herramienta efímera [{image}] con comando: {command}")
    
    try:
        # Se ejecuta el contenedor y se destruye automáticamente al terminar (auto_remove=True)
        logs = client.containers.run(
            image=image,
            command=command,
            network=network,
            remove=True,
            stdout=True,
            stderr=True
        )
        return logs.decode("utf-8", errors="replace")
    except docker.errors.ContainerError as e:
        logger.error(f"Error durante la ejecución del contenedor: {e}")
        return f"Error en la ejecución de la herramienta: {e.stderr.decode('utf-8', errors='replace')}"
    except Exception as e:
        logger.error(f"Error inesperado con Docker: {e}")
        return f"Error de sistema al invocar Docker: {str(e)}"