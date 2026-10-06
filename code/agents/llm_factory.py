import logging
import os
from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama

logger = logging.getLogger("llm-factory")

DEFAULT_MODEL = "qwen2.5:7b-instruct"

# Para 16 GB VRAM y un modelo 7B (Q4), 32k es el estándar recomendado.
# Puedes subir a 65536 en .env si tus orquestadores manejan prompts muy largos.
DEFAULT_NUM_CTX = 32768
MAX_NUM_CTX = 131072  # Soporte nativo máximo de Qwen 2.5

DEFAULT_MAX_TOKENS = {
    "orchestrator": 8192,
    "recon": 8192,
    "validate": 8192,
    "reporter": 8192,
}


def get_int_env(name: str, default: int) -> int:
    """Lee una opción numérica de las variables de entorno."""
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Valor no válido para %s; usando %s", name, default)
        return default


def get_num_ctx() -> int:
    """Devuelve el tamaño del contexto validando límites de seguridad."""
    requested = get_int_env("LLM_NUM_CTX", DEFAULT_NUM_CTX)

    if requested > MAX_NUM_CTX:
        logger.warning("LLM_NUM_CTX=%s excede el máximo soportado (%s); limitando.",requested,MAX_NUM_CTX,)
        return MAX_NUM_CTX
    if requested < 2048:
        logger.warning("LLM_NUM_CTX=%s es demasiado bajo; usando mínimo seguro de 2048.",requested,)
        return 2048

    return requested


def get_llm(agent_name: str) -> BaseChatModel:
    """Instancia el modelo local en Ollama optimizado para GPU de 16GB VRAM."""
    agent_upper = agent_name.upper()

    # Búsqueda jerárquica del modelo
    model_name = (os.getenv(f"MODEL_{agent_upper}")
        or os.getenv("OLLAMA_DEFAULT_MODEL")
        or DEFAULT_MODEL
    )

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

    # Tokens de salida
    default_tokens = DEFAULT_MAX_TOKENS.get(agent_name, 8192)
    max_tokens = get_int_env(f"MAX_TOKENS_{agent_upper}", default_tokens)

    num_ctx = get_num_ctx()

    # Mantiene el modelo en VRAM (ej. "30m" o "-1" para permanente).
    # Por defecto '30m' para evitar re-carga de GPU en pipelines activos.
    keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "30m")

    # Opciones de inferencia afinadas para Qwen 2.5
    ollama_options = {
        "num_predict": -1 if max_tokens <= 0 else max_tokens,
        "num_ctx": num_ctx,
        "top_p": 0.9,
        "top_k": 40,
        "repeat_penalty": 1.1,
    }

    logger.info(
        "[LOCAL OLLAMA] Agente '%s' -> Modelo '%s' en '%s' "
        "(max_tokens: %s, num_ctx: %s, keep_alive: %s)",
        agent_name,
        model_name,
        ollama_url,
        max_tokens,
        num_ctx,
        keep_alive,
    )

    return ChatOllama(
        base_url=ollama_url,
        model=model_name,
        temperature=0.1,
        keep_alive=keep_alive,
        options=ollama_options,
    )