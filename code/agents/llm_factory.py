import os
import logging
from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama

logger = logging.getLogger("llm-factory")

# Fallback en código si no se encuentra ninguna variable de entorno
DEFAULT_MODEL = "qwen2.5:7b-instruct"

# Contexto compartido por agente. 16k es el valor conservador; 32k se puede
# activar desde el entorno después de comprobar el consumo real de VRAM.
DEFAULT_NUM_CTX = 16384
MAX_NUM_CTX = 32768

DEFAULT_MAX_TOKENS = {
    "orchestrator": 500,
    "recon": 2000,
    "validate": 2000,
    "reporter": 4000,
}


def get_int_env(name: str, default: int) -> int:
    """Lee una opción numérica de las variables de entorno."""
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Valor no válido para %s; usando %s", name, default)
        return default


def get_num_ctx() -> int:
    """Devuelve un contexto soportado y evita configuraciones accidentales."""
    requested = get_int_env("LLM_NUM_CTX", DEFAULT_NUM_CTX)
    if requested not in (DEFAULT_NUM_CTX, MAX_NUM_CTX):
        logger.warning(
            "LLM_NUM_CTX=%s no está soportado; usando %s (válidos: %s, %s)",
            requested,
            DEFAULT_NUM_CTX,
            DEFAULT_NUM_CTX,
            MAX_NUM_CTX,
        )
        return DEFAULT_NUM_CTX
    return requested


def get_llm(agent_name: str) -> BaseChatModel:
    """
    Instancia el modelo local en Ollama mapeando las variables de entorno especificadas.
    """
    agent_upper = agent_name.upper()

    # 1. Búsqueda jerárquica del modelo:
    # Primero busca MODEL_ORCHESTRATOR / MODEL_RECON / etc.
    # Luego OLLAMA_DEFAULT_MODEL, y como último recurso DEFAULT_MODEL
    model_name = (
        os.getenv(f"MODEL_{agent_upper}")
        or os.getenv("OLLAMA_DEFAULT_MODEL")
        or DEFAULT_MODEL
    )

    # 2. Lee OLLAMA_BASE_URL (http://host.docker.internal:11434 por defecto si viene de tu env)
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

    # 3. Límite de tokens de respuesta por agente (lee MAX_TOKENS_ORCHESTRATOR, etc. si existen)
    default_tokens = DEFAULT_MAX_TOKENS.get(agent_name, 1500)
    max_tokens = get_int_env(f"MAX_TOKENS_{agent_upper}", default_tokens)

    num_ctx = get_num_ctx()
    keep_alive = get_int_env("OLLAMA_KEEP_ALIVE", 0)

    # 4. Opciones del motor Ollama
    ollama_options = {
        "num_predict": -1 if max_tokens <= 0 else max_tokens,
        "num_ctx": num_ctx,
        "num_keep": 0,
    }

    logger.info(
        "[LOCAL OLLAMA] Agente '%s' -> Modelo '%s' en '%s' "
        "(max_tokens_salida: %s, num_ctx: %s, keep_alive: %ss)",
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
        num_ctx=num_ctx,
        keep_alive=keep_alive,
        options=ollama_options,
    )
