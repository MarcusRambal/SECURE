import os
import logging
from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama

logger = logging.getLogger("llm-factory")

# Fallback en código si no se encuentra ninguna variable de entorno
DEFAULT_MODEL = "qwen2.5:7b-instruct"

# Contexto fijo para ejecuciones secuenciales (16k tokens)
FIXED_NUM_CTX = 16384 

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

    # 4. Opciones del motor Ollama
    ollama_options = {
        "num_predict": -1 if max_tokens <= 0 else max_tokens,
        "num_ctx": FIXED_NUM_CTX,  # Mantiene el contexto amplio e independiente
        "num_keep": 0,             # Fuerza la desasignación de tokens en caché al cambiar de agente
    }

    logger.info(
        f"🏠 [LOCAL OLLAMA] Agente '{agent_name}' → Modelo '{model_name}' "
        f"en '{ollama_url}' (max_tokens_salida: {max_tokens}, num_ctx_entrada: {FIXED_NUM_CTX})"
    )

    return ChatOllama(
        base_url=ollama_url,
        model=model_name,
        temperature=0.1,
        num_ctx=FIXED_NUM_CTX,
        options=ollama_options,
    )