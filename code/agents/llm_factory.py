import os
import logging
from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama

logger = logging.getLogger("llm-factory")

DEFAULT_MODEL = "qwen2.5:7b-instruct"

DEFAULT_MAX_TOKENS = {
    "orchestrator": 300,
    "recon": 1200,
    "validate": 1200,
    "reporter": 1800,
}


def get_int_env(name: str, default: int) -> int:
    """Lee una opción numérica y conserva el valor por defecto si no es válida."""
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Valor no válido para %s; usando %s", name, default)
        return default

def get_llm(agent_name: str) -> BaseChatModel:
    """
    Instancia y retorna un modelo local ejecutable en Ollama.
    """
    agent_upper = agent_name.upper()

    # Permite configurar un modelo por agente o compartir uno para todos.
    model_name = (
        os.getenv(f"MODEL_{agent_upper}")
        or os.getenv("OLLAMA_MODEL")
        or os.getenv("QWEN_MODEL")
        or DEFAULT_MODEL
    )

    # 2. Configurar la URL de conexión a Ollama
    # Si usas Docker en Linux: http://172.17.0.1:11434 o IP de la red Docker.
    # Si usas Docker en Windows/Mac: http://host.docker.internal:11434
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # 3. Determinar el límite de tokens generados
    default_tokens = DEFAULT_MAX_TOKENS.get(agent_name, 900)
    max_tokens = get_int_env(f"MAX_TOKENS_{agent_upper}", default_tokens)
    ollama_options = {"num_predict": -1 if max_tokens <= 0 else max_tokens}
    num_ctx = get_int_env("OLLAMA_NUM_CTX", 0)
    if num_ctx > 0:
        ollama_options["num_ctx"] = num_ctx

    logger.info(
        f"🏠 [LOCAL OLLAMA] Agente '{agent_name}' → Modelo '{model_name}' "
        f"en '{ollama_url}' (max_tokens: {max_tokens})"
    )

    return ChatOllama(
        base_url=ollama_url,
        model=model_name,
        temperature=0.1,      # Baja temperatura para consistencia en respuestas y tool calling
        **ollama_options,
    )