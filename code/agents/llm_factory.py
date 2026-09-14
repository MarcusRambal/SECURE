import os
import logging
from langchain_groq import ChatGroq

logger = logging.getLogger("llm-factory")

# Presupuesto máximo por agente para no agotar los 8,000 TPM del tier gratuito.
DEFAULT_MAX_TOKENS = {
    "orchestrator": 300,
    "recon": 1200,  
    "validate": 1200,  
    "reporter": 1800,  
}


def get_llm(agent_name: str) -> ChatGroq:
    """
    Instancia y retorna un objeto ChatGroq configurado dinámicamente según:
      - MODEL_<AGENT_NAME>          (formato: "groq:<nombre-modelo>")
      - GROQ_ACCOUNT_<AGENT_NAME>   ("friend" o "mine", default: "friend")
      - MAX_TOKENS_<AGENT_NAME>     (opcional, override del default)
    """
    agent_upper = agent_name.upper()

    # 1. Determinar modelo
    model_spec = os.getenv(
        f"MODEL_{agent_upper}",
        "groq:openai/gpt-oss-20b",
    )
    if not model_spec.startswith("groq:"):
        raise ValueError(
            f"Formato no soportado en MODEL_{agent_upper}: '{model_spec}'. "
            "Debe comenzar con 'groq:'."
        )
    model_name = model_spec.split("groq:", 1)[1]

    # 2. Determinar cuenta y API key
    account = os.getenv(f"GROQ_ACCOUNT_{agent_upper}", "friend").lower()
    if account == "mine":
        api_key = os.getenv("GROQ_API_KEY_MINE")
        if not api_key:
            raise RuntimeError(f"GROQ_API_KEY_MINE no configurada para el agente '{agent_name}'.")
    else:
        api_key = os.getenv("GROQ_API_KEY_FRIEND")
        if not api_key:
            raise RuntimeError(f"GROQ_API_KEY_FRIEND no configurada para el agente '{agent_name}'.")

    # 3. Determinar max_tokens (override por env, o default por agente)
    default_tokens = DEFAULT_MAX_TOKENS.get(agent_name, 900)
    max_tokens = int(os.getenv(f"MAX_TOKENS_{agent_upper}", default_tokens))

    logger.info(
        f"🤖 Agente '{agent_name}' → modelo '{model_name}' "
        f"(cuenta: {account}, max_tokens: {max_tokens})"
    )

    return ChatGroq(
        model_name=model_name,
        groq_api_key=api_key,
        temperature=0.1,
        max_tokens=max_tokens,
    )
