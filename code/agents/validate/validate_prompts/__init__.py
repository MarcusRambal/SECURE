from collections.abc import Callable

from attack_types import normalize_attack_type
from .common import build_prompt as build_common_prompt
from .crypto_inspector import build_prompt as build_crypto_prompt
from .sqli import build_prompt as build_sqli_prompt
from .xss import build_prompt as build_xss_prompt

PromptBuilder = Callable[[str], str]

GENERIC_ATTACK_INSTRUCTIONS = (
    "Analiza exclusivamente la evidencia disponible y determina si la "
    "vulnerabilidad debe clasificarse como confirmada o no confirmada."
)

PROMPT_BUILDERS: dict[str, PromptBuilder] = {
    "sqli": build_sqli_prompt,
    "xss": build_xss_prompt,
    "crypto_inspector": build_crypto_prompt,
}


def get_system_prompt(attack_type_filter: str) -> str:
    """Select the attack-specific prompt while keeping a generic fallback."""
    prompt_builder = PROMPT_BUILDERS.get(normalize_attack_type(attack_type_filter))
    if prompt_builder is None:
        return build_common_prompt(attack_type_filter, GENERIC_ATTACK_INSTRUCTIONS)
    return prompt_builder(attack_type_filter)
