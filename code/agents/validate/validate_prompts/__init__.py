from collections.abc import Callable

from attack_types import normalize_attack_type
from .sqli import build_prompt as build_sqli_prompt

PromptBuilder = Callable[[str], str]

PROMPT_BUILDERS: dict[str, PromptBuilder] = {
    "sqli": build_sqli_prompt,
}


def get_system_prompt(attack_type_filter: str) -> str:
    """Select the attack-specific prompt while keeping a generic fallback."""
    prompt_builder = PROMPT_BUILDERS.get(normalize_attack_type(attack_type_filter))
    return prompt_builder(attack_type_filter)
