SQLI_ATTACK_TYPE = "sqli"


def normalize_attack_type(attack_type_filter: str) -> str:
    return attack_type_filter.casefold()


def is_sqli_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == SQLI_ATTACK_TYPE