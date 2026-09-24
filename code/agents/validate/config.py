import os

from llm_factory import get_int_env

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
SKILLS_QUEUE = "skills_queue"
VALIDATE_QUEUE = "validate_queue"

MAX_ENDPOINTS_TO_VALIDATE = get_int_env("MAX_ENDPOINTS_TO_VALIDATE", 10)
LOG_RPC_PAYLOADS = os.getenv("LOG_RPC_PAYLOADS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

ALLOWED_ATTACK_TYPES = {"full", "sql_injection", "xss", "command_injection"}
TOOL_MAP = {
    "full": ["sqlmap", "dalfox", "commix", "nuclei", "ffuf"],
    "sql_injection": ["sqlmap"],
    "xss": ["dalfox"],
    "command_injection": ["commix"],
}

TOOL_COMMAND_TEMPLATES = {
    "sqlmap": 'sqlmap -r "{file_path}" --batch --level=5 --risk=3 --ignore-stdin --ignore-code=401 --no-escape',
    "dalfox": 'dalfox url "{target_url}" --silence',
    "commix": 'commix --url="{target_url}" --batch',
    "nuclei": 'nuclei -u "{target_url}" -tags {tags} -silent -nc',
    "ffuf": 'ffuf -u "{target_url}" -w /wordlists/common.txt -s',
}
