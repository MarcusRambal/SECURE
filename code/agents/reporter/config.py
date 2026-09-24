import os

from llm_factory import get_int_env

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
REPORTER_QUEUE = "reporter_queue"
REPORTER_MAX_ENDPOINTS = get_int_env("REPORTER_MAX_ENDPOINTS", 15)
REPORTER_MAX_EVIDENCE_CHARS = get_int_env("REPORTER_MAX_EVIDENCE_CHARS", 200)
LOG_RPC_PAYLOADS = os.getenv("LOG_RPC_PAYLOADS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
