import os

from llm_factory import get_int_env

# worker.py
RABBITMQ_URL = os.getenv("RABBITMQ_URL")
RECON_QUEUE = "recon_queue"


# mcp_skills.py
SKILLS_QUEUE = "skills_queue"

MCP_OUTPUT_MAX_CHARS = get_int_env("MCP_OUTPUT_MAX_CHARS", 1500)