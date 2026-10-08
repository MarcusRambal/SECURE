import os

# worker.py
RABBITMQ_URL = os.getenv("RABBITMQ_URL")
RECON_QUEUE = "recon_queue"

# mcp_skills.py
SKILLS_QUEUE = "skills_queue"
