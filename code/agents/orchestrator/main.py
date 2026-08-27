import os
from langchain_groq import ChatGroq
from auth import ensure_webgoat_session
from tools import navigate_and_inspect, test_sql_payload  # Importación actualizada
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

TARGET_URL = os.getenv("TARGET_URL", "http://webgoat:8080/WebGoat")

def main():
    ensure_webgoat_session(target_url=TARGET_URL)

    # Llama-3.1-70b en Groq procesará y creará payloads SQL sin bloquearse
    llm = ChatGroq(
        model_name="qwen/qwen3.8-27b",
        groq_api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1
    )

    tools = [navigate_and_inspect, test_sql_payload]

    system_message = SystemMessage(
        content=(
            "Eres Orchestrator, un agente de auditoría de seguridad en entornos de laboratorio controlados.\n"
            "Tu objetivo es resolver el laboratorio de SQL Injection en WebGoat probando payloads directamente.\n"
            "1. Llama a `navigate_and_inspect` para inspeccionar la estructura de los campos de la página.\n"
            "2. Analiza qué input es vulnerable y diseña el payload de inyección SQL adecuado.\n"
            "3. Usa `test_sql_payload` enviando el selector del campo y la cadena del payload exacta hasta completar el laboratorio."
        )
    )

    agent_executor = create_react_agent(
        model=llm,
        tools=tools,
        prompt=system_message
    )

    print("[ORCHESTRATOR] Iniciando agente de auditoría con Groq...")

    initial_input = {
        "messages": [
            HumanMessage(content="Navega a 'start.mvc#lesson/SqlInjection.lesson', analiza la lección y envía el payload necesario para resolver el laboratorio.")
        ]
    }

    for event in agent_executor.stream(initial_input, config={"recursion_limit": 15}):
        for value in event.values():
            last_msg = value["messages"][-1]
            print(f"\n[{last_msg.type.upper()}]: {last_msg.content}")

if __name__ == "__main__":
    main()