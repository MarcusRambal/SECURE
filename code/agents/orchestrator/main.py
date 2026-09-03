import os
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

TARGET_URL = os.getenv("TARGET_URL", "http://webgoat:8080/WebGoat")

def main():
    llm = ChatGroq(
        model_name="qwen/qwen3.8-27b",
        groq_api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1
    )

    tools = []

    system_message = SystemMessage(
        content=(
            "Eres Orchestrator, un agente de auditoría de seguridad en un laboratorio controlado.\n"
            "Esta ejecución es una prueba sin herramientas: no tienes navegador, HTTP client ni acceso a la web.\n"
            "No afirmes que has visitado una URL ni inventes el contenido de una página.\n"
            "Si te piden navegar, indica claramente que no puedes hacerlo sin una herramienta.\n"
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
            HumanMessage(content=(
                f"Intenta navegar a '{TARGET_URL}/start.mvc#lesson/SqlInjection.lesson' y analiza la lección. "
                "Devuelve un JSON con 'navigation_possible', 'lesson_title', "
                "'lesson_description', 'lesson_steps' y 'lesson_hints'."
            ))
        ]
    }

    for event in agent_executor.stream(initial_input, config={"recursion_limit": 15}):
        for value in event.values():
            last_msg = value["messages"][-1]
            print(f"\n[{last_msg.type.upper()}]: {last_msg.content}")

if __name__ == "__main__":
    main()