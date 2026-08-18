# toolsLibrary/registry.py

from typing import Dict, Any, Callable, List

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, description: str, parameters: Dict[str, Any]):
        """Decorador para registrar herramientas de forma limpia."""
        def decorator(func: Callable):
            self._tools[name] = {
                "name": name,
                "description": description,
                "parameters": parameters,
                "handler": func
            }
            return func
        return decorator

    def get_schema_list(self) -> List[Dict[str, Any]]:
        """Retorna la lista de schemas que el agente/LLM necesita ver."""
        return [
            {
                "name": data["name"],
                "description": data["description"],
                "parameters": data["parameters"]
            }
            for data in self._tools.values()
        ]

    def execute(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta el handler de la herramienta solicitada."""
        if name not in self._tools:
            raise KeyError(f"Herramienta '{name}' no registrada.")
        return self._tools[name]["handler"](arguments)

# Instancia global del registro
registry = ToolRegistry()