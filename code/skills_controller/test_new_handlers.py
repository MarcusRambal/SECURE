import sys
from pathlib import Path

current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY

def test_mcp_integration():
    print("🧪 Validando integración de MCP Skills Registry...")
    
    for tool_name in ["testssl", "hydra"]:
        print(f"\n🔍 Verificando herramienta: '{tool_name}'")
        assert tool_name in MCP_SKILLS_REGISTRY, f"{tool_name} no está en MCP_SKILLS_REGISTRY"
        
        tool_config = MCP_SKILLS_REGISTRY[tool_name]
        
        # 1. Validar que la clave sea 'prepare_args' y sea ejecutable
        assert "prepare_args" in tool_config, f"Falta 'prepare_args' en {tool_name}"
        assert callable(tool_config["prepare_args"]), f"'prepare_args' no es una función en {tool_name}"
        
        # 2. Validar que mcp_schema sea un DICT y tenga inputSchema
        schema = tool_config["mcp_schema"]
        assert isinstance(schema, dict), f"'mcp_schema' en {tool_name} debe ser dict, no {type(schema)}"
        assert "inputSchema" in schema, f"Falta 'inputSchema' dentro de 'mcp_schema' en {tool_name}"
        
        # 3. Probar ejecución de prepare_args
        if tool_name == "testssl":
            test_input = {"target_url": "http://juice-shop-target:3000"}
        else:
            test_input = {"target": "juice-shop-target", "form_path": "/rest/user/login"}
            
        args_out, files_out = tool_config["prepare_args"](test_input)
        assert isinstance(args_out, dict), "prepare_args debe retornar un dict de args como primer elemento"
        assert "args" in args_out, "El dict de salida debe contener la clave 'args'"
        
        print(f"  ✅ Schema válido (Dict con inputSchema)")
        print(f"  ✅ Handler 'prepare_args' ejecutable correctamente")
        print(f"  ✅ Comando generado: {args_out['args']}")

    print("\n🎉 ¡Todas las verificaciones del servidor MCP pasaron con éxito!")

if __name__ == "__main__":
    test_mcp_integration()