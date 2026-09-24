import argparse
import asyncio
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from mcp_server import mcp_server
from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY

DEFAULT_TARGET = "http://juice-shop-target:3000/"
STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg",
    ".jpg", ".map", ".mov", ".mp3", ".mp4", ".png", ".svg", ".tif",
    ".ttf", ".webm", ".webp", ".woff", ".woff2", ".zip",
}


def build_arguments(tool_name: str, target_url: str) -> dict:
    base_url = target_url.rstrip("/")
    if tool_name in {"sqlmap", "dalfox", "commix"}:
        return {"target_url": f"{base_url}/rest/products/search?q=test"}
    if tool_name == "ffuf":
        return {"target_url": f"{base_url}/FUZZ"}
    return {"target_url": target_url}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ejecuta las herramientas MCP registradas contra un objetivo autorizado."
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"URL interna del objetivo (por defecto: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--tools",
        help="Lista separada por comas; por defecto ejecuta todas las herramientas.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout en segundos para cada herramienta; sobrescribe el del registro.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Guarda la salida completa de cada herramienta en esta carpeta.",
    )
    parser.add_argument(
        "--full-output",
        action="store_true",
        help="Muestra la salida completa sin limitarla a 1000 caracteres.",
    )
    parser.add_argument(
        "--urls-only",
        action="store_true",
        help="Muestra solo las URLs descubiertas en la salida de la herramienta.",
    )
    parser.add_argument(
        "--include-assets",
        action="store_true",
        help="No filtra imágenes, fuentes, CSS, mapas ni otros recursos estáticos.",
    )
    return parser.parse_args()


def extract_urls(output: str, include_assets: bool) -> list[str]:
    urls = re.findall(r"https?://[^\s\"<>]+", output)
    unique_urls = list(dict.fromkeys(urls))
    if include_assets:
        return unique_urls

    filtered_urls = []
    for url in unique_urls:
        path = urlsplit(url.rstrip(".,);]" )).path.lower()
        if Path(path).suffix in STATIC_EXTENSIONS:
            continue
        filtered_urls.append(url)
    return filtered_urls


async def run_tool(tool_name: str, target_url: str, timeout: int | None) -> dict:
    arguments = build_arguments(tool_name, target_url)
    started = time.monotonic()
    result = await mcp_server.call_tool(
        tool_name, arguments, timeout_override=timeout
    )
    result["elapsed_seconds"] = round(time.monotonic() - started, 1)
    result["arguments"] = arguments
    return result


async def main() -> int:
    args = parse_args()
    selected_tools = (
        [item.strip() for item in args.tools.split(",") if item.strip()]
        if args.tools
        else list(MCP_SKILLS_REGISTRY)
    )
    unknown_tools = [name for name in selected_tools if name not in MCP_SKILLS_REGISTRY]
    if unknown_tools:
        print(f"Herramientas desconocidas: {', '.join(unknown_tools)}", file=sys.stderr)
        print(f"Disponibles: {', '.join(MCP_SKILLS_REGISTRY)}", file=sys.stderr)
        return 2

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Objetivo: {args.target}")
    print(f"Herramientas: {', '.join(selected_tools)}")
    print(f"Timeout: {args.timeout or 'registro'} segundos por herramienta")
    print()

    summary = []
    for tool_name in selected_tools:
        print(f"[{tool_name}] ejecutando...")
        result = await run_tool(tool_name, args.target, args.timeout)
        is_error = result.get("result", {}).get("isError", True)
        content = result.get("result", {}).get("content", [])
        output = "\n".join(
            item.get("text", "") for item in content if item.get("type") == "text"
        )
        status = "ERROR" if is_error else "OK"
        summary.append((tool_name, status, result["elapsed_seconds"]))
        print(f"[{tool_name}] {status} ({result['elapsed_seconds']} s)")
        if args.output_dir:
            output_file = args.output_dir / f"{tool_name}.json"
            output_file.write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"  salida: {output_file}")
        elif output:
            preview = output.strip()
            if args.urls_only:
                preview = "\n".join(extract_urls(preview, args.include_assets))
            if not args.full_output and not args.urls_only and len(preview) > 1000:
                preview = preview[:1000] + "..."
            print(f"  {preview}")
        print()

    print("Resumen")
    for tool_name, status, elapsed in summary:
        print(f"  {status:5} {tool_name:22} {elapsed:>7} s")
    return 1 if any(status == "ERROR" for _, status, _ in summary) else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
