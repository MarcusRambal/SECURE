"""
Utilidades compartidas por todos los adaptadores (handlers).

Centralizar aquí evita duplicar lógica en cada handler y permite
cambiar el comportamiento (por ejemplo, agregar extensiones estáticas)
en un solo lugar.
"""

from pathlib import Path
from urllib.parse import urlsplit


# Extensiones de recursos que NO tiene sentido atacar con herramientas de pentesting.
STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2",
    ".ttf", ".ico", ".map", ".gif", ".webp", ".mp4", ".mp3", ".pdf",
    ".zip", ".tar", ".gz", ".rar", ".7z",
}


def is_static_asset(url: str) -> bool:
    """
    Devuelve True si la URL apunta a un recurso estático que las
    herramientas de ataque deben ignorar.
    """
    if not url:
        return False
    try:
        path = urlsplit(url).path.lower()
        return Path(path).suffix in STATIC_EXTENSIONS
    except Exception:
        return False