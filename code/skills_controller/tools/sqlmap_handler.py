import urllib.parse

def build_raw_request(request: dict) -> str:
    """Serializa una petición estructurada al formato HTTP raw."""
    method = request.get("method", "GET").upper()
    url = request.get("url", "")
    parsed_url = urllib.parse.urlsplit(url)
    request_target = parsed_url.path or "/"
    if parsed_url.query:
        request_target += f"?{parsed_url.query}"
    
    headers = request.get("headers", {})
    lines = [f"{method} {request_target} HTTP/1.1"]
    
    if parsed_url.netloc and not any(name.lower() == "host" for name in headers):
        lines.append(f"Host: {parsed_url.netloc}")
        
    for name, value in headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
            
    lines.append("")
    lines.append(str(request.get("body", "") or ""))
    return "\n".join(lines)


def handle_sqlmap_args(arguments: dict) -> tuple[dict, dict]:
    """Prepara el archivo HTTP temporal que SQLMap consume con ``-r``."""
    args = dict(arguments)
    input_files = {}

    request_data = args.get("request")
    if request_data:
        file_path = args.get("file_path", "/tmp/secure-request.txt")
        args["file_path"] = file_path
        input_files[file_path] = build_raw_request(request_data)

    return args, input_files