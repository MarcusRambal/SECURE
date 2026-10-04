import json
import urllib.parse


def _serialize_body(body: object, content_type: str) -> str:
    if body is None:
        return ""
    if isinstance(body, (dict, list)):
        if "application/x-www-form-urlencoded" in content_type.lower():
            return urllib.parse.urlencode(body, doseq=True)
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return str(body)

def build_raw_request(request: dict) -> str:
    """Serializa una petición estructurada al formato HTTP raw."""
    method = request.get("method", "GET").upper()
    url = request.get("url", "")
    parsed_url = urllib.parse.urlsplit(url)
    request_target = parsed_url.path or "/"
    if parsed_url.query:
        request_target += f"?{parsed_url.query}"
    
    headers = dict(request.get("headers", {}))
    content_type = next(
        (value for name, value in headers.items() if name.lower() == "content-type"), ""
    )
    body = _serialize_body(request.get("body"), content_type)
    lines = [f"{method} {request_target} HTTP/1.1"]

    host_header = next(
        (value for name, value in headers.items() if name.lower() == "host"),
        parsed_url.netloc,
    )
    if host_header:
        lines.append(f"Host: {host_header}")

    for name, value in headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")

    if body and not any(name.lower() == "content-length" for name in headers):
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")

    lines.append("")
    lines.append(body)
    return "\r\n".join(lines)


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