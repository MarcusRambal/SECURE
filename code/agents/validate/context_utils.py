from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def sanitize_endpoint_for_context(endpoint: str) -> str:
    """Redact user info and query values before persisting or displaying a URL."""
    try:
        parts = urlsplit(endpoint)
        query = urlencode(
            [
                (name, "[REDACTED]")
                for name, _ in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
    except ValueError:
        return "[invalid-url]"

    return urlunsplit(
        (parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, query, "")
    )
