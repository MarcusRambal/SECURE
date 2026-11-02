from urllib.parse import parse_qsl, urlsplit


def is_weak_page_target(url: str) -> bool:
    """Return whether URL is the exact root allowed for the weak-page lab."""
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "http"
            and parsed.hostname == "weak-page"
            and parsed.port == 3009
            and not parsed.username
            and not parsed.password
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def is_weak_page_origin(url: str) -> bool:
    """Return whether URL belongs to the exact weak-page lab origin."""
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "http"
            and parsed.hostname == "weak-page"
            and parsed.port == 3009
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        return False


def classify_weak_page_xss_surface(url: str, request: dict) -> str | None:
    """Classify only the two XSS challenges currently defined by weak_page."""
    if not is_weak_page_origin(url):
        return None

    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    method = str(request.get("method") or "GET").upper()
    path = parsed.path.rstrip("/") or "/"
    if method == "GET" and path == "/api/products":
        if any(name.casefold() == "q" for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )):
            return "dom_reflected_search"

    body = request.get("body")
    if method == "POST" and path == "/api/contact":
        if isinstance(body, dict) and any(
            name in body for name in ("name", "email", "subject", "message")
        ):
            return "stored_contact"
        if isinstance(body, str) and body.strip():
            return "stored_contact"
    return None
