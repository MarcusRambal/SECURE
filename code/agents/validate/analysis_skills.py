import json
from collections import defaultdict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _observed_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def _safe_endpoint(endpoint: str) -> str:
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return "[invalid-url]"

    safe_netloc = parts.netloc.rsplit("@", 1)[-1]
    safe_query = urlencode(
        [
            (name, "[REDACTED]")
            for name, _ in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, safe_netloc, parts.path, safe_query, ""))


def _body_representation(request: dict, body: object) -> str:
    headers = request.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    content_type = next(
        (
            str(value).split(";", 1)[0].strip().casefold()
            for name, value in headers.items()
            if isinstance(name, str) and name.casefold() == "content-type"
        ),
        "",
    )
    if content_type:
        return content_type
    if isinstance(body, (dict, list)):
        return "structured_capture"
    if body is None:
        return "absent"
    return "unlabeled_body"


def _flatten_observed_fields(
    value: object,
    location: str,
    prefix: str = "",
) -> list[dict]:
    observed_type = _observed_type(value)
    fields = []
    if isinstance(value, dict):
        if prefix:
            fields.append(
                {"path": prefix, "location": location, "observed_type": "object"}
            )
        for name, child in value.items():
            child_path = f"{prefix}.{name}" if prefix else str(name)
            fields.extend(
                _flatten_observed_fields(child, location, child_path)
            )
    elif isinstance(value, list):
        path = prefix or "$body"
        fields.append(
            {
                "path": path,
                "location": location,
                "observed_type": "array",
                "observed_item_types": sorted(
                    {_observed_type(item) for item in value}
                ),
                "observed_item_count": len(value),
            }
        )
        for item in value:
            if isinstance(item, (dict, list)):
                fields.extend(
                    _flatten_observed_fields(item, location, f"{path}[]")
                )
    else:
        path = prefix or "$body"
        fields.append(
            {
                "path": path,
                "location": location,
                "observed_type": observed_type,
            }
        )
    return fields


def _captured_body_fields(request: dict, body: object) -> list[dict]:
    if body is None:
        return []

    headers = request.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    content_type = next(
        (
            str(value).split(";", 1)[0].strip().casefold()
            for name, value in headers.items()
            if isinstance(name, str) and name.casefold() == "content-type"
        ),
        "",
    )
    if isinstance(body, str):
        if content_type == "application/x-www-form-urlencoded":
            return [
                {
                    "path": name,
                    "location": "form_body",
                    "observed_type": "string",
                }
                for name, _ in parse_qsl(body, keep_blank_values=True)
            ]
        if content_type == "application/json":
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                return [
                    {
                        "path": "$body",
                        "location": "body",
                        "observed_type": "string",
                    }
                ]
            return _flatten_observed_fields(parsed_body, "json_body")
        return [
            {
                "path": "$body",
                "location": "body",
                "observed_type": "string",
            }
        ]

    return _flatten_observed_fields(body, "body")


def analyze_validation_targets(targets: list[dict]) -> list[dict]:
    """Report only types and structures directly present in captured requests."""
    analyses = []
    observations_by_endpoint: dict[
        tuple[str, str, str, str], set[str]
    ] = defaultdict(set)

    for target in targets:
        if not isinstance(target, dict):
            continue

        request = target.get("request")
        request = request if isinstance(request, dict) else {}
        raw_endpoint = str(request.get("url") or target.get("url") or "")
        method = str(
            request.get("method") or target.get("method") or "GET"
        ).upper()
        body = request.get("body")
        endpoint = _safe_endpoint(raw_endpoint)

        try:
            endpoint_path = urlsplit(endpoint).path
            query_pairs = parse_qsl(
                urlsplit(raw_endpoint).query,
                keep_blank_values=True,
            )
        except ValueError:
            endpoint_path = ""
            query_pairs = []

        fields = _captured_body_fields(request, body)
        fields.extend(
            {
                "path": name,
                "location": "query",
                "observed_type": "string",
            }
            for name, _ in query_pairs
        )
        analysis = {
            "target_id": target.get("target_id"),
            "request_id": target.get("request_id"),
            "endpoint": endpoint,
            "method": method,
            "body_representation": _body_representation(request, body),
            "observed_fields": fields,
        }
        analyses.append(analysis)

        for field in fields:
            key = (
                method,
                endpoint_path,
                field["location"],
                field["path"],
            )
            observations_by_endpoint[key].add(field["observed_type"])

    for analysis in analyses:
        endpoint_path = urlsplit(analysis["endpoint"]).path
        for field in analysis["observed_fields"]:
            key = (
                analysis["method"],
                endpoint_path,
                field["location"],
                field["path"],
            )
            field["observed_types_for_endpoint"] = sorted(
                observations_by_endpoint[key]
            )

    return analyses
