"""Interaccion acotada de endpoints descubiertos por crawler.py."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from playwright.sync_api import Page, Request, sync_playwright

try:
	from .crawler import _authenticate_if_configured, _authentication_state_path, analyze_website
except ImportError:
	from crawler import _authenticate_if_configured, _authentication_state_path, analyze_website


CRAWLER_REPORT_DEFAULT = Path(__file__).with_name("crawler_report.json")
DEEP_REPORT_DEFAULT = Path(__file__).with_name("deep_crawler_report.json")
DEFAULT_TIMEOUT_MS = 30_000
MAX_INTERACTIONS_PER_ENDPOINT = 12
MAX_FORMS_PER_ENDPOINT = 8
INTERACTION_SETTLE_MS = 500

DESTRUCTIVE_TERMS = (
	"logout", "log out", "sign out", "delete", "remove", "destroy", "cancel",
	"cerrar sesion", "eliminar", "borrar", "cancelar", "checkout", "purchase", "pay",
)
SAFE_BUTTON_TERMS = ("search", "filter", "submit", "login", "log in", "send", "register", "buscar", "filtrar", "enviar", "iniciar")
IRRELEVANT_HEADERS = {
	"accept-encoding", "accept-language", "connection", "content-length", "cookie",
	"origin", "pragma", "cache-control", "authorization", "proxy-authorization",
	"x-api-key",
}
IRRELEVANT_RESPONSE_HEADERS = {
	"connection", "content-length", "date", "keep-alive", "set-cookie",
	"transfer-encoding",
}


def _load_endpoints(report_path: Path) -> tuple[str, list[str]]:
	report = json.loads(report_path.read_text(encoding="utf-8"))
	return _endpoints_from_report(report)


def _endpoints_from_report(report: dict[str, Any]) -> tuple[str, list[str]]:
	target_url = report.get("target", {}).get("requested_url", "")
	endpoint_urls = []
	for endpoint in report.get("navigation", {}).get("endpoints", []):
		for url in endpoint.get("sample_urls", []):
			if url and url not in endpoint_urls:
				endpoint_urls.append(url)
	if not target_url:
		raise ValueError("El informe no contiene target.requested_url.")
	return target_url, endpoint_urls


def _filtered_headers(headers: dict[str, str]) -> dict[str, str]:
	"""Elimina cabeceras repetidas, de navegador o que puedan contener secretos."""
	filtered = {}
	for name, value in headers.items():
		normalized_name = name.lower()
		if normalized_name in IRRELEVANT_HEADERS or normalized_name.startswith("sec-"):
			continue
		filtered[normalized_name] = value
	return dict(sorted(filtered.items()))


def _request_record(request: Request) -> dict[str, Any]:
	safe_url = _redact_url(request.url)
	parsed_url = urlsplit(safe_url)
	path = parsed_url.path or "/"
	if parsed_url.query:
		path = f"{path}?{parsed_url.query}"
	headers = _filtered_headers(dict(request.headers))
	headers.setdefault("host", parsed_url.netloc)
	body = _redact_request_body(request.post_data, headers.get("content-type", ""))
	return {
		"request_line": f"{request.method} {path} HTTP/1.1",
		"method": request.method,
		"url": safe_url,
		"path": path,
		"resource_type": request.resource_type,
		"headers": headers,
		"body": body,
		"response": None,
	}


def _redact_request_body(body: str | None, content_type: str) -> Any:
	"""Mantiene el body estructurado, ocultando contraseñas, tokens y secretos."""
	if not body:
		return None

	def redact(value: Any) -> Any:
		if isinstance(value, dict):
			return {
				key: "[REDACTED]" if re.search(r"password|passwd|token|secret|api[_-]?key|authorization", key, re.IGNORECASE) else redact(item)
				for key, item in value.items()
			}
		if isinstance(value, list):
			return [redact(item) for item in value]
		return value

	if "json" in content_type.lower():
		try:
			return redact(json.loads(body))
		except json.JSONDecodeError:
			return body
	if "application/x-www-form-urlencoded" in content_type.lower():
		return {
			key: "[REDACTED]" if re.search(r"password|passwd|token|secret|api[_-]?key", key, re.IGNORECASE) else value
			for key, value in parse_qsl(body, keep_blank_values=True)
		}
	return re.sub(
		r"(?i)(password|passwd|token|secret|api[_-]?key)=([^&\\s]+)",
		r"\1=[REDACTED]",
		body,
	)


def _redact_url(url: str) -> str:
	parsed = urlsplit(url)
	query = urlencode(
		[
			(key, "[REDACTED]" if re.search(r"password|passwd|token|secret|api[_-]?key|code", key, re.IGNORECASE) else value)
			for key, value in parse_qsl(parsed.query, keep_blank_values=True)
	]
	)
	return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _request_key(record: dict[str, Any]) -> tuple[str, str, str]:
	return record["method"], record["url"], json.dumps(record["body"], sort_keys=True, ensure_ascii=False)


def _is_destructive(candidate: dict[str, Any]) -> bool:
	text = " ".join(
		str(candidate.get(key, ""))
		for key in ("text", "name", "id", "action", "value")
	).lower()
	return any(term in text for term in DESTRUCTIVE_TERMS)


def _is_safe_button(candidate: dict[str, Any]) -> bool:
	text = candidate.get("text", "").lower()
	return any(term in text for term in SAFE_BUTTON_TERMS)


def _form_pattern(candidate: dict[str, Any]) -> str:
	form = candidate.get("form") or {}
	fields = ",".join(f"{item['name']}:{item['type']}" for item in form.get("fields", []))
	return f"{form.get('method', 'GET')}|{form.get('action', '')}|{fields}"


def _extract_candidates(page: Page) -> list[dict[str, Any]]:
	"""Marca controles de la vista actual para interactuar con ellos sin usar selectores fragiles."""
	return page.evaluate(
		"""() => {
			const controls = Array.from(document.querySelectorAll(
				'input:not([type="hidden"]):not([type="password"]), textarea, button, [role="button"]'
			));
			return controls.filter(element => !element.disabled && !element.readOnly).map((element, index) => {
				const form = element.closest('form');
				const fields = form ? Array.from(form.querySelectorAll('input, textarea, select'))
					.filter(field => field.type !== 'hidden' && field.type !== 'password')
					.map(field => ({name: field.name || field.id || '', type: field.type || field.tagName.toLowerCase()})) : [];
				const marker = `deep-candidate-${index}`;
				element.setAttribute('data-deep-candidate', marker);
				return {
					marker,
					tag: element.tagName.toLowerCase(),
					type: (element.type || '').toLowerCase(),
					text: (element.innerText || element.value || element.getAttribute('aria-label') || '').trim(),
					name: element.name || '',
					id: element.id || '',
					value: element.value || '',
					action: form?.action || '',
					form: form ? {
						action: form.action || '',
						method: (form.method || 'GET').toUpperCase(),
						fields
					} : null
				};
			});
		}"""
	)


def _interact(page: Page, candidate: dict[str, Any]) -> bool:
	locator = page.locator(f'[data-deep-candidate="{candidate["marker"]}"]')
	if candidate["tag"] in {"input", "textarea"} and candidate["type"] not in {"submit", "button", "file", "checkbox", "radio"}:
		locator.fill("test")
		return True
	if candidate["tag"] == "button" or candidate["type"] in {"button", "submit"}:
		if not _is_safe_button(candidate):
			return False
		locator.click(timeout=3_000)
		return True
	return False


def _same_view(source_url: str, current_url: str) -> bool:
	source, current = urlsplit(source_url), urlsplit(current_url)
	return (source.scheme, source.netloc, source.path) == (current.scheme, current.netloc, current.path)


def _deep_scan_endpoint(
	page: Page,
	endpoint_url: str,
	timeout_ms: int,
	tested_forms: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
	page.goto(endpoint_url, wait_until="domcontentloaded", timeout=timeout_ms)
	captured_requests: list[dict[str, Any]] = []
	kept_interactions: list[dict[str, Any]] = []
	skipped = {"destructive": 0, "duplicate_form": 0, "no_network": 0}

	def capture_request(request: Request) -> None:
		if request.resource_type in {"xhr", "fetch"}:
			captured_requests.append(_request_record(request))

	page.on("request", capture_request)
	try:
		for candidate in _extract_candidates(page)[:MAX_INTERACTIONS_PER_ENDPOINT]:
			if _is_destructive(candidate):
				skipped["destructive"] += 1
				continue
			pattern = _form_pattern(candidate) if candidate.get("form") else ""
			if pattern and pattern in tested_forms:
				skipped["duplicate_form"] += 1
				continue
			if pattern:
				tested_forms.add(pattern)

			request_start = len(captured_requests)
			try:
				if not _interact(page, candidate):
					continue
				page.wait_for_timeout(INTERACTION_SETTLE_MS)
			except Exception:
				continue

			interaction_requests = captured_requests[request_start:]
			if not interaction_requests:
				skipped["no_network"] += 1
				continue
			if not _same_view(endpoint_url, page.url):
				page.goto(endpoint_url, wait_until="domcontentloaded", timeout=timeout_ms)
				continue
			kept_interactions.append({
				"endpoint": endpoint_url,
				"element": {
					"tag": candidate["tag"],
					"type": candidate["type"],
					"text": candidate["text"],
					"name": candidate["name"],
					"form": candidate.get("form"),
				},
				"request_count": len(interaction_requests),
			})
	finally:
		page.remove_listener("request", capture_request)
	return captured_requests, kept_interactions, skipped


def _unique_requests(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
	unique = []
	seen = set()
	for request in requests:
		key = (request["method"], request["url"], json.dumps(request["headers"], sort_keys=True))
		if key not in seen:
			seen.add(key)
			unique.append(request)
	return unique


def _filtered_response_headers(headers: dict[str, str]) -> dict[str, str]:
	"""Normaliza cabeceras de respuesta y omite valores de transporte o sesión."""
	filtered = {
		name.lower(): value
		for name, value in headers.items()
		if name.lower() not in IRRELEVANT_RESPONSE_HEADERS
	}
	return dict(sorted(filtered.items()))


def _collect_endpoint_headers(
	page: Page,
	endpoint_url: str,
	timeout_ms: int,
	tested_forms: set[str],
) -> dict[str, Any]:
	"""Captura la carga y envíos de formularios seguros en la URL actual."""
	requests: list[dict[str, Any]] = []
	requests_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}

	def capture_request(request: Request) -> None:
		if request.resource_type not in {"document", "xhr", "fetch"}:
			return
		request_url = urlsplit(request.url)
		if request_url.path.rstrip("/").lower().endswith("/socket.io"):
			return
		if request_url.path.lower().startswith(("/analytics", "/telemetry", "/collect")):
			return
		record = _request_record(request)
		key = _request_key(record)
		if key not in requests_by_key:
			requests_by_key[key] = record
			requests.append(record)

	def capture_response(response: Any) -> None:
		request = response.request
		if request.resource_type not in {"document", "xhr", "fetch"}:
			return
		record = requests_by_key.get(_request_key(_request_record(request)))
		if record:
			record["response"] = {
				"status": response.status,
				"headers": _filtered_response_headers(response.headers),
			}

	page.on("request", capture_request)
	page.on("response", capture_response)
	try:
		response = page.goto(endpoint_url, wait_until="domcontentloaded", timeout=timeout_ms)
		page.wait_for_timeout(250)
		form_results = _submit_forms(
			page, endpoint_url, timeout_ms, requests, requests_by_key, tested_forms
		)
	finally:
		page.remove_listener("request", capture_request)
		page.remove_listener("response", capture_response)
	if response is None:
		return {
			"requested_urls": [endpoint_url],
			"final_url": page.url,
			"status": None,
			"status_text": "No response received",
			"headers": {},
			"requests": requests,
			"forms": form_results,
		}
	return {
		"requested_urls": [endpoint_url],
		"final_url": page.url,
		"status": response.status,
		"status_text": response.status_text,
		"headers": _filtered_response_headers(response.all_headers()),
		"requests": requests,
		"forms": form_results,
	}


def _extract_forms(page: Page) -> list[dict[str, Any]]:
	"""Reconoce formularios HTML, sus tipos de campo y sus botones de envío."""
	return page.evaluate(
		"""() => Array.from(document.forms).map((form, formIndex) => {
			const formMarker = `deep-form-${formIndex}`;
			form.setAttribute('data-deep-form', formMarker);
			const fields = Array.from(form.querySelectorAll('input, textarea, select'))
				.filter(field => field.type !== 'hidden' && !field.hidden)
				.map((field, fieldIndex) => {
				const marker = `${formMarker}-field-${fieldIndex}`;
				field.setAttribute('data-deep-field', marker);
				return {
					marker,
					name: field.name || field.id || `field_${fieldIndex}`,
					type: (field.type || field.tagName.toLowerCase()).toLowerCase(),
					required: field.required,
					disabled: field.disabled,
					read_only: field.readOnly,
					visible: Boolean(field.offsetWidth || field.offsetHeight || field.getClientRects().length),
					options: field.tagName === 'SELECT'
						? Array.from(field.options).filter(option => !option.disabled).map(option => option.value)
						: [],
					labels: field.labels ? Array.from(field.labels).map(label => label.innerText.trim()) : []
				};
			});
			const submitters = Array.from(form.querySelectorAll('button, input[type="submit"], input[type="image"]'))
				.filter(button => !button.disabled).map((button, buttonIndex) => {
					const marker = `${formMarker}-submit-${buttonIndex}`;
					button.setAttribute('data-deep-submit', marker);
					return {
						marker,
						text: (button.innerText || button.value || button.getAttribute('aria-label') || '').trim(),
						type: (button.type || '').toLowerCase(),
						is_submit: button.type === 'submit' || button.type === 'image'
					};
				});
			return {
				marker: formMarker,
				index: formIndex,
				action: form.action || location.href,
				method: (form.method || 'GET').toUpperCase(),
				enctype: form.enctype || 'application/x-www-form-urlencoded',
				text: (form.innerText || '').trim(),
				fields,
				submitters
			};
		})"""
	)


def _form_pattern(form: dict[str, Any]) -> str:
	fields = ",".join(f"{field['name']}:{field['type']}" for field in form["fields"])
	action = urlsplit(form["action"])
	normalized_action = urlunsplit((action.scheme, action.netloc, action.path, "", ""))
	return f"{form['method']}|{normalized_action}|{form['enctype']}|{fields}"


def _form_is_safe(form: dict[str, Any], endpoint_url: str) -> bool:
	form_url = urlsplit(form["action"])
	endpoint = urlsplit(endpoint_url)
	if (form_url.scheme, form_url.netloc) != (endpoint.scheme, endpoint.netloc):
		return False
	action_text = f"{form['action']} {form['text']} {' '.join(item['text'] for item in form['submitters'])}".lower()
	return not any(term in action_text for term in DESTRUCTIVE_TERMS)


def _default_field_value(field: dict[str, Any]) -> str | None:
	field_type = field["type"]
	name = field["name"].lower()
	if field["disabled"] or field["read_only"] or not field.get("visible", True) or field_type in {"hidden", "file", "submit", "button", "reset", "image"}:
		return None
	if field_type in {"checkbox", "radio"}:
		return "__check__" if field["required"] else None
	if field_type == "select-one" or field_type == "select-multiple":
		return field["options"][0] if field["options"] else None
	if field_type == "email" or "email" in name:
		return "test@example.com"
	if field_type == "password" or any(token in name for token in ("password", "passwd", "pass")):
		return "TestPass123!"
	if field_type == "number" or any(token in name for token in ("quantity", "amount", "count", "age")):
		return "1"
	if field_type == "tel" or any(token in name for token in ("phone", "mobile", "tel")):
		return "5550100100"
	if field_type == "url" or "website" in name:
		return "https://example.com"
	if field_type == "date":
		return "2026-01-15"
	if field_type == "datetime-local":
		return "2026-01-15T12:00"
	if field_type == "time":
		return "12:00"
	if field_type == "month":
		return "2026-01"
	if field_type == "color":
		return "#336699"
	if field_type in {"range", "submitter"}:
		return None
	return "test"


def _fill_form(page: Page, form: dict[str, Any]) -> None:
	for field in form["fields"]:
		value = _default_field_value(field)
		if value is None:
			continue
		locator = page.locator(f'[data-deep-field="{field["marker"]}"]')
		if value == "__check__":
			locator.check()
		elif field["type"] in {"checkbox", "radio"}:
			if field["type"] == "radio":
				locator.check()
		elif field["type"] in {"select-one", "select-multiple"}:
			locator.select_option(value)
		else:
			locator.fill(value)


def _submit_forms(
	page: Page,
	endpoint_url: str,
	timeout_ms: int,
	requests: list[dict[str, Any]],
	requests_by_key: dict[tuple[str, str, str], dict[str, Any]],
	tested_forms: set[str],
) -> list[dict[str, Any]]:
	forms_seen: set[str] = set()
	results = []
	for form in _extract_forms(page)[:MAX_FORMS_PER_ENDPOINT]:
		pattern = _form_pattern(form)
		if pattern in forms_seen or pattern in tested_forms:
			results.append({"form_pattern": pattern, "status": "duplicate_on_page"})
			continue
		forms_seen.add(pattern)
		tested_forms.add(pattern)
		if not _form_is_safe(form, endpoint_url):
			results.append({"form_pattern": pattern, "status": "skipped_unsafe_or_external"})
			continue

		request_start = len(requests)
		try:
			_fill_form(page, form)
			submitter = next(
				(item for item in form["submitters"] if _is_safe_button(item)),
				next((item for item in form["submitters"] if item["is_submit"]), None),
			)
			if submitter:
				page.locator(f'[data-deep-submit="{submitter["marker"]}"]').click(timeout=1_500)
			else:
				page.locator(f'[data-deep-form="{form["marker"]}"]').evaluate("form => form.requestSubmit()")
			page.wait_for_timeout(INTERACTION_SETTLE_MS)
			form_requests = requests[request_start:]
			results.append({
				"form_pattern": pattern,
				"method": form["method"],
				"action": _redact_url(form["action"]),
				"status": "request_captured" if form_requests else "submitted_no_request_observed",
				"request_lines": [record["request_line"] for record in form_requests],
			})
		except Exception as error:
			results.append({"form_pattern": pattern, "status": "submit_failed", "error": str(error)})
		try:
			page.goto(endpoint_url, wait_until="domcontentloaded", timeout=timeout_ms)
			page.wait_for_timeout(150)
		except Exception:
			pass
	return results


def run_deep_crawler(
	target_url: str | None = None,
	crawler_report_path: Path | None = None,
	timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
	"""Obtiene cabeceras y peticiones de los endpoints descubiertos."""
	if crawler_report_path:
		target_url, endpoint_urls = _load_endpoints(crawler_report_path)
	elif target_url:
		crawler_report = analyze_website(target_url, timeout_ms)
		target_url, endpoint_urls = _endpoints_from_report(crawler_report)
	else:
		raise ValueError("Se requiere target_url o crawler_report_path.")
	endpoints_by_final_url: dict[str, dict[str, Any]] = {}
	errors = []
	tested_forms: set[str] = set()

	with sync_playwright() as playwright:
		browser = playwright.chromium.launch(headless=True)
		try:
			state_path = _authentication_state_path(target_url)
			context = browser.new_context(
				**({"storage_state": str(state_path)} if state_path.is_file() else {})
			)
			page = context.new_page()
			_, authentication = _authenticate_if_configured(
				context, page, target_url, timeout_ms, state_path, state_path.is_file()
			)
			for endpoint_url in endpoint_urls:
				try:
					result = _collect_endpoint_headers(
						page, endpoint_url, timeout_ms, tested_forms
					)
					existing = endpoints_by_final_url.get(result["final_url"])
					if existing:
						existing["requested_urls"].extend(
							url for url in result["requested_urls"]
							if url not in existing["requested_urls"]
						)
						existing["forms"].extend(result["forms"])
						request_records = {
							_request_key(item): item
							for item in existing["requests"]
						}
						for request in result["requests"]:
							key = _request_key(request)
							if key not in request_records:
								existing["requests"].append(request)
								request_records[key] = request
					else:
						endpoints_by_final_url[result["final_url"]] = result
				except Exception as error:
					errors.append({"url": endpoint_url, "error": str(error)})
		finally:
			browser.close()

	endpoints = sorted(endpoints_by_final_url.values(), key=lambda endpoint: endpoint["final_url"])
	form_results = [form for endpoint in endpoints for form in endpoint["forms"]]
	entry_points_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
	for endpoint in endpoints:
		endpoint["entry_point_ids"] = []
		for request in endpoint.pop("requests"):
			key = _request_key(request)
			entry_point = entry_points_by_key.get(key)
			if entry_point is None:
				entry_point = {
					"id": f"entry_{len(entry_points_by_key) + 1:04d}",
					**request,
					"observed_on": [],
				}
				entry_points_by_key[key] = entry_point
			elif entry_point["response"] is None and request["response"] is not None:
				entry_point["response"] = request["response"]
			if endpoint["final_url"] not in entry_point["observed_on"]:
				entry_point["observed_on"].append(endpoint["final_url"])
			endpoint["entry_point_ids"].append(entry_point["id"])
	entry_points = list(entry_points_by_key.values())
	return {
		"target": target_url,
		"analyzed_at": datetime.now(timezone.utc).isoformat(),
		"authentication": authentication,
		"summary": {
			"requested_url_count": len(endpoint_urls),
			"unique_response_count": len(endpoints),
			"unique_entry_point_count": len(entry_points),
			"forms_attempted": sum(form["status"] not in {"duplicate_on_page", "skipped_unsafe_or_external"} for form in form_results),
			"forms_with_requests": sum(form["status"] == "request_captured" for form in form_results),
			"error_count": len(errors),
		},
		"endpoints": endpoints,
		"forms": form_results,
		"entry_points": entry_points,
		"errors": errors,
	}


def _write_report(report: dict[str, Any]) -> Path:
	output_path = Path(os.getenv("DEEP_CRAWLER_REPORT_PATH", str(DEEP_REPORT_DEFAULT))).expanduser()
	output_path.parent.mkdir(parents=True, exist_ok=True)
	output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
	return output_path


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Crawler profundo de formularios y endpoints")
	parser.add_argument("--target-url", help="URL raiz para descubrir y analizar endpoints")
	parser.add_argument("--crawler-report", type=Path, help="Informe de crawler.py para una ejecucion local")
	parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
	args = parser.parse_args()
	if not args.target_url and not args.crawler_report:
		parser.error("se requiere --target-url o --crawler-report")
	try:
		report = run_deep_crawler(args.target_url, args.crawler_report, args.timeout_ms)
	except Exception as error:
		report = {"error": str(error)}
	print(json.dumps(report, ensure_ascii=False, indent=2))
