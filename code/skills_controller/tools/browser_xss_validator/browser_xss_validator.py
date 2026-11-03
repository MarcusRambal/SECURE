#!/usr/bin/env python3
"""Run a bounded browser XSS proof from a declarative Recon validation plan."""

from __future__ import annotations

import argparse
import json
import secrets
from urllib.parse import parse_qsl, urljoin, urlsplit


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("URL must be absolute HTTP(S).")
    if parts.username or parts.password:
        raise ValueError("Credentials in URLs are not allowed.")
    return parts.scheme, parts.hostname.casefold(), parts.port or (
        443 if parts.scheme == "https" else 80
    )


def _same_origin(base_url: str, url: str) -> bool:
    try:
        return _origin(base_url) == _origin(url)
    except ValueError:
        return False


def _target_url(base_url: str, path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Validation request paths must be origin-relative.")
    target = urljoin(base_url, path)
    if not _same_origin(base_url, target):
        raise ValueError("Validation request paths must remain on the target origin.")
    return target


def _proof_payload(marker: str) -> str:
    return (
        f"<img src=/__xss_probe_missing_{marker} "
        "onerror=window.__browserXssProof=1>"
    )


def _field_value(field_name: str, parameter: str, marker: str, payload: str) -> str:
    if field_name == parameter:
        return f"{marker}{payload}"
    if "email" in field_name.casefold():
        return "browser-xss-test@invalid.example"
    if "name" in field_name.casefold():
        return "Browser XSS Test"
    if "subject" in field_name.casefold():
        return "Synthetic browser validation"
    return f"Synthetic browser validation {marker}"


def _validate_plan(base_url: str, plan: dict) -> tuple[str, str]:
    if not isinstance(plan, dict):
        raise ValueError("Validation plan must be an object.")
    mode = plan.get("mode")
    if mode not in {"reflected_dom", "stored_dom"}:
        raise ValueError("Unsupported browser XSS validation mode.")
    source_url = plan.get("source_url")
    if not isinstance(source_url, str) or not _same_origin(base_url, source_url):
        raise ValueError("The observed source page must share the target origin.")
    request = plan.get("request")
    if not isinstance(request, dict):
        raise ValueError("Validation plan must include the observed request.")
    endpoint = _target_url(base_url, request.get("path"))
    method = str(request.get("method") or "").upper()
    marker_prefix = plan.get("marker_prefix", "xss-probe-")
    if (
        not isinstance(marker_prefix, str)
        or not marker_prefix
        or not all(character.isalnum() or character in "_-" for character in marker_prefix)
    ):
        raise ValueError("Validation marker prefix contains unsupported characters.")
    if mode == "reflected_dom":
        if method != "GET" or not plan.get("input_selector"):
            raise ValueError("Reflected DOM plans require GET and an input selector.")
    else:
        if (
            method != "POST"
            or not isinstance(plan.get("form_fields"), list)
            or not plan.get("form_selector")
            or not isinstance(plan.get("cleanup"), dict)
            or not isinstance(plan.get("verification_request"), dict)
        ):
            raise ValueError(
                "Stored DOM plans require a form, fields, POST, and cleanup request."
            )
        cleanup = plan["cleanup"]
        _target_url(base_url, cleanup.get("path_template", "").replace("{id}", "1"))
        if str(cleanup.get("method") or "").upper() != "DELETE":
            raise ValueError("Stored DOM validation must provide a DELETE cleanup.")
        verification_request = plan["verification_request"]
        _target_url(
            base_url,
            verification_request.get("path_template", "").replace("{id}", "1"),
        )
        if str(verification_request.get("method") or "").upper() != "GET":
            raise ValueError("Stored DOM validation requires a GET verification request.")
    return endpoint, method


def run_validation(base_url: str, plan: dict) -> dict:
    endpoint, method = _validate_plan(base_url, plan)
    marker = f"{plan.get('marker_prefix', 'xss-probe-')}{secrets.token_hex(6)}"
    payload = _proof_payload(marker)
    parameter = str(plan.get("parameter") or "")
    result = {
        "tool": "browserXssValidator",
        "target": base_url.rstrip("/"),
        "outcome": "INCONCLUSIVE",
        "evidence": "",
        "cleanup": "not_required",
    }
    stage = "browser_startup"
    failed_stage = None

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(service_workers="block")
        page = context.new_page()
        page.add_init_script("window.__browserXssProof = 0;")
        page.on("dialog", lambda dialog: dialog.dismiss())
        record_id = None

        def restrict_and_tag(route) -> None:
            request = route.request
            if not _same_origin(base_url, request.url):
                route.abort()
                return

            headers = dict(request.headers)
            request_parts = urlsplit(request.url)
            if (
                method == request.method.upper()
                and request_parts.path == urlsplit(endpoint).path
            ):
                extra_headers = plan.get("request_headers", {})
                if isinstance(extra_headers, dict):
                    headers.update(extra_headers)
            if plan.get("mode") == "stored_dom":
                verification_request = plan["verification_request"]
                verification_path = verification_request["path_template"].format(
                    id=record_id or "pending"
                )
                if (
                    request.method.upper()
                    == str(verification_request.get("method") or "GET").upper()
                    and request_parts.path == urlsplit(
                        _target_url(base_url, verification_path)
                    ).path
                ):
                    extra_headers = verification_request.get("headers", {})
                    if isinstance(extra_headers, dict):
                        headers.update(extra_headers)
            route.continue_(headers=headers)

        context.route("**/*", restrict_and_tag)
        try:
            stage = "source_navigation"
            page.goto(plan["source_url"], wait_until="domcontentloaded", timeout=15_000)
            if plan["mode"] == "reflected_dom":
                stage = "reflected_input"
                selector = plan["input_selector"]
                field = page.locator(selector).first
                field.wait_for(state="visible", timeout=10_000)
                query_parameter = str(
                    plan.get("request", {}).get("query_parameter") or parameter
                )
                with page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == urlsplit(endpoint).path
                        and response.request.method.upper() == method
                        and any(
                            name == query_parameter
                            for name, _ in parse_qsl(
                                urlsplit(response.url).query,
                                keep_blank_values=True,
                            )
                        )
                    ),
                    timeout=12_000,
                ) as reflected_response:
                    field.fill(f"{marker}{payload}")
                response = reflected_response.value
                response_body = response.text()
                marker_in_response = marker in response_body
                page.wait_for_timeout(350)
                executed = bool(
                    page.evaluate("() => window.__browserXssProof === 1")
                )
                stage = "reflected_result"
                result.update(
                    mode=plan["mode"],
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    outcome="VULNERABLE" if executed else "NO_XSS",
                    evidence=(
                        "Chromium observed execution of the synthetic proof in the DOM."
                        if executed
                        else "The request completed but the synthetic marker was absent "
                        "from the response."
                        if not marker_in_response
                        else "The synthetic marker was reflected in the response but did "
                        "not execute in the DOM."
                    ),
                    checks={
                        "response_status": response.status,
                        "marker_in_response": marker_in_response,
                        "execution_observed": executed,
                    },
                )
            else:
                stage = "stored_form_submission"
                form = page.locator(plan["form_selector"]).first
                form.wait_for(state="visible", timeout=10_000)
                form_fields = plan["form_fields"]
                if parameter not in form_fields:
                    raise ValueError("The injection parameter is absent from observed form fields.")
                for field_name in form_fields:
                    field = form.locator(f'[name="{field_name}"]').first
                    if field.count() == 0:
                        continue
                    field_type = (field.get_attribute("type") or "").casefold()
                    if field_type in {"checkbox", "radio"}:
                        field.check()
                    elif field_type in {"submit", "button", "file", "hidden"}:
                        continue
                    else:
                        field.fill(
                            _field_value(field_name, parameter, marker, payload)
                        )

                with page.expect_response(
                    lambda response: (
                        urlsplit(response.url).path == urlsplit(endpoint).path
                        and response.request.method.upper() == method
                    ),
                    timeout=12_000,
                ) as post_response:
                    page.locator(plan["submit_selector"]).first.click(timeout=5_000)

                response = post_response.value
                if response.status < 200 or response.status >= 300:
                    result.update(
                        mode=plan["mode"],
                        endpoint=endpoint,
                        method=method,
                        parameter=parameter,
                        evidence=f"The observed form returned HTTP {response.status}.",
                        checks={
                            "write_status": response.status,
                            "record_created": False,
                            "marker_in_view": False,
                            "execution_observed": False,
                        },
                    )
                else:
                    saved = response.json()
                    record_id = saved.get("id")
                    if record_id is None:
                        raise ValueError(
                            "The observed write response did not contain a cleanup identifier."
                        )
                    verification_url = str(plan.get("verification_url_template") or "")
                    if "{id}" not in verification_url or "{marker}" not in verification_url:
                        raise ValueError("Stored DOM plan must provide a verification URL template.")
                    verification_url = verification_url.format(
                        id=record_id,
                        marker=marker,
                    )
                    verification_url = urljoin(base_url, verification_url)
                    if not _same_origin(base_url, verification_url):
                        raise ValueError("The verification page must share the target origin.")
                    stage = "stored_record_verification"
                    verification_request = plan["verification_request"]
                    verification_path = verification_request["path_template"].format(
                        id=record_id
                    )
                    verification_url_api = _target_url(base_url, verification_path)
                    verification_method = str(
                        verification_request.get("method") or "GET"
                    ).upper()
                    matching_responses = []

                    def capture_verification_response(response) -> None:
                        try:
                            if (
                                urlsplit(response.url).path
                                == urlsplit(verification_url_api).path
                                and response.request.method.upper()
                                == verification_method
                            ):
                                matching_responses.append(response)
                        except Exception:
                            pass

                    page.on("response", capture_verification_response)
                    page.goto(
                        verification_url,
                        wait_until="domcontentloaded",
                        timeout=15_000,
                    )
                    selector = str(plan.get("verification_selector") or "body")
                    try:
                        page.locator(selector).first.wait_for(
                            state="visible", timeout=10_000
                        )
                    except Exception:
                        if selector == "body":
                            raise
                        selector = "body"
                        page.locator("body").first.wait_for(
                            state="visible", timeout=5_000
                        )
                    try:
                        page.wait_for_function(
                            "(marker) => document.body && "
                            "document.body.innerHTML.includes(marker)",
                            arg=marker,
                            timeout=6_000,
                        )
                    except Exception:
                        pass
                    verification_status = (
                        matching_responses[-1].status if matching_responses else None
                    )
                    rendered_html = page.locator(selector).first.inner_html()
                    marker_in_view = marker in rendered_html
                    page.wait_for_timeout(350)
                    executed = bool(
                        page.evaluate("() => window.__browserXssProof === 1")
                    )
                    stage = "stored_result"
                    result.update(
                        mode=plan["mode"],
                        endpoint=endpoint,
                        method=method,
                        parameter=parameter,
                        outcome="VULNERABLE" if executed else "NO_XSS",
                        evidence=(
                            "Chromium observed execution of the stored synthetic proof in the observed verification view."
                            if executed
                            else "The stored synthetic proof appeared in the observed view without executing."
                            if marker_in_view
                            else "The write succeeded, but the synthetic marker was absent "
                            "from the observed verification view."
                        ),
                        checks={
                            "write_status": response.status,
                            "verification_status": verification_status,
                            "marker_in_view": marker_in_view,
                            "execution_observed": executed,
                        },
                    )
        except Exception as error:
            failed_stage = stage
            result.update(
                outcome="INCONCLUSIVE",
                evidence=(
                    f"Browser validation failed during {stage}: "
                    f"{type(error).__name__}."
                ),
            )
        finally:
            if plan["mode"] == "stored_dom" and record_id is not None:
                stage = "stored_record_cleanup"
                cleanup = plan["cleanup"]
                cleanup_path = cleanup["path_template"].format(id=record_id)
                cleanup_url = _target_url(base_url, cleanup_path)
                cleanup_headers = cleanup.get("headers", {})
                cleanup_body = cleanup.get("body", {})
                body = json.dumps(
                    {
                        key: value.format(marker=marker, id=record_id)
                        if isinstance(value, str)
                        else value
                        for key, value in cleanup_body.items()
                    }
                )
                try:
                    cleanup_status = page.evaluate(
                        """async ({url, method, headers, body}) => {
                          const response = await fetch(url, {method, headers, body});
                          return response.status;
                        }""",
                        {
                            "url": cleanup_url,
                            "method": cleanup["method"],
                            "headers": cleanup_headers,
                            "body": body,
                        },
                    )
                    result["cleanup"] = (
                        "success" if cleanup_status == 204 else "failed"
                    )
                except Exception:
                    result["cleanup"] = "failed"
            browser.close()

    if plan["mode"] == "reflected_dom":
        result["cleanup"] = "not_required"
    elif record_id is None:
        result["cleanup"] = "not_required"
    result["stage"] = failed_stage or stage
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--plan-json", required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan_json)
        report = run_validation(args.target_url, plan)
    except Exception as error:
        report = {
            "tool": "browserXssValidator",
            "target": args.target_url,
            "outcome": "INCONCLUSIVE",
            "evidence": f"Browser validation failed: {type(error).__name__}.",
            "cleanup": "failed" if "record_id" in locals() else "not_required",
            "stage": "plan_validation",
        }
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
