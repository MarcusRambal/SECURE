import json
import unittest
from unittest.mock import AsyncMock, patch

from attack_validators import (
    ValidationEvidence,
    XssValidationStrategy,
    _build_generic_browser_xss_plans,
    get_validation_strategy,
)


class DalfoxStrategyTests(unittest.IsolatedAsyncioTestCase):
    def test_xss_selects_the_dalfox_validation_strategy(self):
        self.assertIsInstance(get_validation_strategy("xss"), XssValidationStrategy)

    async def test_strategy_calls_dalfox_and_filters_raw_cli_output(self):
        raw_output = (
            "[INFO] private diagnostic noise\n"
            "[POC][V][GET][inHTML-HTML] "
            "https://example.test/search?token=private&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        )
        strategy = get_validation_strategy("xss")
        target = {
            "target_id": "target-1",
            "request_id": "request-1",
            "url": "https://example.test/search?token=private&q=hello",
            "method": "GET",
            "request": {
                "method": "GET",
                "url": "https://example.test/search?token=private&q=hello",
                "headers": {"cookie": "session=private"},
                "body": None,
            },
        }

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(return_value=raw_output),
        ) as call_skill:
            evidence = await strategy.execute(
                None, "https://example.test", [target], "task-1", []
            )

        call_skill.assert_awaited_once()
        self.assertEqual(call_skill.await_args.args[1], "dalfox")
        self.assertEqual(call_skill.await_args.args[2]["request"], target["request"])

        context = strategy.build_validation_context(evidence)
        serialized_context = json.dumps(context)
        self.assertEqual(len(context["xss_validation_results"]), 1)
        self.assertEqual(context["xss_validation_results"][0]["status"], "FINDINGS")
        self.assertEqual(
            context["xss_validation_results"][0]["findings"][0]["verification"],
            "verified",
        )
        self.assertNotIn("private diagnostic noise", serialized_context)
        self.assertNotIn("session=private", serialized_context)
        self.assertNotIn('"output"', serialized_context)

        merged = strategy.merge_findings(
            {"vulnerabilities": []}, evidence, "task-1"
        )
        self.assertEqual(len(merged["vulnerabilities"]), 1)
        self.assertEqual(
            merged["vulnerabilities"][0]["type"],
            "Cross-Site Scripting (XSS)",
        )

    async def test_declared_browser_plans_use_the_generic_validator(self):
        strategy = get_validation_strategy("xss")
        reflected_plan = {
            "mode": "reflected_dom",
            "source_url": "http://weak-page:3009/#/catalog",
            "parameter": "q",
            "input_selector": '[name="q"]',
            "request": {
                "method": "GET",
                "path": "/api/products",
                "query_parameter": "q",
            },
        }
        stored_plan = {
            "mode": "stored_dom",
            "source_url": "http://weak-page:3009/#/contact",
            "parameter": "message",
            "marker_prefix": "weakpage-xss-probe-",
            "form_selector": "form",
            "form_fields": ["email", "message", "name"],
            "submit_selector": 'button[type="submit"]',
            "request_headers": {
                "x-weak-page-xss-validation": "stored-contact",
            },
            "request": {"method": "POST", "path": "/api/contact"},
            "verification_url_template": (
                "/#/contact-inbox?probeId={id}&marker={marker}"
            ),
            "verification_request": {
                "method": "GET",
                "path_template": "/api/contact/xss-inbox/{id}",
            },
            "verification_selector": "#contact-inbox-items",
            "cleanup": {
                "method": "DELETE",
                "path_template": "/api/contact/{id}",
                "body": {"marker": "{marker}"},
                "headers": {
                    "content-type": "application/json",
                    "x-weak-page-xss-validation": "stored-contact",
                },
            },
        }
        targets = [
            {
                "target_id": "search",
                "request_id": "req-search",
                "url": "http://weak-page:3009/api/products?q=test",
                "method": "GET",
                "request": {
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=test",
                    "body": None,
                },
                "validation_plan": reflected_plan,
            },
            {
                "target_id": "contact",
                "request_id": "req-contact",
                "url": "http://weak-page:3009/api/contact",
                "method": "POST",
                "request": {
                    "method": "POST",
                    "url": "http://weak-page:3009/api/contact",
                    "headers": {"x-weak-page-crawler": "synthetic-probe"},
                    "body": {"message": "Synthetic probe"},
                },
                "validation_plan": stored_plan,
            },
        ]
        reports = [
            json.dumps(
                {
                    "tool": "browserXssValidator",
                    "target": "http://weak-page:3009",
                    "outcome": "VULNERABLE",
                    "mode": "reflected_dom",
                    "endpoint": "http://weak-page:3009/api/products",
                    "method": "GET",
                    "parameter": "q",
                    "evidence": "Chromium observed DOM execution.",
                    "stage": "reflected_result",
                    "checks": {
                        "response_status": 200,
                        "marker_in_response": True,
                        "execution_observed": True,
                    },
                }
            ),
            json.dumps(
                {
                    "tool": "browserXssValidator",
                    "target": "http://weak-page:3009",
                    "outcome": "VULNERABLE",
                    "mode": "stored_dom",
                    "endpoint": "http://weak-page:3009/api/contact",
                    "method": "POST",
                    "parameter": "message",
                    "evidence": "Chromium observed execution from the contact inbox.",
                    "cleanup": "success",
                }
            ),
        ]

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(side_effect=reports),
        ) as call_skill:
            evidence = await strategy.execute(
                None, "http://weak-page:3009", targets, "task-lab", []
            )

        self.assertEqual(call_skill.await_count, 2)
        self.assertEqual(
            [call.args[1] for call in call_skill.await_args_list],
            ["browserXssValidator", "browserXssValidator"],
        )
        self.assertEqual(
            [call.args[2]["plan"]["mode"] for call in call_skill.await_args_list],
            ["reflected_dom", "stored_dom"],
        )
        self.assertEqual(
            [item["status"] for item in evidence.pre_executed_context],
            ["VERIFIED", "VERIFIED"],
        )
        self.assertTrue(
            evidence.pre_executed_context[0]["checks"]["execution_observed"]
        )
        self.assertEqual(len(evidence.executed_commands), 2)
        output = strategy.build_deterministic_output(
            evidence,
            "http://weak-page:3009",
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(len(output.vulnerabilities), 2)
        self.assertEqual(output.unconfirmed_findings, [])
        self.assertTrue(
            all(item.tools_used == ["browserXssValidator"] for item in output.vulnerabilities)
        )

    async def test_stored_plan_without_successful_cleanup_is_not_confirmed(self):
        strategy = get_validation_strategy("xss")
        target = {
            "target_id": "contact",
            "request_id": "req-contact",
            "url": "http://weak-page:3009/api/contact",
            "method": "POST",
            "request": {
                "method": "POST",
                "url": "http://weak-page:3009/api/contact",
                "body": {"message": "synthetic"},
            },
            "validation_plan": {
                "mode": "stored_dom",
                "source_url": "http://weak-page:3009/#/contact",
                "parameter": "message",
                "marker_prefix": "weakpage-xss-probe-",
                "form_selector": "form",
                "form_fields": ["message"],
                "submit_selector": "button[type='submit']",
                "request_headers": {
                    "x-weak-page-xss-validation": "stored-contact",
                },
                "request": {"method": "POST", "path": "/api/contact"},
                "verification_url_template": (
                    "/#/contact-inbox?probeId={id}&marker={marker}"
                ),
                "verification_request": {
                    "method": "GET",
                    "path_template": "/api/contact/xss-inbox/{id}",
                },
                "verification_selector": "#contact-inbox-items",
                "cleanup": {
                    "method": "DELETE",
                    "path_template": "/api/contact/{id}",
                    "headers": {
                        "x-weak-page-xss-validation": "stored-contact",
                    },
                },
            },
        }
        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(
                return_value=json.dumps(
                    {
                        "tool": "browserXssValidator",
                        "target": "http://weak-page:3009",
                        "outcome": "VULNERABLE",
                        "mode": "stored_dom",
                        "endpoint": "http://weak-page:3009/api/contact",
                        "evidence": "Executed",
                        "cleanup": "failed",
                    }
                )
            ),
        ):
            evidence = await strategy.execute(
                None, "http://weak-page:3009", [target], "task-lab", []
            )

        self.assertEqual(evidence.pre_executed_context[0]["status"], "INCONCLUSIVE")
        output = strategy.build_deterministic_output(
            evidence,
            "http://weak-page:3009",
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(output.vulnerabilities, [])
        self.assertEqual(output.unconfirmed_findings[0]["status"], "INCONCLUSIVE")

    async def test_browser_plan_blocks_dalfox_fallback(self):
        strategy = get_validation_strategy("xss")
        target = {
            "target_id": "search",
            "request_id": "req-search",
            "url": "https://example.test/search?q=test",
            "method": "GET",
            "request": {
                "method": "GET",
                "url": "https://example.test/search?q=test",
                "body": None,
            },
            "recommended_tool": "browserXssValidator",
            "validation_plan": {
                "mode": "reflected_dom",
                "source_url": "https://example.test/#/search",
                "parameter": "q",
                "request": {"method": "GET", "path": "/search"},
            },
        }

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(
                return_value=json.dumps(
                    {
                        "tool": "browserXssValidator",
                        "target": "https://example.test",
                        "mode": "reflected_dom",
                        "outcome": "INCONCLUSIVE",
                        "evidence": "The browser validator could not confirm execution.",
                    }
                )
            ),
        ) as call_skill:
            evidence = await strategy.execute(
                None, "https://example.test", [target], "task-browser-only", []
            )

        self.assertEqual(call_skill.await_count, 1)
        self.assertEqual(call_skill.await_args.args[1], "browserXssValidator")
        self.assertEqual(len(evidence.pre_executed_context), 1)
        self.assertEqual(evidence.pre_executed_context[0]["status"], "INCONCLUSIVE")
        self.assertEqual(evidence.executed_commands[0]["tool"], "browserXssValidator")

    def test_generic_reflected_plan_uses_observed_page_and_reflected_parameter(self):
        request = {
            "method": "GET",
            "url": "https://example.test/api/products?q=probe&category=tartas",
            "observed_on": ["https://example.test/#/catalog"],
            "reflected_parameters": ["q"],
        }

        plans = _build_generic_browser_xss_plans(
            "https://example.test",
            "https://example.test/api/products?q=probe&category=tartas",
            request,
        )

        self.assertGreaterEqual(len(plans), 2)
        self.assertEqual(plans[0]["mode"], "reflected_dom")
        self.assertEqual(plans[0]["source_url"], "https://example.test/#/catalog")
        self.assertEqual(plans[0]["parameter"], "q")
        self.assertIn('input[type="search"]', plans[0]["input_selector"])
        self.assertEqual(
            plans[0]["request"]["query_parameter"],
            "q",
        )

    def test_generic_stored_plan_uses_listing_page_and_profile_contract(self):
        request = {
            "method": "POST",
            "url": "http://weak-page:3009/api/contact",
            "body": {
                "name": "[REDACTED]",
                "email": "[REDACTED]",
                "subject": "Synthetic crawler probe",
                "message": "Synthetic weakPageCrawler probe message.",
            },
            "observed_on": ["http://weak-page:3009/#/contact"],
            "observed_pages": [
                "http://weak-page:3009/#/contact",
                "http://weak-page:3009/#/contact-inbox",
            ],
        }

        plans = _build_generic_browser_xss_plans(
            "http://weak-page:3009",
            "http://weak-page:3009/api/contact",
            request,
        )

        self.assertEqual(len(plans), 1)
        plan = plans[0]
        self.assertEqual(plan["mode"], "stored_dom")
        self.assertEqual(plan["source_url"], "http://weak-page:3009/#/contact")
        self.assertEqual(plan["parameter"], "message")
        self.assertEqual(plan["marker_prefix"], "weakpage-xss-probe-")
        self.assertEqual(
            plan["request_headers"],
            {"x-weak-page-xss-validation": "stored-contact"},
        )
        self.assertEqual(
            plan["verification_url_template"],
            "http://weak-page:3009/#/contact-inbox?probeId={id}&marker={marker}",
        )
        self.assertEqual(
            plan["verification_request"]["path_template"],
            "/api/contact/xss-inbox/{id}",
        )
        self.assertEqual(
            plan["verification_request"]["headers"],
            {"x-weak-page-xss-validation": "stored-contact"},
        )
        self.assertEqual(
            plan["cleanup"]["path_template"],
            "/api/contact/{id}",
        )
        self.assertEqual(
            plan["cleanup"]["headers"]["x-weak-page-xss-validation"],
            "stored-contact",
        )

    def test_generic_stored_plan_without_profile_stays_origin_agnostic(self):
        request = {
            "method": "POST",
            "url": "https://example.test/api/comments",
            "body": {"author": "x", "comment": "hello"},
            "observed_on": ["https://example.test/comments"],
            "observed_pages": ["https://example.test/comments"],
        }

        plans = _build_generic_browser_xss_plans(
            "https://example.test",
            "https://example.test/api/comments",
            request,
        )

        self.assertEqual(len(plans), 1)
        plan = plans[0]
        self.assertEqual(plan["parameter"], "comment")
        self.assertEqual(plan["marker_prefix"], "xss-probe-")
        self.assertNotIn("request_headers", plan)
        self.assertEqual(
            plan["verification_url_template"],
            "https://example.test/comments?probeId={id}&marker={marker}",
        )
        self.assertEqual(
            plan["verification_request"]["path_template"],
            "/api/comments",
        )
        self.assertEqual(plan["cleanup"]["path_template"], "/api/comments/{id}")

    async def test_generic_plans_try_each_parameter_until_verified(self):
        strategy = get_validation_strategy("xss")
        target = {
            "target_id": "search",
            "request_id": "req-search",
            "url": "https://example.test/api/products?category=tartas&q=probe",
            "method": "GET",
            "recommended_tool": "browserXssValidator",
            "request": {
                "method": "GET",
                "url": "https://example.test/api/products?category=tartas&q=probe",
                "observed_on": ["https://example.test/#/catalog"],
                "reflected_parameters": ["q"],
            },
        }
        reports = [
            json.dumps(
                {
                    "tool": "browserXssValidator",
                    "target": "https://example.test",
                    "mode": "reflected_dom",
                    "outcome": "NO_XSS",
                    "evidence": "The synthetic marker was absent.",
                }
            ),
            json.dumps(
                {
                    "tool": "browserXssValidator",
                    "target": "https://example.test",
                    "mode": "reflected_dom",
                    "outcome": "VULNERABLE",
                    "evidence": "Chromium observed execution.",
                }
            ),
        ]

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(side_effect=reports),
        ) as call_skill:
            evidence = await strategy.execute(
                None, "https://example.test", [target], "task-params", []
            )

        self.assertEqual(call_skill.await_count, 2)
        self.assertEqual(
            [call.args[2]["plan"]["parameter"] for call in call_skill.await_args_list],
            ["q", "category"],
        )
        self.assertEqual(
            [item["status"] for item in evidence.pre_executed_context],
            ["NO_FINDINGS", "VERIFIED"],
        )

    def test_browser_confirmation_survives_mixed_tool_results_without_llm_finding(self):
        strategy = get_validation_strategy("xss")
        evidence = ValidationEvidence(
            executed_commands=[
                {
                    "tool": "browserXssValidator",
                    "command": "browserXssValidator --target-url https://example.test --plan",
                    "target_id": "browser-target",
                    "endpoint": "https://example.test/search",
                }
            ],
            pre_executed_context=[
                {
                    "tool": "dalfox",
                    "status": "NO_FINDINGS",
                    "target_id": "dalfox-target",
                },
                {
                    "tool": "browserXssValidator",
                    "status": "VERIFIED",
                    "target_id": "browser-target",
                    "request_id": "request-1",
                    "endpoint": "https://example.test/search",
                    "method": "GET",
                    "parameter": "q",
                    "mode": "reflected_dom",
                    "evidence": "Chromium observed execution.",
                },
                {
                    "tool": "browserXssValidator",
                    "status": "INCONCLUSIVE",
                    "target_id": "stored-target",
                    "request_id": "request-2",
                    "endpoint": "https://example.test/contact",
                    "method": "POST",
                    "parameter": "message",
                    "evidence": "The stored record could not be cleaned up.",
                },
            ],
        )

        merged = strategy.merge_findings(
            {"vulnerabilities": []},
            evidence,
            "task-mixed",
        )

        self.assertEqual(len(merged["vulnerabilities"]), 1)
        self.assertEqual(
            merged["vulnerabilities"][0]["type"],
            "Reflected DOM Cross-Site Scripting (XSS)",
        )
        self.assertEqual(
            merged["vulnerabilities"][0]["tools_used"],
            ["browserXssValidator"],
        )
        self.assertEqual(len(merged["unconfirmed_findings"]), 1)
        self.assertEqual(
            merged["unconfirmed_findings"][0]["status"],
            "INCONCLUSIVE",
        )


if __name__ == "__main__":
    unittest.main()
