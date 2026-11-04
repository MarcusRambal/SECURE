import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from tools import TASK_STATE, create_orchestrator_tools


class LocalReconStageTests(unittest.TestCase):
    def test_target_preparation_runs_locally_without_recon_rpc(self):
        task_id = "local-recon-test"
        channel = object()
        recon_output = type(
            "ReconOutput",
            (),
            {
                "model_dump": lambda self: {
                    "recon_summary": {
                        "target_url": "http://weak-page:3009",
                        "attack_type_filter": "sqli",
                        "total_targets_identified": 1,
                        "total_requests_captured": 1,
                    },
                    "high_priority_targets": [
                        {
                            "target_id": "target-1",
                            "endpoint": "http://weak-page:3009/api/products?q=cake",
                            "method": "GET",
                        }
                    ],
                }
            },
        )()
        TASK_STATE[task_id] = {
            "target_url": "http://weak-page:3009",
            "attack_type": "sqli",
            "scraping_report": {"target": "http://weak-page:3009"},
            "timings": {"stages": {}},
        }

        async def run_stage():
            return await prepare_targets.coroutine(task_id)

        try:
            with (
                patch("tools.build_recon_output") as local_recon,
                patch("tools.publish_scan_event", new_callable=AsyncMock),
                patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
            ):
                local_recon.return_value = recon_output
                prepare_targets = next(
                    tool
                    for tool in create_orchestrator_tools(channel)
                    if tool.name == "prepare_targets"
                )
                result = asyncio.run(run_stage())

            local_recon.assert_called_once_with(
                "http://weak-page:3009",
                "sqli",
                scraping_report={"target": "http://weak-page:3009"},
            )
            rpc.assert_not_awaited()
            self.assertIn("Endpoints: 1", result)
            self.assertEqual(
                TASK_STATE[task_id]["recon_data"]["high_priority_targets"][0]["endpoint"],
                "http://weak-page:3009/api/products?q=cake",
            )
            self.assertEqual(TASK_STATE[task_id]["recon_recovery_mode"], "clean")
        finally:
            TASK_STATE.pop(task_id, None)

    def test_jwt_and_crypto_validation_run_without_synthetic_recon_targets(self):
        async def run_validation(attack_type):
            task_id = f"{attack_type}-no-recon-targets"
            TASK_STATE[task_id] = {
                "target_url": "https://example.test",
                "attack_type": attack_type,
                "status": "PROCESSING",
                "recon_data": {
                    "recon_summary": {
                        "target_url": "https://example.test",
                        "attack_type_filter": attack_type,
                        "total_targets_identified": 0,
                        "total_requests_captured": 1,
                    },
                    "high_priority_targets": [],
                },
                "timings": {"stages": {}},
                "token": "header.payload.signature" if attack_type == "jwt" else None,
            }
            try:
                with (
                    patch("tools.publish_scan_event", new_callable=AsyncMock),
                    patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
                ):
                    rpc.return_value = {
                        "status": "SUCCESS",
                        "validation_data": {
                            "target_url": "https://example.test",
                            "vulnerabilities": [],
                            "unconfirmed_findings": [],
                        },
                        "used_fallback": False,
                        "recovery_mode": "clean",
                        "tool_timings": [],
                    }
                    validate_tool = next(
                        tool
                        for tool in create_orchestrator_tools(object())
                        if tool.name == "validate_agent"
                    )
                    await validate_tool.coroutine(task_id)
                    return rpc.await_args.args[1], rpc.await_args.args[2]
            finally:
                TASK_STATE.pop(task_id, None)

        for attack_type in ("jwt", "crypto_inspector"):
            queue_name, payload = asyncio.run(run_validation(attack_type))
            self.assertEqual(queue_name, "validate_queue")
            self.assertEqual(payload["attack_type"], attack_type)
            self.assertEqual(payload["recon_data"]["high_priority_targets"], [])


class OrchestratorFailureFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.task_id = "failure-flow-test"
        self.target_url = "https://example.test"
        TASK_STATE[self.task_id] = {
            "target_url": self.target_url,
            "attack_type": "sqli",
            "status": "PROCESSING",
            "timings": {"stages": {}},
        }
        self.tools = {tool.name: tool for tool in create_orchestrator_tools(object())}

    def tearDown(self):
        TASK_STATE.pop(self.task_id, None)

    def empty_recon(self):
        return {
            "recon_summary": {
                "target_url": self.target_url,
                "attack_type_filter": "sqli",
                "total_targets_identified": 0,
                "total_requests_captured": 0,
            },
            "high_priority_targets": [],
        }

    def empty_validation(self):
        return {
            "target_url": self.target_url,
            "vulnerabilities": [],
            "unconfirmed_findings": [],
        }

    async def test_recon_failure_skips_validate_and_preserves_failure_in_report(self):
        with (
            patch("tools.build_recon_output", side_effect=ValueError("recon error")),
            patch("tools.publish_scan_event", new_callable=AsyncMock) as events,
            patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
        ):
            rpc.return_value = {"status": "SUCCESS", "report_markdown": "report"}
            await self.tools["prepare_targets"].coroutine(self.task_id)
            await self.tools["validate_agent"].coroutine(self.task_id)
            rpc.assert_not_awaited()
            await self.tools["reporter_agent"].coroutine(self.task_id)

        state = TASK_STATE[self.task_id]
        self.assertEqual(state["status"], "FAILED")
        self.assertEqual(state["recon_recovery_mode"], "error")
        self.assertEqual(state["validate_recovery_mode"], "skipped")
        self.assertEqual(state["timings"]["stages"]["validate"]["status"], "SKIPPED")
        self.assertEqual(state["recon_data"], self.empty_recon())
        self.assertEqual(state["validation_data"], self.empty_validation())
        self.assertEqual(state["report_markdown"], "report")
        self.assertEqual(rpc.await_args.args[1], "reporter_queue")
        self.assertEqual(rpc.await_args.args[2]["recon_data"], self.empty_recon())
        self.assertEqual(rpc.await_args.args[2]["validation_data"], self.empty_validation())
        self.assertTrue(any(call.kwargs.get("details", {}).get("status") == "ERROR"
                            for call in events.await_args_list))

    async def test_missing_targets_skips_validation_and_report_uses_empty_data(self):
        with (
            patch("tools.publish_scan_event", new_callable=AsyncMock),
            patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
        ):
            rpc.return_value = {"status": "SUCCESS", "report_markdown": "report"}
            await self.tools["validate_agent"].coroutine(self.task_id)
            rpc.assert_not_awaited()
            await self.tools["reporter_agent"].coroutine(self.task_id)

        state = TASK_STATE[self.task_id]
        self.assertEqual(state["status"], "COMPLETED")
        self.assertEqual(state["validate_recovery_mode"], "skipped")
        self.assertEqual(state["recon_data"], self.empty_recon())
        self.assertEqual(state["validation_data"], self.empty_validation())
        self.assertEqual(rpc.await_args.args[2]["recon_data"], self.empty_recon())
        self.assertEqual(rpc.await_args.args[2]["validation_data"], self.empty_validation())

    async def test_validate_rpc_failure_initializes_empty_validation(self):
        state = TASK_STATE[self.task_id]
        state["recon_data"] = {
            **self.empty_recon(),
            "high_priority_targets": [{"endpoint": "https://example.test/search"}],
        }
        with (
            patch("tools.publish_scan_event", new_callable=AsyncMock),
            patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
        ):
            rpc.return_value = {"status": "ERROR", "error": "validation error"}
            await self.tools["validate_agent"].coroutine(self.task_id)

        self.assertEqual(state["status"], "FAILED")
        self.assertEqual(state["validate_recovery_mode"], "error")
        self.assertEqual(state["validation_data"], self.empty_validation())

    async def test_partial_validation_and_findings_are_preserved_in_report(self):
        state = TASK_STATE[self.task_id]
        state["recon_data"] = {
            **self.empty_recon(),
            "high_priority_targets": [{"endpoint": "https://example.test/search"}],
        }
        validation = {
            **self.empty_validation(),
            "vulnerabilities": [{
                "type": "Finding",
                "severity": "CRITICAL",
                "endpoint": "https://example.test/search",
                "evidence": "evidence",
            }],
        }
        with (
            patch("tools.publish_scan_event", new_callable=AsyncMock) as events,
            patch("tools._send_rpc_request", new_callable=AsyncMock) as rpc,
        ):
            rpc.side_effect = [
                {
                    "status": "PARTIAL",
                    "used_fallback": True,
                    "recovery_mode": "fallback",
                    "validation_data": validation,
                },
                {"status": "SUCCESS", "report_markdown": "report"},
            ]
            await self.tools["validate_agent"].coroutine(self.task_id)
            await self.tools["reporter_agent"].coroutine(self.task_id)

        self.assertEqual(state["status"], "PARTIAL")
        self.assertEqual(state["validation_data"], validation)
        self.assertEqual(rpc.await_args_list[1].args[2]["validation_data"], validation)
        finding_events = [
            call for call in events.await_args_list if call.args[2] == "VULN_DETECTED"
        ]
        self.assertEqual(len(finding_events), 1)
        self.assertEqual(finding_events[0].kwargs["vulnerability"]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
