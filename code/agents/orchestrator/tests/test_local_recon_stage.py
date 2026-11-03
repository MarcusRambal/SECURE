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


if __name__ == "__main__":
    unittest.main()
