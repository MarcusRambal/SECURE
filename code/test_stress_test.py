import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import unittest
from unittest.mock import patch

import requests

import stress_test


class Response:
    def __init__(self, status, body):
        self.status_code = status
        self.body = body

    def json(self):
        return self.body


def simulated_get(url, *, headers, **kwargs):
    flags = dict(
        pair.split("=") for pair in headers["X-Vulnerability-Override"].split(",")
    )
    if url.endswith("/api/admin/vulnerabilities"):
        return Response(200, {"flags": {key: value == "true" for key, value in flags.items()}})
    if url.endswith("/api/me"):
        if flags["MISSING_AUTH_ME"] == "true":
            return Response(200, {"user": {"id": 1}})
        return Response(401, {"message": "Token requerido"})
    if flags["IDOR_ORDERS"] == "true":
        return Response(200, {"id": 1, "user_id": 2})
    return Response(403, {"message": "No autorizado"})


class StressTestTests(unittest.TestCase):
    def test_all_combinations_run_twenty_times_and_report_exact_counters(self):
        output = io.StringIO()
        with patch.dict("os.environ", {"VICTIM_TOKEN": "victim", "ATTACKER_TOKEN": "attacker"}), \
             patch.object(stress_test, "validate_identities", return_value=2), \
             patch.object(stress_test.requests, "get", side_effect=simulated_get), \
             contextlib.redirect_stdout(output):
            result = stress_test.main([])
        self.assertEqual(result, 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "Resumen (cada combinación debe coincidir en login y búsqueda):")
        self.assertEqual(len(lines), 13)
        for scenario in stress_test.SCENARIOS:
            self.assertIn(f"{scenario}:", lines)
        self.assertEqual(sum("OK=20/20 fallo=0 inconclusa=0 timeout=0 error=0" in line for line in lines), 8)

    def test_mismatch_and_unverifiable_override_are_not_success(self):
        flags = stress_test.SCENARIOS["ambas-activas"]
        with patch.object(stress_test.requests, "get", side_effect=[
            Response(200, {"flags": flags}), Response(401, {})
        ]):
            self.assertEqual(stress_test.run_attempt("http://lab", "login", flags, "token", 2, 1), "fallo")
        with patch.object(stress_test.requests, "get", return_value=Response(200, {"flags": {}})), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(stress_test.run_attempt("http://lab", "login", flags, "token", 2, 1), "inconclusa")

    def test_timeouts_network_errors_and_missing_resources_are_counted(self):
        flags = stress_test.SCENARIOS["ambas-desactivadas"]
        for exception, expected in [(requests.Timeout("timeout"), "timeout"),
                                    (requests.ConnectionError("error"), "error")]:
            with self.subTest(expected=expected), \
                 patch.object(stress_test.requests, "get", side_effect=exception), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(stress_test.run_attempt("http://lab", "search", flags, "token", 2, 1), expected)
        with patch.object(stress_test.requests, "get", side_effect=[
            Response(200, {"flags": flags}), Response(404, {})
        ]):
            self.assertEqual(stress_test.run_attempt("http://lab", "search", flags, "token", 2, 1), "inconclusa")

    def test_invalid_owner_and_admin_attacker_are_rejected(self):
        with patch.object(stress_test, "identity", side_effect=[
            {"id": 2}, {"id": 3, "role": "admin"}
        ]):
            with self.assertRaises(ValueError):
                stress_test.validate_identities("http://lab", "victim", "attacker", 1)
        with patch.object(stress_test, "identity", side_effect=[
            {"id": 2}, {"id": 3, "role": "customer"}
        ]), patch.object(stress_test.requests, "get", return_value=Response(200, {"id": 1, "user_id": 3})):
            with self.assertRaises(ValueError):
                stress_test.validate_identities("http://lab", "victim", "attacker", 1)

    def test_end_to_end_over_http(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                flags = dict(
                    pair.split("=") for pair in
                    self.headers.get("X-Vulnerability-Override", "").split(",") if pair
                )
                if self.path == "/api/auth/whoami":
                    status, body = 200, {"user": {"id": 2 if token == "victim" else 3, "role": "customer"}}
                elif self.path == "/api/admin/vulnerabilities":
                    status, body = 200, {"flags": {k: v == "true" for k, v in flags.items()}}
                elif self.path == "/api/me":
                    status, body = (200, {"user": {"id": 1}}) if flags["MISSING_AUTH_ME"] == "true" else (401, {})
                elif self.path == "/api/orders/1":
                    status, body = (200, {"id": 1, "user_id": 2}) if token == "victim" or flags["IDOR_ORDERS"] == "true" else (403, {})
                else:
                    status, body = 404, {}
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.request_queue_size = 64
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            output = io.StringIO()
            with patch.dict("os.environ", {"VICTIM_TOKEN": "victim", "ATTACKER_TOKEN": "attacker"}), \
                 contextlib.redirect_stdout(output):
                result = stress_test.main(["--base-url", f"http://127.0.0.1:{server.server_port}", "--workers", "8"])
            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().count("OK=20/20 fallo=0 inconclusa=0 timeout=0 error=0"), 8)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
