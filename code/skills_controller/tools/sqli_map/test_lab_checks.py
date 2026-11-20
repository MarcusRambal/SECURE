import unittest

from run_lab_checks import build_request, classify, should_stop, test_cases


class SqliLabCheckTests(unittest.TestCase):
    def test_matrix_toggles_only_the_two_requested_flags(self):
        self.assertEqual(
            test_cases(),
            (
                ("ambas-activas", True, True),
                ("solo-login-activa", True, False),
                ("solo-busqueda-activa", False, True),
                ("ambas-desactivadas", False, False),
            ),
        )

        request = build_request(
            "http://weak-page:3009", "search", login=False, search=True
        )
        self.assertIn(
            "X-Vulnerability-Override: SQLI_LOGIN=false,SQLI_SEARCH=true",
            request,
        )
        self.assertNotIn("UNION_SQLI_DUMP", request)

    def test_builds_captured_login_request_with_exact_content_length(self):
        request = build_request(
            "http://weak-page:3009", "login", login=True, search=False
        )
        body = '{"email":"test@example.test","password":"test123"}'

        self.assertIn("POST /api/auth/login HTTP/1.1", request)
        self.assertIn("SQLI_LOGIN=true,SQLI_SEARCH=false", request)
        self.assertIn(f"Content-Length: {len(body.encode('utf-8'))}", request)
        self.assertTrue(request.endswith("\r\n\r\n" + body))

    def test_distinguishes_detection_negative_timeout_and_errors(self):
        self.assertEqual(
            classify({"result": {"exit_code": 0, "injectable": True}}, 0),
            "DETECTADA",
        )
        self.assertEqual(
            classify({"result": {"exit_code": 0, "injectable": False}}, 0),
            "NO DETECTADA",
        )
        self.assertEqual(
            classify(
                {"result": {"status": "timeout", "injectable": False}},
                0,
            ),
            "TIMEOUT",
        )
        self.assertEqual(
            classify(
                {
                    "result": {
                        "exit_code": 0,
                        "injectable": False,
                        "diagnostics": ["[CRITICAL] connection timed out"],
                    }
                },
                0,
            ),
            "INCONCLUSA",
        )
        self.assertEqual(
            classify(
                {
                    "result": {
                        "exit_code": 0,
                        "injectable": False,
                        "diagnostics": [
                            "[CRITICAL] all tested parameters do not appear to be injectable"
                        ],
                    }
                },
                0,
            ),
            "NO DETECTADA",
        )
        self.assertEqual(classify(None, 0), "ERROR")
        self.assertEqual(
            classify({"result": {"exit_code": 0, "injectable": True}}, 1),
            "ERROR",
        )

    def test_inconclusive_results_continue_but_errors_and_timeouts_stop(self):
        self.assertFalse(should_stop("INCONCLUSA"))
        self.assertTrue(should_stop("ERROR"))
        self.assertTrue(should_stop("TIMEOUT"))


if __name__ == "__main__":
    unittest.main()
