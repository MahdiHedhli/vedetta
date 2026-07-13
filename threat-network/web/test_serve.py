"""Security-boundary tests for the dependency-free operations proxy."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("serve.py")
SPEC = importlib.util.spec_from_file_location("vedetta_operations_serve", MODULE_PATH)
serve = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(serve)


class UpstreamHandler(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.server.calls.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "if_match": self.headers.get("If-Match"),
                "action": self.headers.get("X-Vedetta-Admin-Action"),
                "tailscale_login": self.headers.get("Tailscale-User-Login"),
                "body": self.rfile.read(length),
            }
        )
        if self.path == "/api/v1/admin/device-corpus/audit":
            self.send_response(302)
            self.send_header(
                "Location",
                "http://127.0.0.1:%d/redirect-target" % self.server.server_address[1],
            )
            self.end_headers()
            return
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"upstream-etag"')
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply
    do_PUT = _reply

    def log_message(self, *_):
        pass


def start_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


class RaisingOpener:
    def __init__(self, error):
        self.error = error

    def open(self, *_args, **_kwargs):
        raise self.error


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        cls.upstream.calls = []
        cls.upstream_thread = start_server(cls.upstream)
        base = "http://127.0.0.1:%d" % cls.upstream.server_address[1]
        serve.PUBLIC_UPSTREAM = base
        serve.ADMIN_UPSTREAM = base
        cls.proxy = ThreadingHTTPServer(("127.0.0.1", 0), serve.Handler)
        cls.proxy.admin_token = b"a" * 32
        cls.proxy_thread = start_server(cls.proxy)
        cls.base = "http://127.0.0.1:%d" % cls.proxy.server_address[1]
        serve.ALLOWED_ORIGINS = (cls.base,)
        serve.ALLOWED_ADMIN_HOSTS = frozenset((cls.base.removeprefix("http://"),))
        serve.ALLOWED_TAILSCALE_USERS = frozenset(("curator@example.com",))
        serve.ALLOW_LOCAL_ADMIN = False

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.upstream.shutdown()
        cls.proxy.server_close()
        cls.upstream.server_close()
        cls.proxy_thread.join(2)
        cls.upstream_thread.join(2)

    def setUp(self):
        self.upstream.calls.clear()

    def open(self, path, method="GET", body=None, headers=None):
        headers = dict(headers or {})
        if path.startswith("/api/v1/admin/device-corpus/"):
            headers.setdefault("Tailscale-User-Login", "curator@example.com")
        request = urllib.request.Request(
            self.base + path, data=body, method=method, headers=headers
        )
        return urllib.request.urlopen(request, timeout=3)

    def test_public_route_discards_caller_authorization(self):
        with self.open("/api/v1/status", headers={"Authorization": "Bearer browser-secret"}) as response:
            self.assertEqual(response.status, 200)
            self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
        self.assertEqual(len(self.upstream.calls), 1)
        self.assertIsNone(self.upstream.calls[0]["authorization"])

    def test_admin_read_injects_server_token(self):
        with self.open("/api/v1/admin/device-corpus/profiles") as response:
            self.assertEqual(response.headers.get("ETag"), '"upstream-etag"')
        self.assertEqual(self.upstream.calls[0]["authorization"], "Bearer " + "a" * 32)
        self.assertIsNone(self.upstream.calls[0]["tailscale_login"])

    def test_paged_queries_are_allowlisted_and_canonicalized(self):
        with self.open(
            "/api/v1/admin/device-corpus/profiles?search=Acme%20Camera&offset=50&limit=25"
        ) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(
            self.upstream.calls[0]["path"],
            "/api/v1/admin/device-corpus/profiles?limit=25&offset=50&search=Acme+Camera",
        )

    def test_list_queries_reject_unknown_duplicate_and_out_of_range_values(self):
        denied = (
            "/api/v1/admin/device-corpus/profiles?limit=0",
            "/api/v1/admin/device-corpus/profiles?limit=101",
            "/api/v1/admin/device-corpus/profiles?offset=-1",
            "/api/v1/admin/device-corpus/profiles?offset=9223372036854775808",
            "/api/v1/admin/device-corpus/profiles?limit=10&limit=20",
            "/api/v1/admin/device-corpus/profiles?unknown=1",
            "/api/v1/admin/device-corpus/profiles?search=line%0Abreak",
            "/api/v1/admin/device-corpus/profiles?search=nul%00byte",
            "/api/v1/admin/device-corpus/audit?search=camera",
            "/api/v1/admin/device-corpus/profiles/profile_1?limit=10",
            "/api/v1/status?limit=10",
        )
        for path in denied:
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.open(path)
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_publish_preview_route_forwards_captured_etag(self):
        with self.open(
            "/api/v1/admin/device-corpus/profiles/profile_1/preview",
            headers={"If-Match": '"profile-etag"'},
        ) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(
            self.upstream.calls[0]["path"],
            "/api/v1/admin/device-corpus/profiles/profile_1/preview",
        )
        self.assertEqual(self.upstream.calls[0]["if_match"], '"profile-etag"')

    def test_request_log_never_contains_query_values(self):
        canary = "QUERY_CANARY_NEVER_LOG"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            with self.open(
                "/api/v1/admin/device-corpus/profiles?limit=10&offset=0&search="
                + canary
            ) as response:
                self.assertEqual(response.status, 200)
        self.assertNotIn(canary, captured.getvalue())
        self.assertIn("GET /api/v1/admin/device-corpus/profiles", captured.getvalue())

    def test_malformed_request_line_gets_normal_400_without_log_crash(self):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            with socket.create_connection(self.proxy.server_address, timeout=3) as client:
                client.sendall(b"GET / unexpected-token HTTP/1.1\r\n\r\n")
                client.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)

        self.assertIn(b"HTTP/1.0 400 Bad request syntax", response)
        self.assertIn("<malformed-request>", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())
        self.assertNotIn("AttributeError", captured.getvalue())
        self.assertEqual(self.upstream.calls, [])

    def test_invalid_absolute_target_gets_opaque_400_without_thread_crash(self):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            with socket.create_connection(self.proxy.server_address, timeout=3) as client:
                client.sendall(b"GET http://[bad HTTP/1.1\r\nHost: localhost\r\n\r\n")
                client.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)

        self.assertIn(b"HTTP/1.0 400 Bad Request", response)
        self.assertIn(b'"error":"INVALID_TARGET"', response)
        self.assertNotIn(b"http://[bad", response)
        self.assertNotIn("Traceback", captured.getvalue())
        self.assertNotIn("ValueError", captured.getvalue())
        self.assertNotIn("http://[bad", captured.getvalue())
        self.assertEqual(self.upstream.calls, [])

    def test_admin_read_rejects_dns_rebinding_host(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(
                "/api/v1/admin/device-corpus/profiles",
                headers={"Host": "attacker.example"},
            )
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_admin_rejects_unapproved_tailscale_identity(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(
                "/api/v1/admin/device-corpus/profiles",
                headers={"Tailscale-User-Login": "viewer@example.com"},
            )
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_admin_rejects_missing_tailscale_identity_by_default(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(
                "/api/v1/admin/device-corpus/profiles",
                headers={"Tailscale-User-Login": ""},
            )
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_explicit_local_admin_bypass_requires_loopback_client(self):
        handler = object.__new__(serve.Handler)
        handler.headers = {"Host": "localhost:8787"}

        with (
            mock.patch.object(serve, "ALLOW_LOCAL_ADMIN", True),
            mock.patch.object(
                serve, "ALLOWED_ADMIN_HOSTS", frozenset(("localhost:8787",))
            ),
            mock.patch.object(
                serve, "LOCAL_ADMIN_HOSTS", frozenset(("localhost:8787",))
            ),
        ):
            handler.client_address = ("127.0.0.1", 49152)
            self.assertTrue(handler._authorized_admin_client())

            handler.client_address = ("192.0.2.25", 49152)
            self.assertFalse(handler._authorized_admin_client())

    def test_admin_bearer_never_follows_upstream_redirect(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open("/api/v1/admin/device-corpus/audit")
        self.assertEqual(caught.exception.code, 502)
        caught.exception.close()
        self.assertEqual(len(self.upstream.calls), 1)
        self.assertEqual(
            self.upstream.calls[0]["authorization"], "Bearer " + "a" * 32
        )
        self.assertEqual(self.upstream.calls[0]["path"], "/api/v1/admin/device-corpus/audit")

    def test_upstream_http_error_body_is_closed_after_forwarding(self):
        body = io.BytesIO(b'{"error":"rate limited"}')
        error = urllib.error.HTTPError(
            "http://127.0.0.1/status",
            429,
            "Too Many Requests",
            {"Content-Type": "application/json", "Retry-After": "3"},
            body,
        )
        with mock.patch.object(serve, "UPSTREAM_OPENER", RaisingOpener(error)):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.open("/api/v1/status")
            self.assertEqual(caught.exception.code, 429)
            self.assertEqual(caught.exception.read(), b'{"error":"rate limited"}')
            caught.exception.close()

        self.assertTrue(body.closed)

    def test_oversized_upstream_http_error_body_is_closed(self):
        body = io.BytesIO(b"x" * 9)
        error = urllib.error.HTTPError(
            "http://127.0.0.1/status",
            500,
            "Internal Server Error",
            {"Content-Type": "application/json"},
            body,
        )
        with (
            mock.patch.object(serve, "UPSTREAM_OPENER", RaisingOpener(error)),
            mock.patch.object(serve, "MAX_RESPONSE_BYTES", 8),
        ):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.open("/api/v1/status")
            self.assertEqual(caught.exception.code, 502)
            self.assertEqual(
                json.loads(caught.exception.read()),
                {
                    "error": "UPSTREAM_TOO_LARGE",
                    "message": "upstream response exceeded limit",
                },
            )
            caught.exception.close()

        self.assertTrue(body.closed)

    def test_mutation_requires_same_origin_and_action_header(self):
        body = b'{"reason_code":"publish_reviewed"}'
        path = "/api/v1/admin/device-corpus/profiles/profile_1/publish"
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(path, "POST", body, {"Content-Type": "application/json"})
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

        headers = {
            "Content-Type": "application/json",
            "Origin": self.base,
            "X-Vedetta-Admin-Action": "1",
            "Authorization": "Bearer browser-secret",
            "If-Match": '"profile-etag"',
        }
        with self.open(path, "POST", body, headers) as response:
            self.assertEqual(response.status, 200)
        call = self.upstream.calls[0]
        self.assertEqual(call["authorization"], "Bearer " + "a" * 32)
        self.assertEqual(call["if_match"], '"profile-etag"')
        self.assertIsNone(call["action"])
        self.assertEqual(call["body"], body)

    def test_cross_origin_mutation_is_rejected(self):
        headers = {
            "Content-Type": "application/json",
            "Origin": "https://attacker.example",
            "X-Vedetta-Admin-Action": "1",
        }
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(
                "/api/v1/admin/device-corpus/profiles",
                "POST",
                b'{"labels":{}}',
                headers,
            )
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_route_allowlist_is_exact(self):
        denied = (
            "/api/v1/admin/device-corpus/profiles/profile_1/delete",
            "/api/v1/admin/device-corpus/profiles?token=leak",
            "/api/v1/ingest",
            "/api/v1/admin/tokens",
        )
        for path in denied:
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.open(path)
                caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_body_limit_is_enforced_before_upstream(self):
        headers = {
            "Content-Type": "application/json",
            "Origin": self.base,
            "X-Vedetta-Admin-Action": "1",
        }
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.open(
                "/api/v1/admin/device-corpus/profiles",
                "POST",
                b"x" * (serve.MAX_REQUEST_BYTES + 1),
                headers,
            )
        self.assertEqual(caught.exception.code, 413)
        caught.exception.close()
        self.assertEqual(self.upstream.calls, [])

    def test_dashboard_uses_nonce_and_does_not_contain_admin_token(self):
        with self.open("/") as response:
            body = response.read().decode()
            csp = response.headers["Content-Security-Policy"]
        self.assertNotIn("__CSP_NONCE__", body)
        self.assertNotIn("a" * 32, body)
        self.assertIn("script-src 'nonce-", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))


class ConfigurationTests(unittest.TestCase):
    def test_new_corpus_routes_remain_exactly_scoped(self):
        self.assertTrue(
            serve._is_admin_route(
                "POST",
                "/api/v1/admin/device-corpus/variants/variant_1/discard-draft",
            )
        )
        self.assertTrue(
            serve._is_admin_route(
                "GET", "/api/v1/admin/device-corpus/releases/12"
            )
        )
        self.assertFalse(
            serve._is_admin_route(
                "GET", "/api/v1/admin/device-corpus/releases/12/anything"
            )
        )
        self.assertTrue(
            serve._is_admin_route(
                "GET", "/api/v1/admin/device-corpus/profiles/profile_1/preview"
            )
        )
        self.assertFalse(
            serve._is_admin_route(
                "POST", "/api/v1/admin/device-corpus/profiles/profile_1/preview"
            )
        )

    def test_dashboard_captures_editor_etag_and_previews_before_publish(self):
        dashboard = Path(__file__).with_name("dashboard.html").read_text()
        self.assertIn("baseETag:baseETag", dashboard)
        self.assertIn("/preview", dashboard)
        self.assertIn("publishCapturedPreview", dashboard)
        self.assertIn("expected_corpus_revision:preview.currentRevision", dashboard)
        self.assertIn("errorValue.message||errorValue.code", dashboard)
        self.assertIn("current-to-proposed", dashboard.lower())
        self.assertIn("reviewedCorpusRevision", dashboard)
        self.assertEqual(
            dashboard.count("expected_corpus_revision:expectedRevision"), 2
        )
        self.assertIn('error.code==="CORPUS_ADVANCED"', dashboard)
        self.assertIn(
            'body:{reason_code:"signal_correction"}', dashboard
        )
        self.assertFalse(
            serve._is_admin_route(
                "POST", "/api/v1/admin/device-corpus/releases/12"
            )
        )

    def test_upstreams_must_be_explicit_loopback_origins(self):
        for value in ("http://127.0.0.1:9090", "https://[::1]:9091"):
            self.assertEqual(serve._loopback_url(value, "test"), value)
        for value in (
            "https://feed.vedettas.com",
            "http://localhost:9090",
            "http://198.51.100.2:9090",
            "http://127.0.0.1:9090/api",
            "http://user@127.0.0.1:9090",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                serve._loopback_url(value, "test")

    def test_invalid_integer_environment_values_fail_closed(self):
        name = "VED_TEST_INTEGER"
        previous = os.environ.get(name)
        try:
            os.environ[name] = "not-an-integer"
            self.assertEqual(serve._environment_int(name, 10), -1)
        finally:
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous

    def test_token_file_requires_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory, "token")
            token.write_bytes(b"b" * 32 + b"\n")
            os.chmod(token, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(serve._load_admin_token(str(token)), b"b" * 32)
            os.chmod(token, 0o644)
            with self.assertRaises(ValueError):
                serve._load_admin_token(str(token))
            link = Path(directory, "link")
            link.symlink_to(token)
            with self.assertRaises(ValueError):
                serve._load_admin_token(str(link))


if __name__ == "__main__":
    unittest.main()
