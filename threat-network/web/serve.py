#!/usr/bin/env python3
"""Tailnet-only Vedetta Threat Network operations dashboard.

This is deliberately a small, dependency-free boundary rather than a general
reverse proxy.  Public reads go to the public threat-network listener.  Corpus
management calls go to a separate loopback-only listener and receive the admin
bearer token here, on the server.  The token is never sent to dashboard HTML or
JavaScript.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _environment_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return -1


HERE = os.path.dirname(os.path.abspath(__file__))
PORT = _environment_int("MON_PORT", 8787)
PUBLIC_UPSTREAM = os.environ.get(
    "MON_PUBLIC_UPSTREAM", os.environ.get("MON_UPSTREAM", "http://127.0.0.1:9090")
).rstrip("/")
ADMIN_UPSTREAM = os.environ.get(
    "MON_ADMIN_UPSTREAM", "http://127.0.0.1:9091"
).rstrip("/")
ADMIN_TOKEN_FILE = os.environ.get("MON_ADMIN_TOKEN_FILE", "")
DASHBOARD = os.environ.get("MON_DASHBOARD", os.path.join(HERE, "dashboard.html"))
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = _environment_int("MON_MAX_RESPONSE_BYTES", 16 * 1024 * 1024)
MAX_RESPONSE_BYTES_CEILING = 32 * 1024 * 1024
_DEFAULT_ORIGINS = "http://127.0.0.1:%d,http://localhost:%d" % (PORT, PORT)
ALLOWED_ORIGINS = tuple(
    item.strip().rstrip("/")
    for item in os.environ.get("MON_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if item.strip()
)
ALLOWED_ADMIN_HOSTS = frozenset(
    urllib.parse.urlsplit(origin).netloc.lower() for origin in ALLOWED_ORIGINS
)
LOCAL_ADMIN_HOSTS = frozenset(("127.0.0.1:%d" % PORT, "localhost:%d" % PORT))
ALLOWED_TAILSCALE_USERS = frozenset(
    item.strip().lower()
    for item in os.environ.get("MON_ALLOWED_TAILSCALE_USERS", "").split(",")
    if item.strip()
)
_LOCAL_ADMIN_SETTING = os.environ.get("MON_ALLOW_LOCAL_ADMIN", "false").lower()
ALLOW_LOCAL_ADMIN = _LOCAL_ADMIN_SETTING == "true"

ID = r"[A-Za-z0-9_-]{1,128}"
PUBLIC_ROUTES = {
    ("GET", "/api/v1/status"),
    ("GET", "/api/v1/feed/community"),
    ("GET", "/api/v1/device-corpus/manifest"),
    ("GET", "/api/v1/device-corpus/snapshot"),
}
ADMIN_ROUTES = (
    (re.compile(r"^/api/v1/admin/device-corpus/profiles$"), {"GET", "POST"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/profiles/{ID}$"), {"GET", "PUT"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/profiles/{ID}/preview$"), {"GET"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/profiles/{ID}/variants$"), {"POST"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/profiles/{ID}/(?:publish|retire)$"), {"POST"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/variants/{ID}$"), {"PUT"}),
    (re.compile(rf"^/api/v1/admin/device-corpus/variants/{ID}/(?:discard-draft|withdraw)$"), {"POST"}),
    (re.compile(r"^/api/v1/admin/device-corpus/(?:audit|releases)$"), {"GET"}),
    (re.compile(r"^/api/v1/admin/device-corpus/releases/[1-9][0-9]{0,18}$"), {"GET"}),
)
MUTATING_METHODS = {"POST", "PUT"}
LIST_QUERY_KEYS = {
    "/api/v1/admin/device-corpus/profiles": frozenset(("limit", "offset", "search")),
    "/api/v1/admin/device-corpus/audit": frozenset(("limit", "offset")),
    "/api/v1/admin/device-corpus/releases": frozenset(("limit", "offset")),
}
MAX_QUERY_BYTES = 1024
MAX_SEARCH_CHARS = 128
MAX_OFFSET = (1 << 63) - 1


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Never honor process-wide proxy settings and never follow an upstream redirect.
# Both properties are load-bearing for keeping the injected admin bearer local.
UPSTREAM_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect()
)


def _loopback_url(value: str, name: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"{name} must be an http(s) URL")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
        raise ValueError(f"{name} must contain only scheme, host, and port")
    host = parsed.hostname.rstrip(".").lower()
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise ValueError(f"{name} must use a literal loopback address")
    return value


def _load_admin_token(path: str) -> bytes | None:
    if not path:
        return None
    info = os.stat(path, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("MON_ADMIN_TOKEN_FILE must be a regular file, not a symlink")
    if os.name == "posix" and info.st_mode & 0o077:
        raise ValueError("MON_ADMIN_TOKEN_FILE must not be readable by group or others")
    with open(path, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ValueError("MON_ADMIN_TOKEN_FILE changed while it was opened")
        if os.name == "posix" and opened.st_mode & 0o077:
            raise ValueError("MON_ADMIN_TOKEN_FILE must not be readable by group or others")
        token = handle.read(4097).strip()
    if len(token) < 32 or len(token) > 4096 or b"\x00" in token:
        raise ValueError("MON_ADMIN_TOKEN_FILE must contain a 256-bit-or-stronger token")
    try:
        encoded = token.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("MON_ADMIN_TOKEN_FILE must use an ASCII token encoding") from error
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in encoded):
        raise ValueError("MON_ADMIN_TOKEN_FILE contains an invalid bearer-token character")
    return token


def _is_admin_route(method: str, path: str) -> bool:
    return any(pattern.fullmatch(path) and method in methods for pattern, methods in ADMIN_ROUTES)


def _is_admin_path(path: str) -> bool:
    return path.startswith("/api/v1/admin/device-corpus/")


def _read_limited(response, limit: int) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("upstream response exceeds configured limit")
    return data


def _forwarded_header_value(
    headers, name: str, default: str | None = None
) -> str | None:
    """Return one bounded upstream header value or reject unsafe bytes."""
    value = headers.get(name, default)
    if value is None or value == "":
        return None
    if (
        not isinstance(value, str)
        or "\r" in value
        or "\n" in value
        or "\x00" in value
    ):
        raise ValueError("unsafe upstream response header")
    return value[:512]


def _validated_query(method: str, path: str, raw_query: str) -> str:
    """Return a canonical allowlisted query or reject it.

    Only the three paged management collections accept queries. Rebuilding the
    query from decoded values prevents ambiguous encodings and ensures the
    upstream never receives a caller-selected duplicate or unknown key.
    """
    if not raw_query:
        return ""
    allowed = LIST_QUERY_KEYS.get(path) if method == "GET" else None
    if allowed is None or len(raw_query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ValueError("query is not allowed for this route")
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw_query):
        raise ValueError("query contains invalid percent encoding")
    try:
        pairs = urllib.parse.parse_qsl(
            raw_query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=len(allowed),
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("query is malformed") from error
    values: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in values:
            raise ValueError("query contains an unknown or duplicate key")
        values[key] = value
    for name in ("limit", "offset"):
        if name not in values:
            continue
        value = values[name]
        if not re.fullmatch(r"0|[1-9][0-9]*", value):
            raise ValueError(f"{name} must be a decimal integer")
        number = int(value)
        if name == "limit" and not 1 <= number <= 100:
            raise ValueError("limit must be between 1 and 100")
        if name == "offset" and number > MAX_OFFSET:
            raise ValueError("offset is too large")
    if "search" in values:
        search = values["search"]
        if len(search) > MAX_SEARCH_CHARS or any(mark in search for mark in ("\r", "\n", "\x00")):
            raise ValueError("search must be at most 128 characters without control delimiters")
    ordered = ((key, values[key]) for key in ("limit", "offset", "search") if key in values)
    return urllib.parse.urlencode(tuple(ordered), doseq=False)


class Handler(BaseHTTPRequestHandler):
    server_version = "vedetta-operations/2.0"
    sys_version = ""

    def _security_headers(self, nonce: str | None = None) -> None:
        script = f"'nonce-{nonce}'" if nonce else "'none'"
        style = f"'nonce-{nonce}'" if nonce else "'none'"
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; "
            f"script-src {script}; style-src {style}; connect-src 'self'; "
            "img-src 'self'; font-src 'none'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _json_error(self, status: int, code: str, message: str) -> None:
        body = json.dumps({"error": code, "message": message}, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_dashboard(self) -> None:
        try:
            with open(DASHBOARD, "rb") as handle:
                template = handle.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            self._json_error(500, "DASHBOARD_UNAVAILABLE", "dashboard asset unavailable")
            return
        if len(template) > MAX_RESPONSE_BYTES:
            self._json_error(500, "DASHBOARD_TOO_LARGE", "dashboard asset exceeds limit")
            return
        nonce = base64.b64encode(secrets.token_bytes(18)).decode("ascii")
        body = template.replace(b"__CSP_NONCE__", nonce.encode("ascii"))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers(nonce)
        self.end_headers()
        self.wfile.write(body)

    def _same_origin_mutation(self) -> bool:
        if not hmac.compare_digest(self.headers.get("X-Vedetta-Admin-Action", ""), "1"):
            return False
        if self.headers.get("Sec-Fetch-Site", "") not in ("", "same-origin"):
            return False
        origin = self.headers.get("Origin", "")
        host = self.headers.get("Host", "")
        try:
            parsed = urllib.parse.urlsplit(origin)
        except ValueError:
            return False
        if (
            parsed.scheme not in ("http", "https")
            or parsed.username
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            return False
        normalized = origin.rstrip("/")
        return (
            bool(host)
            and hmac.compare_digest(parsed.netloc.lower(), host.lower())
            and any(hmac.compare_digest(normalized, allowed) for allowed in ALLOWED_ORIGINS)
        )

    def _authorized_admin_client(self) -> bool:
        """Require an allowed Tailscale identity (or explicit local-dev mode)."""
        host = self.headers.get("Host", "").lower()
        if not host or host not in ALLOWED_ADMIN_HOSTS:
            return False
        login = self.headers.get("Tailscale-User-Login", "").strip().lower()
        if login:
            return login in ALLOWED_TAILSCALE_USERS
        if not ALLOW_LOCAL_ADMIN or host not in LOCAL_ADMIN_HOSTS:
            return False
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def _request_body(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._json_error(411, "LENGTH_REQUIRED", "Content-Length is required")
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._json_error(400, "BAD_LENGTH", "invalid Content-Length")
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._json_error(413, "BODY_TOO_LARGE", "request body exceeds 64 KiB")
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._json_error(415, "JSON_REQUIRED", "Content-Type must be application/json")
            return None
        data = self.rfile.read(length)
        if len(data) != length:
            self._json_error(400, "INCOMPLETE_BODY", "request body was incomplete")
            return None
        return data

    def _proxy(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
        except ValueError:
            self._json_error(403, "ROUTE_DENIED", "path is not proxyable")
            return
        if parsed.fragment or not parsed.path.startswith("/api/"):
            self._json_error(403, "ROUTE_DENIED", "path is not proxyable")
            return
        path = parsed.path
        is_public = (self.command, path) in PUBLIC_ROUTES
        is_admin = _is_admin_route(self.command, path)
        if not is_public and not is_admin:
            status = 405 if _is_admin_path(path) else 403
            self._json_error(status, "ROUTE_DENIED", "method or path is not proxyable")
            return
        try:
            query = _validated_query(self.command, path, parsed.query)
        except ValueError:
            self._json_error(403, "ROUTE_DENIED", "query is not proxyable")
            return
        if is_admin and not self._authorized_admin_client():
            self._json_error(403, "CURATOR_REQUIRED", "authorized curator identity required")
            return
        body = None
        if self.command in MUTATING_METHODS:
            if not self._same_origin_mutation():
                self._json_error(403, "CSRF_REJECTED", "same-origin admin action required")
                return
            body = self._request_body()
            if body is None:
                return
        upstream = PUBLIC_UPSTREAM if is_public else ADMIN_UPSTREAM
        token = None if is_public else getattr(self.server, "admin_token", None)
        if is_admin and token is None:
            self._json_error(503, "ADMIN_DISABLED", "management proxy is not configured")
            return
        target = upstream + path + (("?" + query) if query else "")
        request = urllib.request.Request(target, data=body, method=self.command)
        request.add_header("Accept", "application/json")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if is_admin:
            request.add_header("Authorization", "Bearer " + token.decode("ascii"))
            if_match = self.headers.get("If-Match")
            if if_match:
                request.add_header("If-Match", if_match[:512])
        try:
            with UPSTREAM_OPENER.open(request, timeout=15) as response:
                data = _read_limited(response, MAX_RESPONSE_BYTES)
                self._send_upstream(response.status, response.headers, data)
        except urllib.error.HTTPError as error:
            # HTTPError doubles as the response body. It owns a socket/file
            # object just like a successful response, so close it on every
            # branch, including body-limit and downstream-write failures.
            with error:
                if 300 <= error.code < 400:
                    self._json_error(502, "UPSTREAM_REDIRECT", "upstream redirects are forbidden")
                    return
                try:
                    data = _read_limited(error, MAX_RESPONSE_BYTES)
                except ValueError:
                    self._json_error(502, "UPSTREAM_TOO_LARGE", "upstream response exceeded limit")
                    return
                self._send_upstream(error.code, error.headers, data)
        except (urllib.error.URLError, TimeoutError, ValueError):
            self._json_error(502, "UPSTREAM_UNAVAILABLE", "upstream service unavailable")

    def _send_upstream(self, status: int, headers, data: bytes) -> None:
        try:
            content_type = _forwarded_header_value(
                headers, "Content-Type", "application/json; charset=utf-8"
            )
            forwarded_headers = tuple(
                (name, value)
                for name in ("ETag", "Last-Modified", "Retry-After")
                if (value := _forwarded_header_value(headers, name)) is not None
            )
        except ValueError:
            self._json_error(502, "UPSTREAM_HEADERS", "upstream returned invalid headers")
            return
        if not content_type or not content_type.lower().startswith("application/json"):
            self._json_error(502, "UPSTREAM_CONTENT_TYPE", "upstream did not return JSON")
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in forwarded_headers:
            self.send_header(name, value)
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
        except ValueError:
            # BaseHTTPRequestHandler accepts some malformed absolute-form
            # targets that urlsplit rejects (for example an unmatched IPv6
            # bracket). Treat them as an opaque client error instead of
            # letting the request thread terminate with a traceback.
            self._json_error(400, "INVALID_TARGET", "invalid request target")
            return
        if parsed.path.startswith("/api/"):
            self._proxy()
        elif not parsed.query and parsed.path in ("/", "/index.html", "/dashboard.html"):
            self._send_dashboard()
        else:
            self._json_error(404, "NOT_FOUND", "resource not found")

    def do_POST(self) -> None:
        self._proxy()

    def do_PUT(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._json_error(405, "METHOD_NOT_ALLOWED", "DELETE is not supported")

    def do_OPTIONS(self) -> None:
        self._json_error(405, "METHOD_NOT_ALLOWED", "cross-origin requests are not supported")

    def log_message(self, fmt: str, *args) -> None:
        # BaseHTTPRequestHandler's default request line contains the raw query.
        # Log only the already-separated path; never headers, bodies, queries,
        # upstream credentials, or attacker-controlled error strings.
        command = getattr(self, "command", None)
        raw_path = getattr(self, "path", None)
        if not isinstance(command, str) or not isinstance(raw_path, str):
            # parse_request() can reject a malformed request line before it
            # assigns command/path, then call log_message() while producing its
            # standard 400 response. Keep that error path safe and opaque.
            sys.stderr.write("%s - <malformed-request>\n" % self.client_address[0])
            return
        try:
            path = urllib.parse.urlsplit(raw_path).path
        except ValueError:
            path = "<invalid-path>"
        sys.stderr.write("%s - %s %s\n" % (self.client_address[0], command, path))


def main() -> None:
    try:
        if not 1 <= PORT <= 65_535:
            raise ValueError("MON_PORT must be an integer between 1 and 65535")
        if not 1 <= MAX_RESPONSE_BYTES <= MAX_RESPONSE_BYTES_CEILING:
            raise ValueError("MON_MAX_RESPONSE_BYTES must be between 1 and 33554432")
        _loopback_url(PUBLIC_UPSTREAM, "MON_PUBLIC_UPSTREAM")
        _loopback_url(ADMIN_UPSTREAM, "MON_ADMIN_UPSTREAM")
        if not ALLOWED_ORIGINS:
            raise ValueError("MON_ALLOWED_ORIGINS must name at least one exact origin")
        if _LOCAL_ADMIN_SETTING not in ("true", "false"):
            raise ValueError("MON_ALLOW_LOCAL_ADMIN must be true or false")
        for origin in ALLOWED_ORIGINS:
            parsed = urllib.parse.urlsplit(origin)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("MON_ALLOWED_ORIGINS contains an invalid origin")
        token = _load_admin_token(ADMIN_TOKEN_FILE)
        if token and not ALLOWED_TAILSCALE_USERS and not ALLOW_LOCAL_ADMIN:
            raise ValueError(
                "set MON_ALLOWED_TAILSCALE_USERS or explicitly enable local admin"
            )
    except (OSError, ValueError) as error:
        sys.stderr.write(f"vedetta-operations: configuration error: {error}\n")
        raise SystemExit(2)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.admin_token = token
    admin_state = "enabled" if token else "disabled"
    sys.stderr.write(
        "vedetta-operations: http://127.0.0.1:%d -> public %s; admin %s (%s); "
        "publish with tailnet-only HTTPS\n"
        % (PORT, PUBLIC_UPSTREAM, ADMIN_UPSTREAM, admin_state)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
