#!/usr/bin/env python3
"""Static + reverse-proxy shim for the Vedetta threat-network monitor dashboard.

Serves dashboard.html at "/" and reverse-proxies "/api/*" to the local
threat-network API. This gives the dashboard a *same-origin* API (no CORS) and
keeps the whole thing on localhost so `tailscale serve` can publish it to the
tailnet only — it is never reachable through the public Cloudflare tunnel.

Zero dependencies (Python 3 stdlib only). Binds 127.0.0.1 by design.

    python3 serve.py                     # :8787  ->  api at 127.0.0.1:9090
    MON_PORT=8080 MON_UPSTREAM=http://127.0.0.1:9090 python3 serve.py

Then expose it on the tailnet (management-only):
    tailscale serve --bg 8787
"""
import os
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(__file__) or "."
PORT = int(os.environ.get("MON_PORT", "8787"))
UPSTREAM = os.environ.get("MON_UPSTREAM", "http://127.0.0.1:9090").rstrip("/")
# MON_DASHBOARD lets an operator point at an explicit file; default is the
# dashboard.html sitting next to this script.
DASHBOARD = os.environ.get("MON_DASHBOARD", os.path.join(HERE, "dashboard.html"))
# Only these upstream path prefixes may be proxied — deny everything else so the
# shim can never be turned into an open forward-proxy.
ALLOW_PREFIXES = ("/api/v1/status", "/api/v1/feed/")


class Handler(BaseHTTPRequestHandler):
    server_version = "vedetta-monitor/1.0"

    def _send_dashboard(self):
        try:
            with open(DASHBOARD, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(500, "dashboard.html not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self):
        if not self.path.startswith(ALLOW_PREFIXES):
            self.send_error(403, "path not proxyable")
            return
        target = UPSTREAM + self.path
        req = urllib.request.Request(target, method="GET")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as up:
                data = up.read()
                self.send_response(up.status)
                self.send_header("Content-Type",
                                 up.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type",
                             e.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:  # upstream down / timeout
            self.send_error(502, "upstream unreachable: %s" % e)

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._proxy()
        elif self.path in ("/", "/index.html", "/dashboard.html"):
            self._send_dashboard()
        else:
            self.send_error(404, "not found")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write(
        "vedetta-monitor: http://127.0.0.1:%d  ->  api %s  (tailnet-only via `tailscale serve`)\n"
        % (PORT, UPSTREAM))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
