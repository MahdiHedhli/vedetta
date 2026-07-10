# Threat-network monitor dashboard

A tiny, self-contained web dashboard for the threat-network JSON API
(`/api/v1/status` + `/api/v1/feed/community`). Read-only and advisory-only.
Intended to be served **tailnet-only** (or behind your own reverse proxy / auth) —
it is never exposed to the public internet and never touches the public feed's
Cloudflare tunnel.

## Files

- **`dashboard.html`** — a single self-contained page (inline CSS/JS, no external
  dependencies, no analytics). Fetches the API same-origin by default; you can
  point it elsewhere with the "API base" field or a `?api=` query parameter.
- **`serve.py`** — a zero-dependency (Python 3 stdlib only) static-file +
  reverse-proxy shim. It serves `dashboard.html` at `/` and proxies **only**
  `/api/v1/status` and `/api/v1/feed/*` to the local threat-network API — every
  other path is refused, so it can't be turned into an open proxy. Binds
  `127.0.0.1` by design.

## Run locally

```sh
python3 serve.py          # http://127.0.0.1:8787  ->  api at 127.0.0.1:9090
```

Environment overrides: `MON_PORT`, `MON_UPSTREAM`, `MON_DASHBOARD`.

## Deploy tailnet-only (recommended)

On the node running the threat-network (its API on `127.0.0.1:9090`):

1. Copy `dashboard.html` + `serve.py` to the node (e.g. `~/vedetta-dashboard/`).
2. Run the shim as a service — example systemd unit:

   ```ini
   [Unit]
   Description=Vedetta threat-network monitor dashboard (tailnet-only)
   After=network-online.target
   Wants=network-online.target

   [Service]
   Environment=MON_PORT=8787
   Environment=MON_UPSTREAM=http://127.0.0.1:9090
   Environment=MON_DASHBOARD=/home/<user>/vedetta-dashboard/dashboard.html
   ExecStart=/usr/bin/python3 /home/<user>/vedetta-dashboard/serve.py
   Restart=always
   User=<user>

   [Install]
   WantedBy=multi-user.target
   ```

3. Publish it on your tailnet over HTTPS (tailnet-only):

   ```sh
   sudo tailscale serve --bg 8787
   ```

   The dashboard is then reachable at `https://<node>.<your-tailnet>.ts.net/`. It
   stays on the tailnet; nothing is published to the public internet. Requires
   Tailscale SSH/serve access and HTTPS certificates enabled on your tailnet.
