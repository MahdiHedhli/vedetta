# Reverse Proxy & TLS

Vedetta Core speaks plain HTTP and, by default, **binds to loopback only**
(`127.0.0.1`). That is the safe default: on a bare-metal / host-network install
nothing on your LAN can reach Core directly, so an unauthenticated device can't
poke the API before you've finished setup. To reach Core from another machine you
put a **reverse proxy** in front of it — one that terminates TLS and forwards
requests to Core.

> **Why not just bind Core to `0.0.0.0` and expose it?** Core serves the dashboard
> and API over HTTP with **bearer-token** auth. Exposing it directly means tokens
> and data travel in clear text on your LAN. A reverse proxy gives you HTTPS.

---

## 1. The listen address

Core's bind address is controlled by one environment variable:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VEDETTA_LISTEN_ADDR` | `127.0.0.1` | Interface Core binds. Loopback by default. |
| `VEDETTA_PORT` | `8080` | TCP port Core listens on. |

So out of the box Core listens on `127.0.0.1:8080`.

```sh
# Bare-metal / systemd: still loopback (recommended; proxy runs on the same host)
VEDETTA_LISTEN_ADDR=127.0.0.1 VEDETTA_PORT=8080 ./vedetta

# Bind a specific internal interface (only if the proxy is on another host).
# Replace 10.0.0.5 with an IP your host actually has on that interface.
VEDETTA_LISTEN_ADDR=10.0.0.5 ./vedetta

# Bind all interfaces — do this ONLY behind a firewall or trusted network
VEDETTA_LISTEN_ADDR=0.0.0.0 ./vedetta
```

> **Docker is different — and already handled.** Inside a container, `127.0.0.1`
> refers to the container itself, so a loopback bind is unreachable through Docker's
> published port and from sibling containers. `docker-compose.yml` therefore sets
> `VEDETTA_LISTEN_ADDR=0.0.0.0` for the backend service. That is safe **only because
> the compose network is internal** — see §4 for how to keep Core unpublished.

---

## 2. Core's auth model — and what NOT to add in front of it

Core authenticates with a **bearer token**: every dashboard and API request carries
`Authorization: Bearer <token>`. The dashboard sends it automatically; sensors and
scripts send it explicitly.

> ⚠️ **Do NOT put HTTP Basic auth in front of Core.** Basic auth also uses the
> `Authorization` header (`Authorization: Basic …`). A browser request can carry
> only **one** `Authorization` header, so a Basic-auth layer and Core's Bearer
> auth collide: the proxy either consumes/rewrites the Bearer (Core then rejects
> the request) or forwards Basic (also rejected). This guide previously suggested
> Basic auth — that was wrong; use one of the composable controls below instead.

The proxy's only job for auth is to **preserve the `Authorization: Bearer` header
untouched** and terminate TLS. If you want an *additional* outer control, pick one
that does not touch the `Authorization` header:

- **Network policy (simplest, recommended).** Only publish the proxy on a trusted
  surface — your LAN, a VPN, or a tailnet — and IP-allowlist at the proxy. Core's
  bearer auth is then your app-layer control and TLS is your transport control.
- **A cookie/session auth proxy (advanced, browser only).** A forward-auth proxy
  (e.g. oauth2-proxy) that gates *browser* access with a **cookie** — never the
  `Authorization` header — can sit in front. Ensure it passes `Authorization`
  through verbatim. This only gates the dashboard, not the native sensor.

> **Not available: sensor mTLS.** The native `vedetta-sensor` cannot present a
> client certificate today (there is no client-cert flag/config), so do **not**
> require mutual TLS at the proxy on any endpoint a sensor uses — it would lock
> the sensor out. mTLS as a proxy control is only workable for a browser/admin
> surface that never carries sensor traffic. Use network policy for remote
> sensors instead.

---

## 3. Proxy examples (TLS, bearer preserved)

**Proxy the FRONTEND, not the API-only backend.** In the Docker deployment Core
(`backend`, port 8080) serves only the JSON API — it does not serve the dashboard
HTML. The `frontend` container both **serves the dashboard** and **proxies `/api/*`
to Core** on the same origin, so pointing your TLS proxy at the frontend gives you
the whole journey (dashboard + API) over HTTPS. Pointing it at `8080` would serve
the API but no dashboard.

Assumptions: the **frontend** container is published loopback-only at
`127.0.0.1:3107` (the default — `${VEDETTA_FRONTEND_PORT:-3107}`); your public
hostname is `vedetta.example.com` (replace with your own). If you followed §4 to
keep Core unpublished, the frontend is republished at `127.0.0.1:8088` instead —
use that port below.

> With the default Compose mapping, use the effective `VEDETTA_FRONTEND_PORT` in
> place of `3107` below when it differs from the default, whether it was selected
> automatically or configured explicitly. Retrieve the value without sourcing
> `.env`: `./scripts/resolve-host-port.sh VEDETTA_FRONTEND_PORT 3107`. If you use
> the §4 override, keep its fixed `8088` port instead; that override intentionally
> replaces the normal `VEDETTA_FRONTEND_PORT` mapping.

### Option A — Caddy (automatic HTTPS)

```caddy
vedetta.example.com {
    # Terminate TLS (Caddy provisions the cert automatically) and forward to the
    # FRONTEND, which serves the dashboard and proxies /api/* to Core, preserving
    # the Authorization: Bearer header. NO basic_auth here.
    reverse_proxy 127.0.0.1:3107

    # Optional outer control — network policy (allow only your LAN/VPN):
    @untrusted not remote_ip 10.0.0.0/8 192.168.0.0/16 100.64.0.0/10
    respond @untrusted 403

    # NOTE: Do not add client-certificate (mTLS) enforcement here — the native
    # sensor cannot present a client cert and would be locked out. Use network
    # policy (above) instead.
}
```

### Option B — nginx (bring your own certificate)

```nginx
server {
    listen 443 ssl;
    server_name vedetta.example.com;

    ssl_certificate     /etc/ssl/certs/vedetta.example.com.crt;
    ssl_certificate_key /etc/ssl/private/vedetta.example.com.key;

    # NOTE: Do not enable client-certificate (mTLS) enforcement
    # (ssl_verify_client on) on endpoints a sensor uses — the native sensor
    # cannot present a client cert and would be locked out. Use network policy
    # below as the outer control instead.

    # Optional network policy:
    # allow 10.0.0.0/8; allow 192.168.0.0/16; deny all;

    location / {
        # Forward to the FRONTEND (serves the dashboard + proxies /api/* to Core),
        # NOT the API-only backend on 8080.
        proxy_pass http://127.0.0.1:3107;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Preserve Core's bearer auth — do NOT add proxy_set_header Authorization.
    }
}

# Redirect plain HTTP to HTTPS.
server { listen 80; server_name vedetta.example.com; return 301 https://$host$request_uri; }
```

---

## 4. Compose topology: keep Core unpublished

For a Docker deployment, do **not** publish Core's port on the host. Let the
frontend container (which already proxies `/api` to Core over the internal
network) and your TLS proxy be the only ingress.

```yaml
# docker-compose.override.yml  (requires Docker Compose v2.24.4+ for the !reset/!override tags)
services:
  backend:
    # Compose MERGES the `ports` list across files by APPENDING — an empty
    # `ports: []` would leave the base "8080:8080" mapping in place, so Core would
    # stay published. The `!reset` tag actually drops the base list, leaving Core
    # with NO host port: reachable only on the internal network as http://backend:8080.
    ports: !reset []
  frontend:
    # Your TLS proxy (Caddy/nginx) terminates HTTPS and forwards to the frontend,
    # which serves the dashboard and proxies /api/* to backend:8080 same-origin.
    # `!override` REPLACES the base mapping (which binds ${VEDETTA_FRONTEND_PORT:-3107}
    # on ALL interfaces, i.e. the LAN) instead of appending to it. Republish
    # loopback-only, and target the frontend's actual listen port 3000 — nginx in
    # the frontend image listens on 3000 (see frontend/nginx.conf and Dockerfile),
    # NOT 80.
    ports: !override
      - "127.0.0.1:8088:3000"   # proxy connects here; not exposed to the LAN directly
```

- Core is reachable only on the internal `vedetta` network (`http://backend:8080`) —
  no host port at all.
- The dashboard is published on `127.0.0.1:8088` only; point your TLS proxy at it
  (e.g. `reverse_proxy 127.0.0.1:8088` / `proxy_pass http://127.0.0.1:8088;`), not
  the LAN. The frontend then proxies `/api/*` to `backend:8080` over the internal
  network.
- Sensors reach Core through the **HTTPS** proxy endpoint, not a plaintext port.

> **Why the `!reset` / `!override` tags?** Compose does not replace list-valued
> keys like `ports` in an override file — it concatenates them. Without these tags
> the base LAN-facing publications survive and the "keep Core unpublished" goal
> silently fails. If your Compose predates v2.24.4, instead edit the base
> `docker-compose.yml` to remove/loopback-bind those `ports:` entries directly.

---

## 5. CORS / split-origin

`VITE_CORE_BASE` lets the dashboard target a Core at a different base URL. **Keep
the dashboard and API on the same origin** (the default: the frontend serves the
UI and proxies `/api` to Core). A genuinely *cross-origin* Core does **not** work
today: attaching `Authorization` triggers a CORS preflight, and Core does not yet
implement CORS/OPTIONS. Until it does, treat `VITE_CORE_BASE` as a same-origin
proxy convenience, not a cross-origin split-deployment feature.

---

## 6. Native sensors: certificate trust

A native `vedetta-sensor` connecting over HTTPS validates the proxy's certificate
against the **host system CA store** — that is the only trust mechanism today.
**There is no in-app `--cacert` flag** and no way to point the sensor at a custom
CA bundle from the command line; trust is managed at the OS level.

- **Public CA (Let's Encrypt via Caddy):** trusted automatically by the system CA
  store — nothing to do.
- **Internal CA / self-signed:** install your CA into the **host** trust store
  (e.g. `/usr/local/share/ca-certificates` + `update-ca-certificates` on Linux,
  or the System keychain on macOS) so the sensor's system trust store accepts it.
  Do **not** disable verification in production.

---

## 7. Verify it (smoke test)

Before trusting a deployment, confirm these checks end-to-end:

1. `https://vedetta.example.com` loads the dashboard (TLS valid).
2. An authenticated `GET /api/v1/status` through the proxy returns 200 **with** a
   bearer token and 401 **without** one (bearer preserved through the proxy).
3. An authenticated write (e.g. create a read token) succeeds through the proxy.
4. A sensor registers through the proxy endpoint over HTTPS.
5. **No direct plaintext Core port is reachable** from the LAN:
   - With the default Compose mapping, obtain the actual host port on the Docker
     host with `./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080`. From a
     different LAN machine, `curl http://<host>:<resolved-port>/api/v1/status`
     must fail or be refused.
   - With the §4 override, `docker compose port backend 8080` on the Docker host
     must print no mapping; Core is intentionally unpublished in that topology.

---

## 8. Auth still matters behind the proxy

The reverse proxy handles **transport** (TLS) and an optional outer control. Core's
own **API-token** auth is independent and still applies:

- Create a first **admin** token during setup (the onboarding wizard requires the
  one-time setup code printed to Core's logs on first boot).
- Mint least-privilege **read** tokens for dashboards/scripts (`{"scope":"read"}`) —
  they can query the read endpoints but never write or reach admin routes.
- Once an active admin token exists, unauthenticated reads are rejected.

See **[Backup, Restore & Rollback](backup-restore-rollback.md)** for protecting
those tokens.

> **Placeholders only.** Every hostname, IP, and path above is a documentation
> placeholder (`vedetta.example.com`, `127.0.0.1`, `10.0.0.5`). Substitute your
> own; never commit real ones.
