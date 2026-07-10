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
- **mTLS (best for remote access).** Require a client certificate at the proxy.
  This is a *separate* credential from Core's bearer and does not use the
  `Authorization` header, so there is no collision. Good for remote sensors and
  admins.
- **A cookie/session auth proxy (advanced).** A forward-auth proxy (e.g.
  oauth2-proxy) that gates access with a **cookie** — never the `Authorization`
  header — can sit in front. Ensure it passes `Authorization` through verbatim.

---

## 3. Proxy examples (TLS, bearer preserved)

Assumptions: Core (or the frontend container that proxies `/api` to Core) is
reachable from the proxy at `127.0.0.1:8080`; your public hostname is
`vedetta.example.com` (replace with your own).

### Option A — Caddy (automatic HTTPS)

```caddy
vedetta.example.com {
    # Terminate TLS (Caddy provisions the cert automatically) and forward to Core,
    # preserving the Authorization: Bearer header. NO basic_auth here.
    reverse_proxy 127.0.0.1:8080

    # Optional outer control — network policy (allow only your LAN/VPN):
    @untrusted not remote_ip 10.0.0.0/8 192.168.0.0/16 100.64.0.0/10
    respond @untrusted 403

    # Optional stronger control — require a client cert (mTLS):
    # tls { client_auth { mode require_and_verify trusted_ca_cert_file /etc/ssl/clients-ca.pem } }
}
```

### Option B — nginx (bring your own certificate, optional mTLS)

```nginx
server {
    listen 443 ssl;
    server_name vedetta.example.com;

    ssl_certificate     /etc/ssl/certs/vedetta.example.com.crt;
    ssl_certificate_key /etc/ssl/private/vedetta.example.com.key;

    # Optional mTLS outer control (separate from Core's bearer; no header collision):
    # ssl_client_certificate /etc/ssl/clients-ca.pem;
    # ssl_verify_client on;

    # Optional network policy:
    # allow 10.0.0.0/8; allow 192.168.0.0/16; deny all;

    location / {
        proxy_pass http://127.0.0.1:8080;
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
# docker-compose.override.yml
services:
  backend:
    ports: []          # <- drop the "8080:8080" host mapping; Core stays internal
  frontend:
    # your TLS proxy (Caddy/nginx) terminates HTTPS and forwards to the frontend,
    # which serves the dashboard and proxies /api/* to backend:8080 same-origin.
    ports:
      - "127.0.0.1:8088:80"   # proxy connects here; not exposed to the LAN directly
```

- Core is reachable only on the internal `vedetta` network (`http://backend:8080`).
- Sensors reach Core through the **HTTPS** proxy endpoint, not a plaintext port.

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

A native `vedetta-sensor` connecting over HTTPS must trust the proxy's
certificate:

- **Public CA (Let's Encrypt via Caddy):** trusted automatically by the system CA
  store — nothing to do.
- **Internal CA / self-signed:** install your CA into the host trust store, or
  point the sensor at it (`--cacert /path/to/ca.pem`). Do **not** disable
  verification in production.

---

## 7. Verify it (smoke test)

Before trusting a deployment, confirm end-to-end. `scripts/proxy-smoke.sh` (or by
hand) should check:

1. `https://vedetta.example.com` loads the dashboard (TLS valid).
2. An authenticated `GET /api/v1/status` through the proxy returns 200 **with** a
   bearer token and 401 **without** one (bearer preserved through the proxy).
3. An authenticated write (e.g. create a read token) succeeds through the proxy.
4. A sensor registers through the proxy endpoint over HTTPS.
5. **No direct plaintext Core port is reachable** from the LAN — e.g.
   `curl http://<host>:8080/api/v1/status` from another machine must fail/refuse.

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
