# Reverse Proxy & TLS

Vedetta Core speaks plain HTTP and, by default, **binds to loopback only**
(`127.0.0.1`). That is the safe default: on a bare-metal / host-network install
nothing on your LAN can reach Core directly, so an unauthenticated device can't
poke the API before you've finished setup. To reach Core from another machine you
put a **reverse proxy** in front of it — one that terminates TLS and (optionally)
adds its own authentication layer.

> **Why not just bind Core to `0.0.0.0` and expose it?** Core serves the dashboard
> and API over HTTP with token auth. Exposing it directly means no TLS (tokens and
> data travel in clear text on your LAN) and no second line of defense. A reverse
> proxy gives you HTTPS and a place to enforce access control in one spot.

---

## 1. The listen address

Core's bind address is controlled by one environment variable:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VEDETTA_LISTEN_ADDR` | `127.0.0.1` | Interface Core binds. Loopback by default. |
| `VEDETTA_PORT` | `8080` | TCP port Core listens on. |

So out of the box Core listens on `127.0.0.1:8080`.

**To change the bind** (for example, to let a reverse proxy on the same host reach
it — which loopback already allows — or to bind a specific internal interface):

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
> published port and from sibling containers (collector, telemetry, frontend).
> `docker-compose.yml` therefore sets `VEDETTA_LISTEN_ADDR=0.0.0.0` for the backend
> service. That is safe because the container is isolated on the internal `vedetta`
> network; only the `8080:8080` host port mapping is exposed, and the other
> services reach Core by its service name (`http://backend:8080`). If you don't want
> Core's port on the host at all, drop the `ports:` mapping from the `backend`
> service and let your proxy talk to it over the compose network.

---

## 2. Put a proxy in front (TLS + auth)

The examples below assume:

- Core is reachable from the proxy at `127.0.0.1:8080` (same host).
- Your public hostname is `vedetta.example.com` (replace with your own).

Pick **one** of the following.

### Option A — Caddy (automatic HTTPS)

Caddy fetches and renews a certificate for you. A minimal `Caddyfile`:

```caddy
vedetta.example.com {
    # Terminate TLS (Caddy provisions the cert automatically) and proxy to Core.
    reverse_proxy 127.0.0.1:8080

    # Optional: gate the whole site behind HTTP Basic auth as a second factor in
    # front of Core's own token auth. Generate the hash with `caddy hash-password`.
    basic_auth {
        operator JDJhJDE0JEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
    }
}
```

Reload with `caddy reload`. Visit `https://vedetta.example.com`.

### Option B — nginx (bring your own certificate)

```nginx
server {
    listen 443 ssl;
    server_name vedetta.example.com;

    # Replace with your certificate paths (Let's Encrypt, internal CA, etc.).
    ssl_certificate     /etc/ssl/certs/vedetta.example.com.crt;
    ssl_certificate_key /etc/ssl/private/vedetta.example.com.key;

    # Optional second-factor auth in front of Core's token auth.
    # Create the file with: htpasswd -c /etc/nginx/.vedetta.htpasswd operator
    auth_basic           "Vedetta";
    auth_basic_user_file /etc/nginx/.vedetta.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect plain HTTP to HTTPS.
server {
    listen 80;
    server_name vedetta.example.com;
    return 301 https://$host$request_uri;
}
```

Reload with `nginx -s reload`.

---

## 3. Auth still matters behind the proxy

The reverse proxy handles **transport** security (TLS) and an optional outer
auth layer. Core's own **API-token** auth is independent and still applies:

- Create a first **admin** token during setup (the onboarding wizard, or
  `POST /api/v1/auth/tokens` while no admin exists yet — the bootstrap window).
- Mint least-privilege **read** tokens for dashboards or scripts that only need
  to view data (`{"scope":"read"}`). A read token can query the read endpoints
  (`GET /status`, `/events`, `/devices`, …) but can never write or reach admin
  routes. An admin token satisfies read routes too.
- Once an active admin token exists, unauthenticated reads are rejected — the
  dashboard and API clients must present a bearer token.

See **[Backup, Restore & Rollback](backup-restore-rollback.md)** for protecting
those tokens (they live in Core's SQLite database).

> **Placeholders only.** Every hostname, IP, and credential above is a
> documentation placeholder (`example.com`, `127.0.0.1`, `operator`). Substitute
> your own values; never commit real ones.
