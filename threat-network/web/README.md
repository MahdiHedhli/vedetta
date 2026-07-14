# Threat Network operations dashboard

This directory contains the standalone, tailnet-only operations UI for the
Vedetta Threat Network. It monitors the advisory community feed and curates the
versioned device-fingerprint corpus. It is intentionally maintained on a
separate operations branch; deploying it does not expose it through the public
feed tunnel or require merging the dashboard into `main`.

## Security boundary

`dashboard.html` never receives an admin token. `serve.py` is the credential
boundary and talks to two distinct loopback listeners:

- public, read-only API: `http://127.0.0.1:9090`
- authenticated management API: `http://127.0.0.1:9091`

The shim injects the file-backed bearer token only for an exact allowlist of
device-corpus management routes. It discards caller `Authorization`, accepts no
arbitrary upstream path or query string, limits mutation bodies to 64 KiB, and
returns no CORS headers. The three collection reads accept only one value for
their documented `limit`/`offset` parameters (plus `search` for profiles), with
numeric bounds enforced before a canonical query is sent upstream. Proxy logs
contain method and path only, never query values. Browser mutations additionally require a same-origin
`Origin`/`Host` match and `X-Vedetta-Admin-Action: 1`.

Same-origin is a CSRF control, not curator authentication. Management reads and
writes also require a `Tailscale-User-Login` inserted by Tailscale Serve and
listed in `MON_ALLOWED_TAILSCALE_USERS`. Serve removes caller-supplied identity
headers before setting its own. Tagged devices do not receive a user identity
and are denied. The shim listens only on localhost, which is required for these
headers to be trustworthy; local processes are part of the host trust boundary.

Both upstream URLs must explicitly name a loopback address. Publish only the
dashboard listener (`127.0.0.1:8787`) with Tailscale Serve. Never publish the
management listener itself.

## Corpus workflow

The **Device corpus** view supports:

- page through and server-search the complete profile corpus, with true totals;
- a typed fixed-schema fingerprint editor (no arbitrary JSON/metadata map);
- explicit public sources and version facts;
- firmware/product lineage through predecessor variants;
- draft, publish, withdraw, and retire lifecycle operations;
- a server-validated, ETag-bound current-to-proposed snapshot diff before every
  publish (the accepted action reuses the same captured ETag);
- immutable revision history and an exact view of the currently public
  snapshot entry; and
- corpus-release and management-audit history.

Publishing remains server-authoritative. The preview endpoint performs the same
privacy validation and canonicalization used for publication and returns the
exact proposed profile/variant content (the final release timestamp is assigned
when the transaction commits). The dashboard compares that candidate with the
current public snapshot, shows both the profile-level diff and complete proposed
JSON, then publishes with both the unchanged profile ETag and corpus revision
captured for the preview. An intervening edit to this or any other public profile
is rejected rather than silently publishing a different complete snapshot. The
server creates the immutable release and advances the corpus revision.

Profile retirement and full variant withdrawal are also bound to both the displayed
profile ETag and the public corpus revision in the currently loaded snapshot. If another
profile is published, retired, or withdrawn first, the server returns
`CORPUS_ADVANCED`; the dashboard requires a reload and review before retrying. A
draft-only discard creates no release and intentionally needs only the profile ETag.

The dashboard pages through the complete audit and release histories using
server-reported totals, and can inspect the exact JSON content of every
historical corpus release (pretty-printed for review; the immutable original
bytes remain in SQLite).
There is deliberately no one-click rollback mutation: restoration remains a
reviewed manual recovery operation. A correction draft can be discarded while
retaining its published revision. Full withdrawal is a separate, explicitly
labelled action that removes the logical variant from the next public release.
An abandoned never-published series can be restarted under the same stable ID
to correct its predecessor. A mistaken key can be replaced by a separate new
series; lineage fields become immutable after first publication.

The corpus is curated content, not telemetry. Community reporting and candidate
submission are deliberately absent from this dashboard and its proxy allowlist.
An `import` evidence source is accepted only with an explicit curator-reviewed
redistributable license code; the dashboard makes that field mandatory for the import
source type.

## Run locally

Create a 256-bit-or-stronger token in a private file. The threat-network admin
listener and dashboard shim must read the same file; do not put the token in an
environment variable or command line.

```sh
# From the repository root, build and install the native service binary once.
(cd threat-network && go build -o ./threat-network ./cmd/threat-network)
sudo install -m 0755 threat-network/threat-network /usr/local/bin/threat-network
sudo install -d -m 0755 /opt/vedetta/threat-network/web
sudo install -m 0755 threat-network/web/serve.py /opt/vedetta/threat-network/web/serve.py
sudo install -m 0644 threat-network/web/dashboard.html /opt/vedetta/threat-network/web/dashboard.html

id -u vedetta >/dev/null 2>&1 || \
  sudo useradd --system --user-group --home-dir /var/lib/vedetta --shell /usr/sbin/nologin vedetta
sudo install -d -m 0700 -o vedetta -g vedetta /var/lib/vedetta
sudo -u vedetta sh -c \
  'umask 077; openssl rand -hex 32 > /var/lib/vedetta/threat-network-admin.token'
sudo chmod 600 /var/lib/vedetta/threat-network-admin.token

sudo -u vedetta env \
  THREAT_NETWORK_DB=/var/lib/vedetta/threat-network.db \
  THREAT_NETWORK_ADMIN_ENABLED=true \
  THREAT_NETWORK_ADMIN_ADDR=127.0.0.1:9091 \
  THREAT_NETWORK_ADMIN_TOKEN_FILE=/var/lib/vedetta/threat-network-admin.token \
    /usr/local/bin/threat-network
```

If the backend runs in the repository Compose stack, use the tracked
`docker-compose.corpus-ops.yml` overlay instead of the native command. The
overlay binds `0.0.0.0:9091` only inside the container (required for Docker port
forwarding), opts into that bind explicitly, mounts the private token read-only,
and publishes the port solely on host `127.0.0.1`. The base service uses a
dedicated `threat-network-isolated` bridge, so ordinary Vedetta application
containers cannot reach the management listener directly. This isolated,
host-loopback publication is the only supported plaintext non-loopback bind.
For any management hop that leaves that boundary, terminate authenticated TLS
before it and keep the upstream private; never expose port `9091` directly:

```sh
export THREAT_NETWORK_ADMIN_TOKEN_FILE=/var/lib/vedetta/threat-network-admin.token
docker compose -f docker-compose.yml -f docker-compose.corpus-ops.yml \
  --profile community up -d --build threat-network
```

For a public, read-only local status check, run the installed shim without the
admin token. This process does not receive a management capability and can run
as the calling user:

```sh
MON_PUBLIC_UPSTREAM=http://127.0.0.1:9090 \
  python3 /opt/vedetta/threat-network/web/serve.py
```

Open `http://127.0.0.1:8787/`. The management portion reports `ADMIN_DISABLED`;
public monitoring continues to work. Do not add the token and enable
`MON_ALLOW_LOCAL_ADMIN` on a multi-user or operational host: loopback proves
only that the request came from the same machine, so that development bypass
trusts every local process. Use the tailnet-only deployment below for curator
access; it runs the shim as `vedetta` to read the token and requires an exact
Tailscale user identity.

Supported dashboard environment settings:

| Variable | Default | Purpose |
|---|---|---|
| `MON_PORT` | `8787` | loopback dashboard port |
| `MON_PUBLIC_UPSTREAM` | `http://127.0.0.1:9090` | public read-only listener |
| `MON_UPSTREAM` | unset | legacy alias for `MON_PUBLIC_UPSTREAM` |
| `MON_ADMIN_UPSTREAM` | `http://127.0.0.1:9091` | corpus management listener |
| `MON_ADMIN_TOKEN_FILE` | unset | private admin bearer-token file |
| `MON_ALLOWED_ORIGINS` | local dashboard origins | exact comma-separated browser origins allowed to use management routes |
| `MON_ALLOWED_TAILSCALE_USERS` | unset | exact comma-separated Tailscale login names authorized as curators |
| `MON_ALLOW_LOCAL_ADMIN` | `false` | single-user development bypass that trusts every local process; never enable operationally or use as tailnet authorization |
| `MON_DASHBOARD` | adjacent `dashboard.html` | explicit dashboard asset |
| `MON_MAX_RESPONSE_BYTES` | `16777216` | maximum buffered JSON response; startup rejects values outside 1–33554432 |

For a tailnet deployment, set the exact HTTPS origin to prevent DNS rebinding:

```ini
Environment=MON_ALLOWED_ORIGINS=https://your-node.your-tailnet.ts.net
Environment=MON_ALLOWED_TAILSCALE_USERS=curator@example.com
```

The proxy validates `Host` for management reads as well as `Origin` for writes.
Do not use wildcards in this setting. The token file must be a regular,
non-symlink file, at least 32 bytes after
trimming, and inaccessible to group/other users on POSIX systems.

## Tailnet-only deployment

An illustrative systemd service (adjust the user and paths):

```ini
[Unit]
Description=Vedetta Threat Network operations dashboard
After=network-online.target vedetta-threat-network.service
Wants=network-online.target

[Service]
Type=simple
User=vedetta
Environment=MON_PORT=8787
Environment=MON_PUBLIC_UPSTREAM=http://127.0.0.1:9090
Environment=MON_ADMIN_UPSTREAM=http://127.0.0.1:9091
Environment=MON_ADMIN_TOKEN_FILE=/var/lib/vedetta/threat-network-admin.token
Environment=MON_ALLOWED_ORIGINS=https://your-node.your-tailnet.ts.net
Environment=MON_ALLOWED_TAILSCALE_USERS=curator@example.com
Environment=MON_DASHBOARD=/opt/vedetta/threat-network/web/dashboard.html
ExecStart=/usr/bin/python3 /opt/vedetta/threat-network/web/serve.py
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/opt/vedetta/threat-network/web /var/lib/vedetta/threat-network-admin.token

[Install]
WantedBy=multi-user.target
```

Expose only the shim over tailnet HTTPS:

```sh
sudo tailscale serve --bg 8787
```

Restrict HTTPS access to this node/service to the curator user or curator group
in the tailnet access-control policy as a second authorization layer. Tailscale
documents that access-control rules apply to Serve and that Serve strips
caller-supplied identity headers before adding the authenticated user's
`Tailscale-User-Login`. Do not use Funnel, device sharing, an `autogroup:member`
grant, or an allow-all ACL for this operations endpoint. See the official
[Serve identity-header documentation](https://tailscale.com/docs/features/tailscale-serve#identity-headers)
and [access-control documentation](https://tailscale.com/docs/features/access-control).

Then open `https://<node>.<tailnet>.ts.net/`. Keep the public Cloudflare Tunnel
routed only to the public API listener and keep ports `8787` and `9091` out of
its ingress configuration.

## Validation

The dashboard has no external JavaScript, CSS, fonts, analytics, or storage.
Dynamic API values are inserted with `textContent`; they are never interpreted
as HTML. The shim sets a per-response CSP nonce, `frame-ancestors 'none'`,
`connect-src 'self'`, no-store caching, and restrictive browser headers.

Run the proxy unit tests and syntax checks before deployment:

```sh
python3 -m unittest threat-network/web/test_serve.py
python3 -m py_compile threat-network/web/serve.py
sed -n '/<script nonce="__CSP_NONCE__">/,/<\/script>/p' threat-network/web/dashboard.html \
  | sed '1d;$d' | node --check -
```
