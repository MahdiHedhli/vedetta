# Pi-hole And AdGuard Home Pollers

Pi-hole and AdGuard Home are optional event sources. Core and a native Vedetta sensor
remain the complete default deployment. Configure a poller in `.env`, then recreate the
backend with `docker compose up -d --force-recreate backend`; a blank URL leaves that
poller disabled.

## Pi-hole

```dotenv
VEDETTA_PIHOLE_URL=http://pi.hole
VEDETTA_PIHOLE_TOKEN=replace-with-dedicated-application-password
VEDETTA_PIHOLE_INTERVAL=60s
```

For Pi-hole v6, `VEDETTA_PIHOLE_TOKEN` is a dedicated application password
(recommended) or the regular Pi-hole password. Core exchanges the credential with
the documented `POST /api/auth`, caches the returned session ID, and sends that ID in
`X-FTL-SID` to `/api/queries`. It re-authenticates once after an expired-session `401`.
Core deletes the session during a clean shutdown so it does not consume one of Pi-hole's
bounded session slots until idle expiry.
If Pi-hole has no password, leave the token blank. Pi-hole documents both the
[session flow](https://docs.pi-hole.net/api/auth/) and its locally versioned API at
`http://pi.hole/api/docs`.

Legacy Pi-hole v5 remains compatible. Either use the host URL and allow Core's one-time
v6-not-found fallback, or set the explicit endpoint:

```dotenv
VEDETTA_PIHOLE_URL=http://pi.hole/admin/api.php
VEDETTA_PIHOLE_TOKEN=replace-with-v5-api-token
```

The v6 request is time-bounded and uses Pi-hole's snapshot cursor plus server-side
`start` offset in 1,000-row pages, up to a bounded 10,000 rows per poll. Each JSON
response is also byte- and row-bounded before it is decoded. If a window exceeds 10,000
rows, Core marks collection unhealthy and keeps the prior replay watermark instead of
silently accepting a partial snapshot; reduce the interval for networks that can exceed
that rate. Legacy v5 responses remain capped at 10,000 rows because that endpoint has no
cursor.

Vedetta treats Pi-hole status codes `1`, `4`-`11`, `15`, `16`, and `18` as blocked;
other current statuses are allowed, pending, cached, or unknown. These meanings follow
Pi-hole's [query database status table](https://docs.pi-hole.net/database/query-database/#supported-status-types).
Pi-hole v6's stable query ID is retained in event metadata and event identity, so a
replayed API window does not inflate findings.

Pi-hole recommends HTTPS for API credentials. Vedetta verifies HTTPS certificates and
does not provide a Pi-hole TLS-skip switch. If you deliberately use HTTP on a trusted
LAN, the application password and session traffic are plaintext on that segment.

## AdGuard Home

```dotenv
VEDETTA_ADGUARD_URL=http://adguard-home:3000
VEDETTA_ADGUARD_USER=vedetta-readonly
VEDETTA_ADGUARD_PASS=replace-me
VEDETTA_ADGUARD_INTERVAL=60s
```

Core reads `/control/querylog` using HTTP Basic authentication when either credential
field is set. The adapter follows AdGuard's `older_than` cursor in 100-row pages, up to a
bounded 1,000 rows per poll. It overlaps its timestamp watermark and uses deterministic
IDs to make replay safe. When more than 1,000 new rows are pending, Core preserves the
prior watermark and resumes from the `older_than` cursor on later polls until the burst
is drained; older retained history therefore does not make an otherwise healthy source
look failed. On first connection, Core intentionally establishes its watermark from the
newest bounded prefix instead of delaying live protection while replaying the appliance's
entire pre-Vedetta history. A missing or non-advancing cursor is still a visible collection
error, and every page is byte-bounded and rejected if the server returns more rows than
requested.

## Verify Collection

After recreating the backend, inspect its logs for `Pi-hole poller registered` or
`AdGuard Home poller registered`, then check the dashboard's collection-health state.
Authentication, malformed JSON, and transport failures mark the source unhealthy; an
empty but valid upstream query array is a healthy zero-event poll.

Keep `.env` private. Never place DNS credentials directly in `docker-compose.yml` or a
tracked file.
