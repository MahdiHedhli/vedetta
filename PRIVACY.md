# Privacy Notice

_Last updated: 2026-07-15 · Vedetta is in public beta; this notice will evolve._

This notice covers two separate things: the **vedettas.com website**, and the
**Vedetta software** you self-host.

## 1. The website (vedettas.com)

The marketing site uses **[Plausible Analytics](https://plausible.io/data-policy)**
for aggregate visitor statistics. Plausible is a privacy-focused, EU-hosted
analytics service that:

- sets **no cookies** and uses **no persistent identifiers**;
- collects **no personal data** and does **not** track you across sites;
- reports only aggregate metrics (page views, referrers, country, browser).

No account is required to use the site, and the site does not ask for personal
information.

## 2. The Vedetta software (self-hosted)

Vedetta is **local-first**. When you run it, your network data — devices,
events, DNS/firewall logs, scan results — stays in **your** Core's database on
**your** infrastructure. The project operators never receive that data, with one
narrow, controllable exception: the **community telemetry** described immediately
below. While enabled, telemetry sends the narrow, allowlisted pseudonymous record
described here — never your device records, raw logs, or raw query history.

### Community telemetry (on by default, opt-out)

Vedetta contributes to a **community threat feed** by default. This is:

- **On by default, and trivially disabled** — set `VEDETTA_TELEMETRY_OPTIN=false`
  (or toggle it off in the dashboard) to stop all telemetry contributions. Core
  separately downloads public threat-intelligence lists, including the advisory
  community feed, using credential-free HTTPS GETs; those requests contain no
  device/event/query data, but the remote services can observe your connection IP
  and timing. Set `VEDETTA_COMMUNITY_FEED_ENABLED=false` to disable the Vedetta
  community download as well. We default contribution on because the shared feed
  only becomes useful when instances contribute, and what they contribute is
  **privacy-reduced and pseudonymous** — never your device identities (below).

#### Exactly what is sent

On first registration, the client sends:

- wire schema version;
- a locally generated random `install_id` UUID;
- a coarse Vedetta software version; and
- supported signal-kind names. The capability list currently names all three v1
  contract kinds even though only `known_bad_domain_hit` is emitted during beta.

The service returns a random, stable `reporter_id`, a one-time reporter secret,
and upload limits. Later signed requests carry that stable reporter ID, an exact
Unix request timestamp, a random nonce, and an HMAC signature.

For beta, every exported signal is a Core-confirmed `known_bad_domain_hit`. The
JSON body contains:

- the matched public block-list domain and its eTLD+1 — not a caller-supplied or
  otherwise query-derived candidate domain;
- an hour-aligned event `time_bucket`;
- `observation_count`, `distinct_asset_count`, and optional `blocked_count`;
- local confidence and one or more fixed-vocabulary local reason codes; and
- a random `signal_id`.

Its batch envelope also contains a random `batch_id`, wire schema version, exact
batch-generation time, and exact collection-window start/end times. The latter
timestamps describe the batch; only the event bucket is hour-aligned. The
query-derived `high_confidence_domain_candidate` and `behavior_summary` kinds
remain disabled pending a trust-model redesign.

#### What is not sent

Internal or device IP addresses, MAC addresses, hostnames, raw query names,
resolved/server IPs, device inventories, network segments, SSIDs, free-form
metadata, and per-asset identifiers are not serialized. The per-source value used
for distinct counting is a salted HMAC computed locally with a random 256-bit
per-instance secret. It is reduced to `distinct_asset_count` and discarded before
egress; the hash and salt never leave the node.

This boundary is structural: the export candidate has an explicit field allowlist.
The community server independently rejects unknown fields, IP- or MAC-shaped
values, single-label and configured special-use/internal names, invalid domain/URL
syntax, and names that fail Public Suffix List reduction. These are concrete
schema/content checks, not a claim that every possible identifier embedded in an
otherwise valid public domain can be recognized.

#### What the community service stores and for how long

This is **pseudonymous, not anonymous**. The current server stores:

- a reporter row containing the stable `reporter_id`, a one-way secret hash,
  capability names, coarse version, exact creation and last-successful-auth times,
  status, and any denylist reason. The registration `install_id` is validated but
  is **not persisted**;
- signal rows linked to the reporter ID, including the domain/eTLD+1, hourly event
  bucket, confidence, reason codes, counts, an immutable exact first-received time,
  and an exact `received_at` time that is updated on each merge; and
- ingest receipts linked to the reporter ID, including `batch_id`, exact receipt
  time, and submitted/accepted/rejected counts.

The current server validates but does not persist each `signal_id` or the batch's
client-generated/window timestamps. Signal rows expire 30 days after their
immutable first-received time, and ingest receipts expire after 30 days. Replay
nonces expire after 24 hours. Reporter rows, reporter counters, computed aggregates,
and live feed records do **not** yet share a complete enforced expiry policy, so
some pseudonymous linkage and derived history can remain after signal/receipt purge.
Successful ingest logs also contain reporter ID, batch ID, acceptance counts, and
errors; log retention depends on the service operator's logging environment.

The server can therefore link submissions to the same stable pseudonym and observe
precise server receipt/merge timing even though it receives no operator name,
internal/device IP, MAC, or hostname. Submissions traverse an outbound-only
Cloudflare tunnel, so Cloudflare can observe each connection's public source address
and timing independently of the payload. Vedetta's community service also consumes
that forwarded public address (or the direct socket-peer address) as an in-memory
rate-limit key. The key and its last-access time remain in process while active and
until a background sweep after 30 idle minutes (the sweep runs every five minutes);
they are not written to SQLite or Vedetta application logs. Infrastructure-level
Cloudflare or hosting logs remain governed by those providers/operators.

The exact guarantees and residual-linkability analysis are documented in
[specs/003-threat-network/anonymization-proof.md](specs/003-threat-network/anonymization-proof.md).

The community feed itself is **advisory-only**: it never instructs or performs a
block; operators decide what to do.

### What the community feed publishes

The **published** advisory feed contains threat indicators (the *attacker's*
infrastructure, e.g. a malicious domain), a confidence score, severity, and
aggregate counts. The public feed itself carries **no** subscriber IPs, MACs,
hostnames, or reporter identities. Note this is a statement about the *published*
artifact only: as described above, the threat-network **server** still stores the
pseudonymous reporter/signal linkage and precise server receipt/merge/last-seen
timing described above — it is simply not exposed in the downloadable feed.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md). Do not open a
public issue for security reports.

## Contact

Questions about privacy: **privacy@vedettas.com**.
