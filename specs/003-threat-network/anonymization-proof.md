# Vedetta Threat Network — Privacy-Reduction & Residual-Linkability Analysis

> **Scope note:** This is **not** an anonymity proof. Sharing is **pseudonymous,
> not anonymous** (consistent with [PRIVACY.md](../../PRIVACY.md)). The analysis
> below establishes what is *removed* by construction (direct device identifiers)
> and what *residual linkage* remains (a stable per-instance pseudonym). Do not
> read any result here as a claim of mathematical anonymity.

**Date:** 2026-07-09  **Environment:** live prod feed (`feed.vedettas.com`) + a
local instance of the exact production binary, fed synthetic data.
**Data:** 100% synthetic — RFC 5737 IPs, RFC 7042 MACs, RFC 2606 `.example` domains.

Two questions were tested:

1. **Can threat data be sent** through the zero-inbound path end-to-end?
2. **What residual linkage remains** — which payload/device identifiers (internal
   IP, device MAC, hostname) are removed by construction, what *pseudonymous*
   linkage (a stable `reporter_id` mapped to what it reported, event hour, and
   exact server receipt/merge/last-seen timing) remains, and which public source
   address/timing metadata the network intermediary still observes?

---

## 1. Send path — WORKS

Against the production binary (SQLite store, real ingest→consensus→feed):

| Step | Result |
|------|--------|
| Register reporters (`POST /reporters/register`) | ✅ per-IP rate limit capped burst at 2 (anti-spray working as designed) |
| Signed ingest (`POST /ingest`, HMAC-SHA256) | ✅ 200 synthetic batches accepted, p95 **218 µs** |
| Fresh-reporter promotion | ✅ **blocked** — 0 feed items while reporters < 24 h old (Sybil maturation gate) |
| After 2 matured reporters corroborate | ✅ indicator promoted → 1 feed item, confidence 0.81, severity high, `reasons:[known_bad, cross_reporter_match]` |
| Public prod surface | ✅ `feed.vedettas.com` serving over the outbound-only Cloudflare tunnel; `status:ok` |

The zero-inbound design holds: the service binds `127.0.0.1:9090`; data arrives
only via the outbound tunnel; no public IP, no inbound port.

---

## 2. Residual linkability — what an adversary can observe

Three application-data surfaces an attacker could reach, plus network-intermediary
metadata:

### a) Public community feed (anyone can download it)
`feed_id`(random UUID) · `kind` · `indicator` · `indicator_type` · `confidence` ·
`severity` · `advisory` · `recommended_action` · `sources_required` ·
**`sources_observed` (a COUNT, e.g. 2)** · `reasons` · timestamps.
→ The `indicator` is the *attacker's* domain (`c2.badzone.example`), i.e. the
threat — never a victim. The only "who" signal is an **aggregate count**. No IP,
no MAC, no reporter id. Live prod feed scanned: **0 IPv4, 0 MAC**.

### b) Registration and ingest wire format (attacker runs a reporter or MITMs the payload)
Registration sends `schema_version` · random `install_id` · coarse
`vedetta_version` · capability names. The service returns a stable random
`reporter_id`, one-time reporter secret, and upload limits. Current server code
validates but does not persist the `install_id`.

Signed ingest headers carry `reporter_id` · exact Unix request timestamp · random
nonce · HMAC signature. The body carries `schema_version` · random `batch_id` ·
exact `generated_at` · exact `window_start/end` · `signals[{signal_id, kind,
time_bucket, domain, etld_plus_one, local_confidence, local_reasons,
observation_count, distinct_asset_count, blocked_count}]`.
→ **No `ip` / `mac` / `hostname` field exists in the schema.** Device involvement
is a bare integer (`distinct_asset_count`). The `reporter_id` carries no operator
identity (no name/IP/email), but it is **stable per instance and reused across
submissions** — so it is a **pseudonym**, not an anonymous nonce: the server can
link everything one reporter sends over time under that one id. Event times are
hour-bucketed, but request, batch-generation, and collection-window timestamps
are transmitted at finer precision.

### c) Full server store compromise (worst case — attacker dumps the SQLite DB)
The 2026-07-09 live test scanned **all 9 then-production tables** for IPv4 / MAC /
hostname patterns → **0 matches.** The current-schema field audit is summarized below.

| Table | Source-identifying content |
|-------|----------------------------|
| `reporters` | stable random UUID + `secret_hash` (one-way) + capabilities + version + status/denylist reason + exact creation and last-seen times. **No name/IP/email.** Registration `install_id` is not persisted. |
| `signals` | reporter UUID + indicator/domain/eTLD+1 + hourly event bucket + confidence/reason codes + observation/distinct-asset/blocked counts + exact immutable first-received and merge-updated `received_at` times. |
| `ingest_receipts` | reporter UUID + batch id + exact receipt time + submitted/accepted/rejected counts. **Client IP never persisted** (confirmed). |
| `feed_items` | published indicator + aggregate counts + timestamps. |
| others | allowlist domains, 24-hour reporter-linked nonces, reporter/day counters, computed aggregates, migrations, and corpus tables — no direct device/operator identifiers, but some pseudonymous/derived records lack complete expiry. |

Even a total server breach yields: *stable pseudonymous reporter UUIDs reported
some bad domains, N of them, with hourly event buckets and precise server-side
receipt/merge/last-seen timing.* It does **not** directly yield the reporters'
real-world identity, internal/device IPs, MACs, or hostnames — but it **does**
yield a per-pseudonym history. Because each `reporter_id` is stable and reused, a
DB dump can group what one reporter sent and when. That is the residual
**linkability** (a pseudonym trail), distinct from the absent direct identifiers.
Application logs also record successful reporter IDs, batch IDs, counts, and
errors; their retention depends on the deployment's logging environment.

### d) Network intermediary
The Cloudflare tunnel terminates the public connection and can observe the
reporter's WAN/public source address and connection timing. That metadata is not
inside the telemetry JSON or SQLite store, but it is a residual disclosure and
must not be folded into a claim that source IPs are universally unobservable.
The Vedetta service also extracts the trusted forwarded address (or direct socket
peer) as its in-memory registration/ingest rate-limit key. The process retains the
address and last-access time while active and until its five-minute sweeper removes
the bucket after 30 idle minutes; the key is not written to SQLite or application
logs.

---

## 3. Reversal attack on the internal source hash (the crux)

Vedetta computes a `SourceHash` **telemetry-locally** to dedupe/count sources.
It is **salted-HMAC and NEVER forwarded** — so it appears on none of the surfaces
above. We still attacked it, to prove the scheme is sound *even if it leaked*:

```
1. UNSALTED  sha256(ip)                 <- the naive "we hash IPs" approach
   recovered 203.0.113.147 in 0.2 ms (brute force)
   full IPv4 space (2^32) ≈ 1.5 core-hours single-threaded  ->  REVERSIBLE

2. SALTED    hmac_sha256(secret_salt, ip)   <- Vedetta (32-byte crypto/rand salt)
   same brute force -> NOT RECOVERED
   to also brute the salt: 2^256 ≈ 1.16e77 keys ≈ 3.7e57 years  ->  INFEASIBLE

3. MAC       sha256(mac) unsalted        <- even 2^48 falls to OUI narrowing
   recovered 00:00:5E:00:53:2A in 17.8 ms  ->  MACs need the salt too
```

**Key finding (honest):** hashing a source identifier *alone* is **not** anonymity
— IP and MAC input spaces are small enough to brute-force. Vedetta's
non-reversibility rests on two independent properties, both verified:
(1) the hash is **never transmitted**, and (2) it is bound to a **256-bit
per-instance secret salt**. Either alone would stop the attack; together they are
defence in depth.

---

## 4. Residual linkage (disclosed, not hidden)

- **Stable pseudonym, linkable over time (the primary residual).** Each instance
  registers one stable `reporter_id`, reused for every submission. The server
  stores that ID with signal data, hourly event buckets, and precise receipt,
  first-received, last-merge, creation, and last-seen timing — so contributions
  are **linkable to a pseudonym over time**. This is why the model is
  **pseudonymous, not anonymous**. The pseudonym carries no name, internal/device
  IP, MAC, or hostname, but it is not a fresh nonce per submission.
- **Cloudflare sees the connection.** Submissions egress over an outbound-only
  Cloudflare tunnel, so Cloudflare (as the network intermediary) observes each
  reporter's **connection source address and timing**, independent of the payload.
  Vedetta also transiently holds that public address and last-access time in its
  in-memory rate limiter until swept after 30 idle minutes, not in SQLite or
  application logs.
- **Retention/expiry is partial today.** Signal rows expire 30 days after their
  immutable first-received time, ingest receipts expire after 30 days, and replay
  nonces expire after 24 hours. Reporter rows, reporter/day counters, computed
  aggregates, live feed records, and operational logs do **not** share one complete
  enforced expiry policy, so some pseudonymous linkage and derived history remain.
- **Aggregate counts are intentional.** `sources_observed` reveals "≥2 pseudonymous
  reporters saw X." That is the point of consensus and leaks nothing about a
  reporter's real-world identity.
- **Traffic analysis** of a very rare indicator seen by exactly 2 sources tells a
  feed-only observer that two pseudonymous reporters exist. Correlation with the
  intermediary's public-source/timing view remains a separate residual risk.
- **Not yet tested live:** an end-to-end run through `telemetry/export/strip.go`
  with realistic raw input (the strip step that produces the export candidate).
  The structural guarantee — an allowlisted `ExportCandidate` that *cannot* carry
  `source_ip` — is verified from the observable surfaces; a live strip run is a
  good addition once repo access is restored.

---

## Verdict

✅ **Data sends** end-to-end over the zero-inbound path.
✅ **No application payload/store surface** (feed, wire body, or full DB) carries
an internal/device IP, MAC, or hostname. Cloudflare still observes the public
connection source and timing; Vedetta transiently uses that address as an in-memory
rate-limit key as stated above.
⚠️ **A stable pseudonym remains.** The wire and the server store carry a stable
per-instance `reporter_id`; the server links it to signals plus exact receipt,
merge, and last-seen timing. Sharing is therefore **pseudonymous, not anonymous**
— reconstructable to a pseudonym over time, though the payload/store contains no
direct device/operator identifier. Cloudflare additionally sees public connection
source/timing. Signal rows and receipts expire after 30 days, but reporter and
derived-record expiry remains incomplete.
✅ **The one internal hashed source identifier is unforwarded AND 256-bit-salted**
— reversal of *that* value is computationally infeasible (it is never exposed).

Reproduce: `reverse_attack.py` (source-hash reversal proof) and the loadsmoke send test.
