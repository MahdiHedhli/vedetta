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
2. **What residual linkage remains** — which *direct* source identifiers (a
   household IP, a device MAC, a hostname) are removed by construction, and what
   *pseudonymous* linkage (a stable `reporter_id` mapped to "which reporter saw
   what, at which hour") an adversary can still reconstruct?

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

Three surfaces an attacker could reach, and every field on each:

### a) Public community feed (anyone can download it)
`feed_id`(random UUID) · `kind` · `indicator` · `indicator_type` · `confidence` ·
`severity` · `advisory` · `recommended_action` · `sources_required` ·
**`sources_observed` (a COUNT, e.g. 2)** · `reasons` · timestamps.
→ The `indicator` is the *attacker's* domain (`c2.badzone.example`), i.e. the
threat — never a victim. The only "who" signal is an **aggregate count**. No IP,
no MAC, no reporter id. Live prod feed scanned: **0 IPv4, 0 MAC**.

### b) Ingest wire format (attacker runs a reporter or MITMs the payload)
`schema_version` · `batch_id` · `generated_at` · `window_start/end` ·
`signals[{signal_id, kind, time_bucket, domain, etld_plus_one, local_confidence,
local_reasons, observation_count, distinct_asset_count}]`.
→ **No `ip` / `mac` / `hostname` field exists in the schema.** Device involvement
is a bare integer (`distinct_asset_count`). The `reporter_id` carries no operator
identity (no name/IP/email), but it is **stable per instance and reused across
submissions** — so it is a **pseudonym**, not an anonymous nonce: the server can
link everything one reporter sends over time under that one id.

### c) Full server store compromise (worst case — attacker dumps the SQLite DB)
Scanned **all 9 tables** for IPv4 / MAC / hostname patterns → **0 matches.**

| Table | Source-identifying content |
|-------|----------------------------|
| `reporters` | random UUID + `secret_hash` (one-way) + capabilities + version. **No name/IP/email.** |
| `signals` | random reporter UUID + attacker domain + counts (`observation_count`, `distinct_asset_count`). |
| `ingest_receipts` | reporter UUID + batch id + counts. **Client IP never persisted** (confirmed). |
| `feed_items` | published indicator + aggregate counts + timestamps. |
| others | allowlist domains, nonces, counters, migrations — no PII. |

Even a total server breach yields: *stable pseudonymous reporter UUIDs reported
some bad domains, N of them, at hour-granularity.* It does **not** yield the
reporters' real-world identity, their IPs, their devices, or any victim — but it
**does** yield a per-pseudonym history: because each `reporter_id` is stable and
reused, a DB dump lets an adversary group "everything this one reporter ever
reported, and when." That is the residual **linkability** (a pseudonym trail),
distinct from the absent **direct identifiers**.

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
  stores the relationship between that id and the indicators it reported, at
  hourly time-bucket granularity — so contributions are **linkable to a pseudonym
  over time** ("the same reporter reported X at hour H and Y at hour H+3"). This
  is why the model is **pseudonymous, not anonymous**. The pseudonym carries no
  name, IP, or device, but it is not a fresh nonce per submission.
- **Cloudflare sees the connection.** Submissions egress over an outbound-only
  Cloudflare tunnel, so Cloudflare (as the network intermediary) observes each
  reporter's **connection source address and timing**, independent of the payload.
- **Retention/expiry is incomplete today.** Reporter identities and the stored
  aggregates do **not** yet have complete, enforced expiry, so the pseudonymous
  linkage above is retained rather than aged out.
- **Aggregate counts are intentional.** `sources_observed` reveals "≥2 pseudonymous
  reporters saw X." That is the point of consensus and leaks nothing about a
  reporter's real-world identity.
- **Traffic analysis** of a very rare indicator seen by exactly 2 sources tells an
  observer only that two pseudonymous reporters exist — no linkage to a household.
- **Not yet tested live:** an end-to-end run through `telemetry/export/strip.go`
  with realistic raw input (the strip step that produces the export candidate).
  The structural guarantee — an allowlisted `ExportCandidate` that *cannot* carry
  `source_ip` — is verified from the observable surfaces; a live strip run is a
  good addition once repo access is restored.

---

## Verdict

✅ **Data sends** end-to-end over the zero-inbound path.
✅ **No observable surface** (feed, wire, or full DB) carries a *direct* source
identifier — no IP, MAC, or hostname.
⚠️ **A stable pseudonym remains.** The wire and the server store carry a stable
per-instance `reporter_id`; the server links it to the indicators/hour it
reported. Sharing is therefore **pseudonymous, not anonymous** — reconstructable
to a pseudonym over time, though not to a real-world identity. Cloudflare (the
outbound tunnel) additionally sees connection source/timing, and reporter
identities/aggregates lack complete expiry today.
✅ **The one internal hashed source identifier is unforwarded AND 256-bit-salted**
— reversal of *that* value is computationally infeasible (it is never exposed).

Reproduce: `reverse_attack.py` (source-hash reversal proof) and the loadsmoke send test.
