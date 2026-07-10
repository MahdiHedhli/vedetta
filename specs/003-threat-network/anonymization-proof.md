# Vedetta Threat Network — Anonymization Send + Reversal Proof

**Date:** 2026-07-09  **Environment:** live prod feed (`feed.vedettas.com`) + a
local instance of the exact production binary, fed synthetic data.
**Data:** 100% synthetic — RFC 5737 IPs, RFC 7042 MACs, RFC 2606 `.example` domains.

Two questions were tested:

1. **Can threat data be sent** through the zero-inbound path end-to-end?
2. **Is it truly anonymous** — can an adversary *reverse* any published/stored
   artifact back to a source identity (a household IP, a device MAC, or "which
   reporter saw what")?

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

## 2. Anonymity — what an adversary can observe

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
is a bare integer (`distinct_asset_count`). The `reporter_id` is a random opaque
credential with no operator identity attached.

### c) Full server store compromise (worst case — attacker dumps the SQLite DB)
Scanned **all 9 tables** for IPv4 / MAC / hostname patterns → **0 matches.**

| Table | Source-identifying content |
|-------|----------------------------|
| `reporters` | random UUID + `secret_hash` (one-way) + capabilities + version. **No name/IP/email.** |
| `signals` | random reporter UUID + attacker domain + counts (`observation_count`, `distinct_asset_count`). |
| `ingest_receipts` | reporter UUID + batch id + counts. **Client IP never persisted** (confirmed). |
| `feed_items` | published indicator + aggregate counts + timestamps. |
| others | allowlist domains, nonces, counters, migrations — no PII. |

Even a total server breach yields: *random UUIDs reported some bad domains, N of
them, at hour-granularity.* It does **not** yield who the reporters are, their
IPs, their devices, or any victim.

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

## 4. Residual considerations (disclosed, not hidden)

- **Aggregate counts are intentional.** `sources_observed` reveals "≥2 anonymous
  reporters saw X." That is the point of consensus and leaks nothing about *who*.
- **Traffic analysis** of a very rare indicator seen by exactly 2 sources tells an
  observer only that two unidentified reporters exist — no linkage to a household.
- **Not yet tested live:** an end-to-end run through `telemetry/export/strip.go`
  with realistic raw input (the strip step that produces the export candidate).
  The structural guarantee — an allowlisted `ExportCandidate` that *cannot* carry
  `source_ip` — is verified from the observable surfaces; a live strip run is a
  good addition once repo access is restored.

---

## Verdict

✅ **Data sends** end-to-end over the zero-inbound path.
✅ **No observable surface** (feed, wire, or full DB) carries a source identity.
✅ **The one internal hashed identifier is unforwarded AND 256-bit-salted** —
reversal is computationally infeasible.

Reproduce: `reverse_attack.py` (reversal proof) and the loadsmoke send test.
