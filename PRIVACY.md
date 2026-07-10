# Privacy Notice

_Last updated: 2026-07-09 · Vedetta is in public beta; this notice will evolve._

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
**your** infrastructure. The project operators never receive it.

### Community telemetry (on by default, opt-out)

Vedetta contributes to a **community threat feed** by default. This is:

- **On by default, and trivially disabled** — set `VEDETTA_TELEMETRY_OPTIN=false`
  (or toggle it off in the dashboard) and nothing leaves your network. We default
  it on because the shared feed only becomes useful when instances contribute, and
  what they contribute is **privacy-reduced and pseudonymous** — never your device
  identities (below);
- **privacy-reduced at the source**: source IP addresses, MAC addresses, and
  hostnames are stripped before anything leaves your network and are **never
  transmitted**. What is shared for a known-bad hit is the **matched indicator from
  the public block-list** — never the raw observed query name (which could embed a
  hostname or address) — plus coarse aggregate counts. **For beta,
  telemetry shares ONLY these Core-confirmed block-list matches** — the
  query-derived high-confidence-candidate (eTLD+1) and behavior-summary signals are
  temporarily DISABLED pending a trust-model redesign, so nothing derived from your
  own observed queries is shared today;
- **salted-HMAC counting stays local**: the per-source identifier used to count
  distinct assets is a salted HMAC computed locally with a 256-bit per-instance
  secret and is **never forwarded**; the published feed exposes only the indicator
  and an aggregate source count, never a device;
- **pseudonymous, not anonymous** — the honest residual model. We do **not** claim
  mathematical anonymity. Direct device identifiers (IP/MAC/hostname) are removed by
  construction, but a **stable per-instance `reporter_id`** accompanies each
  submission and the threat-network server **stores the relationship between that
  reporter ID and the indicators it reported, at hourly time-bucket granularity**.
  That makes contributions *linkable over time to a pseudonym* — the server can tell
  that "the same reporter reported X at hour H and Y at hour H+3," even though the
  pseudonym carries no name, IP, or device. In addition:
  - **Cloudflare sees the connection.** Submissions reach the feed over an
    outbound-only Cloudflare tunnel, so Cloudflare (as the network intermediary)
    observes each reporter's **connection source address and timing**, independent
    of the payload.
  - **Retention/expiry is incomplete today.** Reporter identities and the stored
    aggregates do **not** yet have complete, enforced expiry, so the pseudonymous
    linkage above is retained rather than aged out.

  The exact guarantees, the coarse metadata that *is* shared today (the matched
  known-bad indicator and its eTLD+1, aggregate counts, a coarse version string,
  and an hourly time bucket — the candidate eTLD+1 is **not** currently shared, as
  the `high_confidence_domain_candidate` signal is disabled for beta), and this
  residual linkability model are documented and independently reviewed in
  [specs/003-threat-network/anonymization-proof.md](specs/003-threat-network/anonymization-proof.md).

The community feed itself is **advisory-only**: it never instructs or performs a
block; operators decide what to do.

### What the community feed publishes

The **published** advisory feed contains threat indicators (the *attacker's*
infrastructure, e.g. a malicious domain), a confidence score, severity, and
aggregate counts. The public feed itself carries **no** subscriber IPs, MACs,
hostnames, or reporter identities. Note this is a statement about the *published*
artifact only: as described above, the threat-network **server** still stores the
pseudonymous `reporter_id`↔indicator/hour linkage that consensus is computed from —
it is simply not exposed in the downloadable feed.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md). Do not open a
public issue for security reports.

## Contact

Questions about privacy: **privacy@vedettas.com**.
