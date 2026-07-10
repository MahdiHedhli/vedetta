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
  what they contribute is reduced to threat indicators that do not identify you
  (below);
- **privacy-reduced at the source**: source IP addresses, MAC addresses, and
  hostnames are stripped before anything leaves your network and are **never
  transmitted**. What is shared for a known-bad hit is the **matched indicator from
  the public block-list** — never the raw observed query name (which could embed a
  hostname or address) — plus coarse, non-identifying aggregate counts;
- **salted-HMAC counting stays local**: any per-source identifier used to count
  distinct assets is a salted HMAC computed locally with a 256-bit per-instance
  secret and is **never forwarded**; the published feed exposes only the indicator
  and an aggregate source count, never who reported it;
- **precise, not absolute**: we do not claim mathematical anonymity. The reduction
  removes direct identifiers by construction; the exact guarantees, the coarse
  metadata that *is* shared (a coarse version string, aggregate counts, an hourly
  time bucket), and the residual linkability model are documented and independently
  reviewed in
  [specs/003-threat-network/anonymization-proof.md](specs/003-threat-network/anonymization-proof.md).

The community feed itself is **advisory-only**: it never instructs or performs a
block; operators decide what to do.

### What the community feed publishes

The public advisory feed contains threat indicators (the *attacker's*
infrastructure, e.g. a malicious domain), a confidence score, severity, and
aggregate counts. It contains **no** subscriber IPs, MACs, hostnames, or
reporter identities.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md). Do not open a
public issue for security reports.

## Contact

Questions about privacy: **privacy@vedettas.com**.
