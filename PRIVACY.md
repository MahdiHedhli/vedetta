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

### Opt-in telemetry (off by default)

Vedetta can optionally contribute to a **community threat feed**. This is:

- **Off by default** (`VEDETTA_TELEMETRY_OPTIN=false`) and only active if you
  explicitly enable it;
- **privacy-reduced before it ever leaves your network**: source IP addresses,
  MAC addresses, and hostnames are **never transmitted**. What is shared is
  limited to threat indicators (e.g. a known-bad domain) plus coarse,
  non-identifying counts;
- **anonymized and non-reversible**: any per-source identifier used internally is
  a salted HMAC computed locally with a 256-bit per-instance secret and is
  **never forwarded**. The published community feed exposes only the indicator and
  an aggregate source count — never who reported it.

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
