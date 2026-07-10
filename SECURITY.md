# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vedetta, **please do not open a public issue.**

Instead, report it privately:

- **Email:** security@vedettas.com
- **Subject line:** `[VULN] <brief description>`

Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

This policy covers:

- The Vedetta backend, frontend, collector, telemetry daemon, and threat network services
- The Docker Compose deployment configuration
- The SIEM storage layer and event schema
- The telemetry PII stripping pipeline

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (dev) | Yes |
| Tagged releases | Yes |

## Known Limitations & Accepted Risks

Vedetta is a **LAN-first, self-hosted** tool. Two properties are inherent to that
design and are documented, accepted trade-offs rather than defects:

### 1. The community threat feed is advisory-only (no Sybil resistance) — GHSA-573f

The community threat network aggregates anonymized, **pseudonymous** reports and
promotes an indicator only after **≥2 independent, matured (24 h) reporters**
corroborate it, with per-source-IP registration rate limiting. This raises the
*cost* of manipulation but does **not** make the feed Sybil-proof: an anonymous,
permissionless P2P feed cannot cryptographically prove two reporters are distinct
operators without identity, proof-of-work, or a web of trust — none of which fit a
privacy-preserving, zero-signup design.

**Accepted posture:** the feed is **advisory-only** — it never instructs or performs
a block; operators decide what to act on. Treat it as one weak signal among many,
not authoritative blocklisting. This is a permanent architectural limitation, and
**GHSA-573f is tracked as an accepted limitation, not an open defect.**

### 2. Default deployment is loopback-only; LAN/remote exposure is an explicit choice

Core's API carries admin and sensor bearer tokens over plain HTTP. By default:

- Bare-metal Core binds `127.0.0.1` (`VEDETTA_LISTEN_ADDR`).
- Docker Compose publishes the Core API and dashboard to the **host loopback only**
  (`127.0.0.1:…`) — nothing is on the LAN in the clear out of the box.

To reach Vedetta from another machine you must make an **explicit choice**: put the
documented TLS reverse proxy in front (recommended — `docs/reverse-proxy.md`), or
knowingly change the bind to `0.0.0.0`, accepting that bearer tokens then traverse
your LAN as plaintext. **Insecure LAN exposure is never the silent default.** (The
syslog collector port is the one intentional LAN listener — it must receive logs
from network devices and carries no admin credentials.)

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version
2. Publish a security advisory on GitHub
3. Credit the reporter (unless they prefer anonymity)
