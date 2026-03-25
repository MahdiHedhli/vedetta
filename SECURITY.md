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

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version
2. Publish a security advisory on GitHub
3. Credit the reporter (unless they prefer anonymity)
