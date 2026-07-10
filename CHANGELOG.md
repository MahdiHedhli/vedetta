# Changelog

All notable changes to Vedetta are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it leaves
beta.

## [Unreleased]

Public-beta hardening. Highlights in flight:

### Security
- Closed an unauthenticated sensor-registration hijack and an admin-bootstrap
  lockout; the last active admin token can no longer be revoked.
- Corrected the telemetry request-signing key so reporter uploads authenticate.
- Upgraded the service container toolchain off end-of-life Go/Alpine and added a
  binary-mode vulnerability scan to CI.

### Fixed
- Fresh databases now create the `suppression_rules` table (migration runner runs
  statement-by-statement with an asserted final-schema test).
- The sensor no longer deadlocks on shutdown and now reports dropped events and
  retries registration.
- The UniFi collector's syslog parser again accepts CEF and single-digit-day
  lines; the collector's ingest credential is provisioned from a shared secret.

### Changed
- The default `docker compose up` stack is scoped to Core + collector + frontend;
  telemetry and the central threat-network are behind a `community` profile.
- Removed a large binary from version control; corrected landing-page claims.

### Added
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `PRIVACY.md`, and issue templates.

<!-- Add a dated version section here when the first beta tag is cut, e.g.:
## [0.1.0-beta.1] - 2026-mm-dd
-->
