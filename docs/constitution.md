# Vedetta Project Constitution

This document captures non-negotiable principles for the Vedetta project. All contributors and automated agents must respect these rules.

## Environment Data Handling (Non-Negotiable)
- Data derived from live access to a real environment (device/MCP/SSH/API queries, network topology, WAN/LAN IPs, MACs, hostnames, firmware versions, client inventory, SSIDs, credentials) is LOCAL-ONLY — written only to gitignored paths, NEVER tracked files.
- All tracked docs/research/design files use SYNTHETIC or doc-reserved values only (RFC 5737 IPs, example MACs 00:00:5E:00:53:xx, placeholder hostnames).
- Agents with live MCP/SSH/API access treat captured real data as sensitive: sanitized examples in tracked docs; raw captures to gitignored scratch only.
- .gitignore includes analysis-notes/ and agent scratch dirs; .env/secrets never committed.
- Environment-specific identifiers in a commit to a public repo are a release blocker — scrub to synthetic first.

## Other Core Principles
(Existing project rules around passive-first, V1 scope, Pi-4 floor, SNR discipline, local-first, primary-source grounding, and the sensor/Docker Core split remain in force as previously established.)

