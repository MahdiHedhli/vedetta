# Vedetta Project Constitution

> Canonical governance document. Every spec, plan, task breakdown, and implementation
> MUST be validated against this constitution. Violations require an explicit,
> documented exception in the corresponding spec.
>
> Version: 1.0.0 | Ratified: 2026-07-03 | Supersedes: /constitution.md (env-data rules incorporated verbatim below)

## Core Identity & Constraints (Non-Negotiable)

- Vedetta is a self-hosted, FOSS (AGPLv3) security monitoring platform for homes and
  small businesses. "Your network, under watch."
- **L2 Sensor Hard Constraint:** The L2 sensor MUST run as a native binary on the host
  OS. The Docker Core + native sensor split is foundational. Docker cannot provide full
  host network stack fidelity (raw sockets, ARP, passive sniffing) on macOS/Windows
  (only Linux `--network=host` works reliably). Any feature touching L2 visibility
  (discovery, passive DNS/ARP/DHCP/mDNS/SSDP) must respect this split. No proposals to
  collapse into pure Docker.
- **Pi-hole Optional:** Pi-hole (and AdGuard Home) are OPTIONAL DNS inputs among
  several. Never a prerequisite. The product must deliver value with only the native
  sensor + Core. Integrations are additive, not core identity.
- **Passive-First:** Prioritize passive ARP + DNS interception (zero gateway
  cooperation required). Must remain robust across ISP-locked routers, aftermarket
  gear, and no-port-forward scenarios. Active scanning (nmap) is complementary, not a
  replacement.

## V1 Scoping Discipline (Enforced on Every Feature)

- V1 deliberately EXCLUDES full LAN scanning, exploit verification, active
  vulnerability assessment, and other high-risk/high-complexity work.
- For every proposed feature: explicitly call out scope cuts if risk/complexity rises.
  Prefer "what can we ship that adds signal without new noise or attack surface?"
- Hardware floor: Raspberry Pi 4 (or equivalent). One-command install target
  <5 minutes. Idle resource budget respected (<200 MB RAM, <5% CPU target for core
  paths).
- One data source at a time for major expansions (e.g., UniFi logs land as a complete,
  tuned workflow before the next connector starts).

## Development & Quality Principles

- Planning artifacts first: every major feature gets `specs/NNN-name/spec.md` →
  `plan.md` → `tasks.md` before implementation (see Workflow below).
- Signal-to-noise is an ONGOING discipline. It re-opens with every new data source;
  new sources bring new noise patterns requiring suppression, context, and scoring
  updates before the source is called "supported".
- Local value first, self-hosted first. Telemetry/community threat network is
  optional, opt-in, privacy-conscious, and secondary to local operation.
- Ground decisions in primary sources (CISA KEV, FBI FLASH advisories, vendor docs,
  endoflife.date, official APIs, live tests) — never from memory alone.
- Every schema change is a NEW sequential migration in `siem/migrations/`. Never edit
  an already-committed migration file: applied databases skip it and fresh installs
  diverge (or break on duplicate columns).
- Backward compatibility for wire formats and event tags: sensors and Core upgrade
  independently; renamed fields/tags keep an accepted alias for at least one release.
- Builds and tests green before commit: `go build ./... && go test ./... -short` in
  `backend/` and `sensor/`, `npm run build` in `frontend/`.
- AGPLv3 throughout. No proprietary lock-in in core paths.
- Alpha expectations: document shipped vs planned honestly. Public internet exposure
  is not supported yet.

## Environment Data Handling (Non-Negotiable)

- Any data derived from live access to a real environment — device queries (UniFi MCP,
  SSH, controller APIs), network topology, WAN/LAN IPs, MAC addresses, hostnames,
  firmware versions, client/device inventory, SSIDs, or credentials — is LOCAL-ONLY.
  It is written exclusively to gitignored paths (e.g. analysis-notes/, .local/) and
  NEVER to tracked files.
- All tracked documentation, research, and design files use SYNTHETIC or
  documentation-reserved values only: RFC 5737 IPs (192.0.2.x / 198.51.100.x /
  203.0.113.x), example MACs (00:00:5E:00:53:xx), placeholder hostnames. No real
  network artifacts in the tracked tree, ever.
- Agents operating with live MCP/SSH/API access to the owner's environment MUST treat
  captured real data as sensitive: summarize design implications in tracked docs using
  sanitized examples, write any raw captures to gitignored scratch only.
- .gitignore MUST include analysis-notes/ and any agent scratch directories. Secrets
  (.env, tokens, keys) remain gitignored and are never committed.
- Before any commit to a public repo, environment-specific identifiers are a release
  blocker: scrub to synthetic values first.

## Spec-Driven Workflow (GitHub Spec Kit)

Artifacts live under `specs/NNN-feature-name/` (three-digit prefix, kebab-case):

| Artifact | Purpose |
| --- | --- |
| `spec.md` | WHAT and WHY: user stories, requirements, constitution check, out-of-scope |
| `plan.md` | HOW: architecture, data flows, APIs, schema changes, SNR impact analysis |
| `tasks.md` | Phased, testable task breakdown with explicit verification steps |
| `contracts/` | API/wire-format contracts when the feature crosses a service boundary |

Templates live in `.specify/templates/`. The flow is sequential:
Spec → Plan → Tasks → Implement. Each phase validates against this constitution.
`docs/backlog.md` remains the day-to-day tracker; VED-xxx entries link to their spec
directory once one exists.

## Enforcement

- Every spec/plan/tasks artifact MUST contain a "Constitution Check" section listing
  which constraints apply and how the feature respects them.
- Violations (e.g., proposing full LAN scans in V1, making Pi-hole required,
  collapsing the sensor into Docker-only, committing live-environment data) require an
  explicit exception with justification recorded in the spec.
- This constitution changes only via a dedicated spec documenting the amendment and
  its rationale.
