# Plan: LLM Assistant via Model Context Protocol (MCP)

> Spec: `specs/009-llm-assistant/spec.md`
> Threat model: `specs/009-llm-assistant/threat-model.md`
> Status: Phase 0 signed off (spec + threat model merged). Severity/risk policy finalized. Code not started.

## What ships and what is net-new

Spec 009 is a NEW optional module — a `vedetta-mcp` stdio adapter binary — plus additive
Core changes. Core with `assistant.enabled=false` (the fresh-install default) behaves
byte-for-byte as today; that compatibility guarantee is what lets the early phases ship
independently. The load-bearing structural fact: Vedetta is Bearer-only — no sessions, no
CSRF, no WebAuthn (`backend/internal/auth`). The human-accepted-execution boundary is
therefore net-new code, and the execution phase sits behind an **acceptance-gate wall**:
its accept/reject routes must not merge until the WebAuthn/passkey human-presence primitive
ships and is tested.

## Existing paths this builds on

- chi router at `backend/internal/api/router.go`; existing scopes `sensor`/`admin`/`ingest`/`read`
  in `backend/internal/auth/auth.go`; `ScopeSatisfies` is a blanket admin-superuser
  (`have == ScopeAdmin ⇒ true`, auth.go:42) — **left unchanged**.
- Middleware templates: `RequireStrictAuth`, `RequireStrictAdmin`, `RequireExactScope`,
  `RequireRead` (`backend/internal/auth/middleware.go`). The sensor group
  (`RequireStrictAuth + RequireExactScope(ScopeSensor)`, router.go ~316) is the template
  for the assistant action group.
- Token store `backend/internal/store/tokens.go` (`CreateToken`, `ValidateToken`); the
  `api_tokens` DDL is an inline `CHECK(scope IN ('sensor','admin','ingest','read'))`
  (db.go:612) with a `sensors` FK, the `ux_api_tokens_active_sensor` partial unique index,
  and three `idx_api_tokens_*` indexes. Migration 021 widened this CHECK via a full
  table-rebuild — the required recipe here too.
- SQLite migrations under `siem/migrations/`, currently at 030; next are 031, 032.
- Settings via `GetSetting`/`SetSetting` (`backend/internal/store/settings.go`, migration 023).
- Suppression store `SuppressFinding` / `DeactivateFindingSuppression`
  (`backend/internal/store/finding_suppression.go:22,113`) — the byte-identical guard stack
  the execute path reuses. Rate limiting `backend/internal/api/ratelimit.go`; ingest-lag
  signal `backend/internal/store/detection_health.go`.
- `models.Priority = {low, medium, high, critical}` (finding.go:20-25) — **no `info` band**.
  The severity matrix is built on exactly this enum plus an `unknown` fail-closed bucket.

## Shared predicate — a first-class prerequisite, not a refactor

The `trusted_high_confidence_ioc_or_ips` predicate on which the entire code-constant ceiling
rests **does not exist as an extractable function today**. What exists is the ingress
`trustedIPS` struct (`processing/hardening.go:24`) and the finding-creation rule
`CreatesFinding = Detector=="ips" || ScoreContribution>=0.30` (`processing/evidence.go:222`),
plus spec-007 prose including the community-corroborated-public-IOC composition
(spec 009 lines 123-126). Extracting assistant eligibility is a first-class workstream with
its own tests, sequenced **before** any policy engine: define the predicate semantics
precisely and build a separate shared assistant-eligibility function in
`backend/internal/processing` (or a shared package) without replacing or changing existing
`CreatesFinding` semantics. Differential tests cover both outputs — finding creation and
assistant eligibility — over a shared synthetic corpus and require the assistant policy-engine
stub to consume the shared eligibility result rather than re-implement it. Landed in P1a
because detection context is needed, but the two semantics remain distinct.

## The acceptance-gate wall (the single most important sequencing constraint)

Because Vedetta has no sessions/CSRF/WebAuthn, the human-execution boundary is net-new. The
P3 accept/reject routes MUST NOT merge until the P1b WebAuthn/passkey platform-authenticator
primitive + server-session/CSRF/Origin hardening are shipped and tested. Until then the
assistant is CODE-CAPPED at propose-only and no accept route exists. Building the primitive
in P1b (its own reviewable, security-reviewed unit) means P3 consumes a tested dependency
instead of inventing auth under deadline.

## Phases, gates, and shippable milestones

Phase 1 is split into P1a (fast additive foundation) and P1b (the net-new human-presence
primitive) so the trivial scope/TTL/table work is not coupled to the slowest, highest-risk
subsystem. Phase 2 is split into P2a (local-only read, genuinely low-risk) and P2b (cloud
opt-in read — the effectively-irreversible privacy boundary, owner-gated like P3/P4).

### P1a — Least-privilege Core foundation (Core-only; subsystem OFF; independently shippable)
Additive scope isolation, token TTL, settings, storage, and the shared predicate. With
`assistant.enabled=false` Core is behaviorally identical to today.
- **Depends on:** Phase 0 (done).
- **GATE-1a:** scope truth-table + negative tests green (assistant satisfies only itself via
  `RequireExactScope` + explicit `RequireAssistantRead` membership; admin-superuser rule
  untouched); 031 token-table REBUILD + manifest tests green (incl. run against a populated
  `api_tokens` DB preserving legacy NULL non-assistant tokens); assistant-token TTL
  enforcement tests; 032 tables + manifest tests; settings default off/read_only verified;
  shared predicate differential test (detection == policy engine) green.
- **Shippable:** YES. Recommended first cut — scope isolation, the token rebuild, and the
  predicate land under normal review pressure without the adapter's surface area.
- **Effort/risk:** low / low–medium (the token-table rebuild on the security-critical token
  table is the one careful spot).

### P1b — Human-presence primitive (net-new sessions + CSRF/Origin + WebAuthn; the P3 wall)
Vedetta's first-ever session/auth surface, decoupled from the accept route so P1a/P2 never
wait on it.
- **Depends on:** none at runtime; built in parallel with P1a. Long pole.
- **GATE-1b (the wall's input):** server-session issuance + `RequireDashboardSession` (bearer
  tokens do NOT satisfy it and it does NOT satisfy bearer routes); CSRF + Origin/Host
  allowlist tests; WebAuthn platform-authenticator registration + verify-assertion helper
  (over a supplied `action_id||accept_nonce` challenge), library pinned by exact version+hash. The
  accept route that consumes this ships in P3.
- **Shippable:** independently reviewable/mergeable as dormant auth groundwork; delivers no
  user-facing feature alone. If it slips, P1a/P2 still ship; only P3 is blocked.
- **Effort/risk:** high / high (net-new auth; dedicated security review).

### P2a — Read-only assistant, LOCAL only (Core projections + `vedetta-mcp` adapter)
The full "help me triage" product over a local model (Ollama / LM Studio), ZERO mutation,
ZERO egress off the LAN. The largest injection surface, shipped with no state-change risk.
- **Depends on:** GATE-1a (scope/token/settings + shared predicate). NOT the accept route.
- **GATE-2a:** injection-corpus fuzz/property gate green in CI (build fails on leak);
  projection allowlist tests (a later-added DTO field is dropped by default); `mode=ro` pool
  writer-progress + WAL/checkpoint tests; per-tool caps/pagination/deadlines + per-session
  rate limits + ingest-lag circuit breaker; static tool manifest hash exposed in `/status`;
  first-pass tool-poisoning + SBOM scan.
- **Shippable:** YES — the recommended standalone release. Complete local triage assistant,
  no execution boundary yet built, biggest injection surface with zero mutation risk.
- **Effort/risk:** high / medium–high (injection surface).

### P2b — Read-only assistant, CLOUD opt-in (owner-gated privacy boundary)
Adds the opt-in cloud read path — the effectively-irreversible "data leaves the network"
crossing. Owner-gated like P3/P4, not framed as the default cut.
- **Depends on:** GATE-2a.
- **GATE-2b (owner human-gate):** cloud per-install AND per-session consent + field-class
  disclosure; whole-session minimization + no local→cloud downgrade + eTLD+1 granularity;
  Core-side never-egress denylist tests; Core-independent loopback verification; same
  minimizer over model rationale + conversation context; per-session egress ledger; no
  telemetry/community coupling (tested); **FULL tool-poisoning audit signed off + static
  hash-pinned manifest verification** (the adapter binary reaches users here). Owner sign-off.
- **Shippable:** YES on top of P2a, behind the owner gate.
- **Effort/risk:** medium / high (privacy consequence is the risk, not the code).

### P3 — Human-accepted execution (behind the acceptance-gate wall; owner-gated)
The three guarded, reversible actions carried to completion on a genuine present-human
passkey tap. Where the finalized severity policy, the code-constant ceiling, drift-void,
single-use CAS, rate limits, kill switch, and reversibility land.
- **Depends on:** GATE-1a AND GATE-2a AND — as the WALL — GATE-1b shipped+tested. The
  finalized severity policy (resolved) precedes the policy-engine task.
- **GATE-3 (the wall):** accept rejects all bearers incl. admin; assertion bound to
  `action_id||accept_nonce`; severity policy enforced at prepare AND accept with fail-closed
  tests; single-use CAS replay/double-submit/expired → 409; any-drift void → 409; ceiling
  tests (critical/high/trusted-IOC ineligible; medium- and low-suppress blocked by default;
  park→login re-prepare); one-outstanding-per-session; rate-limit/circuit-breaker/kill-switch;
  reversibility; append-only audit (no UPDATE/DELETE); tool-poisoning re-run for guarded
  tools signed off. Owner sign-off.
- **Shippable:** NO until GATE-3. Propose-only is the enforced ceiling until the wall is
  satisfied. Then independently shippable on top of P2; backend-agnostic (accept boundary is
  model-location-independent).
- **Effort/risk:** high / highest (the security boundary — de-risked by P1b groundwork and by
  P2a having proven the read surface).

### P4 — Remote transport hardening (optional; owner-gated; independently shippable)
Opt-in HTTP/SSE transport for split-host local models, off by default; adds no new Core trust
boundary and no new default listener.
- **Depends on:** GATE-2a (a non-loopback transport must inherit whole-session minimization).
  Independent of P3.
- **GATE-4:** non-loopback-without-secret refusal test; `0.0.0.0` bind impossible;
  Origin/Host DNS-rebind tests; constant-time secret compare; non-loopback-misconfig →
  remote-classification (inherits the no-cloud-full-fidelity rule).
- **Shippable:** YES on top of P2a/P3. Lowest value; last or skip for a single-host homelab.
- **Effort/risk:** low / low.

## Sequencing summary

```
P0 (done)
  ├── P1a  (scope isolation, 031 token rebuild, settings, 032 tables, shared predicate)  [ships]
  ├── P1b  (sessions + CSRF/Origin + WebAuthn primitive — the P3 wall)                    [dormant]
  │
  └── P2a  (local read: projections, sanitizer, ro-pool, adapter) ── needs GATE-1a        [ships]
        ├── P2b  (cloud opt-in read) ── owner-gated, needs GATE-2a                          [ships, gated]
        ├── P3   (execution) ── needs GATE-1a + GATE-2a + GATE-1b(the wall)                 [ships, gated]
        └── P4   (remote transport) ── needs GATE-2a, owner-gated                           [ships, gated]
```

Strict order P1a → P2a → P3, with P1b built in parallel (the wall for P3), P2b branching off
P2a behind the owner gate, and P4 branching off P2a. Release P1a then P2a first so scope
isolation, the migrations, the predicate, and the entire local read product land and soak
before any execution or cloud-egress code exists — front-loading the largest injection
surface into phases with zero mutation and zero off-LAN risk.

## Cross-cutting invariants

- **New module vs Core changes.** `vedetta-mcp` is a separate optional binary (proposed
  `backend/cmd/vedetta-mcp` to share `go.mod`; a sibling module only if independent release
  cadence is wanted). Everything else is additive Core change under
  `backend/internal/{auth,api,store}` + new `backend/internal/assistant/{sanitize,policy}` +
  migrations 031/032.
- **Migration discipline.** Forward-only, additive, RFC 5737 / synthetic fixtures only. 031
  (api_tokens REBUILD: scope-CHECK widen + `expires_at`, all constraints/indexes recreated)
  and 032 (assistant_audit / assistant_actions / assistant_action_policy) keep the db.go
  inline runtime-fallback schema at exact parity, guarded by `migration_manifest_test.go`.
- **Audit immutability is a store-shape invariant.** `assistant_audit` has no UPDATE/DELETE
  path in the store; lifecycle rows (approve/reject/execute/reverse) are written ONLY by Core
  from authenticated admin state transitions, never from assistant-supplied fields. Enforced
  by a test that no store method mutates an audit row.
- **Off-by-default everywhere.** `assistant.enabled=false`, `assistant.mode=read_only`, cloud
  opt-in, HTTP/SSE off, full-fidelity QNAME forbidden under any reachable cloud endpoint.
  Policy narrows freely, widens only within a non-editable code ceiling; both severity and
  IOC-strength axes fail closed.

## Risks

- **Net-new WebAuthn/session/CSRF (P1b)** is the critical-path risk for all execution.
  Mitigation: build/test it as its own security-reviewed unit; P1a/P2 ship without it.
- **Injection is assumed not defeated.** Sanitizer/projector reduce but do not eliminate it;
  the real backstops are the code-constant ceiling and the present-human accept. Always
  surface the raw finding beside the summary; `injection_suspected` is a quality signal, never
  the boundary.
- **prepare→accept TOCTOU / drift.** Load-bearing and tested hard: params_hash pin +
  re-derive-from-current-state + void-on-ANY-drift 409 + single-use CAS + fail-closed re-check
  at accept.
- **SQLite writer contention.** `mode=ro` reduces but does not eliminate checkpoint pinning /
  WAL growth; cancellation depends on the driver interrupting blocked calls. Explicit tests
  for writer progress under assistant load, WAL-growth monitoring, and driver cancellation.
- **Cloud egress is the privacy risk.** In MCP the client accumulates conversation, so Core's
  per-result minimization can't retroactively govern data a client already holds. Mitigation:
  full-fidelity QNAME forbidden whenever any cloud endpoint is reachable; whole-session
  minimization; Core-independent loopback verification; same minimizer over rationale +
  context; force-classify non-loopback "local" as remote. Owner-gated at P2b.
- **Ceiling/detection divergence** if the predicate is copied not shared. Mitigation: ONE
  shared function with a differential test (P1a).
- **Supply chain of the MCP dependency tree.** Prefer a lean first-party Go MCP impl; pin by
  exact version+hash; SBOM scan in CI; static hashed tool manifest (rug-pull defense);
  full tool-poisoning audit as a P2b ship gate.

## Constitution check

Every phase is privacy-first (local default, off on fresh install, allowlist-only egress,
never-egress denylist in Core, no telemetry/community coupling), least-privilege (dedicated
non-admin scope isolated via exact-scope + explicit gate membership, admin-superuser rule
untouched), human-in-the-loop / auditable / reversible (every mutation a present-human passkey
accept under the approver's identity, append-only audited), and safe-by-default (subsystem off;
propose-only until the wall ships; stdio/loopback transport; policy narrows-only and fails
closed on both axes). Synthetic / RFC 5737 fixtures only.
