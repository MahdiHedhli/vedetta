# Tasks: LLM Assistant via Model Context Protocol (MCP)

> Spec: `specs/009-llm-assistant/spec.md` · Plan: `specs/009-llm-assistant/plan.md`
> All unchecked — implementation not started. Phases 1b, 2b, 3, 4 are owner-gated.

## Phase 1a - Least-privilege Core foundation (Core-only; subsystem OFF; shippable)

- [ ] Add `ScopeAssistant TokenScope = "assistant"` in `backend/internal/auth/auth.go`;
      leave the `ScopeSatisfies` admin-superuser rule (auth.go:42) UNCHANGED.
- [ ] Add `RequireAssistantRead` middleware admitting `ScopeAssistant` + `ScopeAdmin` by
      explicit membership (not via ScopeSatisfies), 403 for all other scopes.
- [ ] Enforce action-route isolation with `RequireStrictAuth + RequireExactScope(ScopeAssistant)`
      (mirrors the sensor group, router.go ~316) — bypasses ScopeSatisfies so even admin does
      not create actions.
- [ ] Scope tests: exhaustive have×need truth table; negative tests that assistant tokens 403
      on every existing `RequireRead`/`RequireStrictAdmin` route; admin 200 on read gate but
      403 on the exact-scope action gate.
- [ ] Migration `031_api_tokens_expiry.sql`: REBUILD `api_tokens` (SQLite cannot ALTER a CHECK)
      per the migration 021/017 recipe — new `CHECK(scope IN ('sensor','admin','ingest','read','assistant'))`,
      add `expires_at TIMESTAMP NULL`, INSERT-SELECT rows, DROP/RENAME, recreate the `sensors`
      FK, `ux_api_tokens_active_sensor` partial unique index, and `idx_api_tokens_hash/_sensor/_revoked`.
- [ ] Keep the db.go inline runtime-fallback schema at exact parity with 031; update
      `migration_manifest_test.go`. Test 031 against a populated `api_tokens` DB (legacy NULL
      non-assistant tokens preserved).
- [ ] Thread `ExpiresAt *time.Time` through `auth.Token`, `scanAuthToken`,
      `CreateToken`/`GenerateToken` (`store/tokens.go`).
- [ ] In `ValidateToken` (tokens.go:53) reject expired assistant tokens, assistant tokens with
      NULL `expires_at`, and assistant tokens whose expiry exceeds `VEDETTA_ASSISTANT_MAX_TOKEN_TTL`;
      preserve NULL-as-legacy for non-assistant scopes.
- [ ] In `handleCreateToken` accept `scope=assistant` from an admin caller only (never
      bootstrap); server-select a non-NULL `expires_at ≤ max TTL`; add `assistant` to the
      validation-error scope list. Tests: admin issuance sets expiry; non-admin/bootstrap
      rejected; over-max-TTL clamped/rejected; expired-assistant rejected; legacy NULL valid.
- [ ] Add `assistant.enabled` (default false) + `assistant.mode` (default read_only) via
      `SetSetting`/`GetSetting`; admin-only writes through a `RequireStrictAdmin` route;
      `enabled=false` hard-cuts all assistant data/action/projection routes at middleware.
      Keep the assistant settings administration route outside that data-route gate, or
      explicitly exempt it, so administrators can disable and later re-enable the assistant.
      Tests: disable succeeds, all non-settings assistant routes 403/disabled, re-enable succeeds.
- [ ] Migration `032_assistant_tables.sql`: `assistant_audit` (append-only, no UPDATE/DELETE
      path in store), `assistant_actions` (action_id, action_type, target_id, params_json,
      params_hash, server_computed_effect, severity_class, ioc_strength, status, accept_nonce,
      review_window_expires_at, accepted_by, reverse_handle, injection_suspected),
      `assistant_action_policy` (versioned, append-only). Store constructors + manifest test.
- [ ] **Shared assistant-eligibility predicate (first-class):** define a separate
      `trusted_high_confidence_ioc_or_ips` eligibility function in `backend/internal/processing`
      without replacing or changing existing `CreatesFinding` semantics
      (`Detector=="ips" || ScoreContribution>=0.30`, evidence.go:222). The findings processor
      may annotate both values; the assistant policy engine consumes only the shared eligibility
      predicate, never a copy.
- [ ] Differential tests over a shared synthetic corpus assert both outputs independently:
      existing finding-creation behavior is unchanged, and detection plus a policy-engine stub
      compute identical assistant-eligibility results.

## Phase 1b - Human-presence primitive (net-new; the P3 wall; owner security review)

- [ ] Server-side dashboard sessions: HttpOnly + `SameSite=Strict` cookie distinct from API
      bearers; CSRF token; Origin/Host allowlist.
- [ ] `RequireDashboardSession` gate; tests that bearer tokens do NOT satisfy it and it does NOT
      satisfy existing bearer routes.
- [ ] WebAuthn platform-authenticator registration (Touch ID / Windows Hello) bound to the
      admin, stored server-side; assertion-verification library pinned by exact version+hash.
- [ ] `verify-assertion` helper over a supplied `action_id||accept_nonce` challenge, with tests.
      (The accept route that consumes this ships in Phase 3 — this phase delivers a tested
      dependency only.)

## Phase 2a - Read-only assistant, LOCAL only (projections + adapter; shippable)

- [ ] New `/api/v1/assistant` route group behind `RequireAssistantRead` (NOT the generic
      `RequireRead` group): GET `/assistant/findings`, `/findings/{id}`, `/findings/explain/{id}`,
      `/finding-stats`, `/events/summary`, `/devices`, `/status`, `/suppressions`. Each composes
      a FRESH allowlist DTO — must NOT reuse/proxy raw handlers (`api/findings.go`, etc.).
- [ ] Build the composed `explain_finding` verdict server-side (headline / what_tripped /
      confidence{level,score,drivers,caveats} / base_rate / device / recommended_action).
      `base_rate` v1 reuses `handleFindingStats` 7-day aggregates rather than a new per-detector
      table (open item for owner if resolution is poor).
- [ ] New `backend/internal/assistant/sanitize` package: NFC-normalize; strip C0/C1,
      zero-width, bidi (U+202A–202E, U+2066–2069), Unicode Tag block (U+E0000–E007F);
      punycode-decode + homograph-flag; defang domains/IPs/URLs; length-cap (QNAME 253, UA 512,
      description 1KB, log 2KB) with truncation markers; wrap untrusted values in per-response
      nonce-labelled `untrusted_*` containers with the sentinel stripped from the value first.
- [ ] `json.RawMessage` projector (Finding.Details/Evidence, device_context, IdentityEvidence):
      server-side key allowlist, coerce-to-string, recursive control/zw/bidi/tag strip, nesting
      + serialized-size caps, drop unknown keys.
- [ ] Wire an injection-corpus fixture set (RFC 5737 / synthetic) and make the fuzz/property
      test a CI BUILD GATE (build fails if the projector leaks).
- [ ] Projection allowlist test: a later-added models DTO field is dropped by default.
- [ ] NEW module `vedetta-mcp` (proposed `backend/cmd/vedetta-mcp`), stdio transport. Read tools
      ONLY: list_findings, get_finding, explain_finding, finding_stats, summarize_events,
      list_devices, get_system_status, list_suppressions. Provisioned ONLY an assistant token
      (file 0600, never echoed); REFUSES to boot with an admin-scoped token; no
      outbound/network/file tools of its own; egress restricted to Core loopback + the single
      configured LLM endpoint.
- [ ] Static tool manifest as code constants (zero runtime/telemetry-derived content), pinned by
      hash to an in-repo manifest; expose the hash in `/status`. MCP dependency pinned by exact
      version+hash; SBOM-scanned in CI; prefer a lean first-party Go MCP impl.
- [ ] Dedicated read-only SQLite pool (`mode=ro`, WAL, short busy timeout, bounded read txns,
      context deadlines). Hard per-tool caps (max rows, pagination limit≤50, max window,
      byte ceiling); per-session rate limiting; circuit breaker on `/health/detection` ingest lag.
- [ ] Tests: writer progress under concurrent assistant reads; checkpoint/WAL-growth
      monitoring; the driver's query-cancellation limits.
- [ ] First-pass tool-poisoning audit + SBOM scan (full sign-off is a P2b gate).

## Phase 2b - Read-only assistant, CLOUD opt-in (owner-gated privacy boundary)

- [ ] Core-side never-egress denylist (enforced in Core, tested): raw MAC, raw client/source
      IP, per-install HMAC key / SourceHash preimage, tokens/secrets/config, Device.Notes/
      CustomName, bulk DNS QNAME history.
- [ ] Rotating `session_device_alias` from a key DISTINCT from the telemetry HMAC key; Core
      keeps alias→canonical mapping server-side; canonical IDs never in cloud projections.
- [ ] Cloud consent: per-install opt-in AND per-session re-disclosure naming destination,
      retention, and exact field classes that leave (category, priority, eTLD+1 domain, OUI
      vendor, rotating alias); second acknowledgement.
- [ ] Whole-session minimization: full-fidelity raw-QNAME tier FORBIDDEN whenever any
      cloud/remote endpoint is reachable in the session; no mid-session local→cloud downgrade;
      minimized tier applies to the WHOLE session; Core-independent loopback verification; same
      minimizer over model rationale + conversation context. Tests for each.
- [ ] Per-session user-visible egress ledger; TLS-only; no observable/domain/IP/identifier in
      any URL path/query (body-only). Test that no assistant read path can trigger a
      telemetry/community submission.
- [ ] **P2b SHIP gate:** FULL tool-poisoning audit signed off + static hash-pinned-manifest
      verification (the adapter binary reaches users here). Owner sign-off.

## Phase 3 - Human-accepted execution (behind the wall; owner-gated)

- [ ] **THE WALL:** `POST /assistant/actions/{id}/accept` and `.../reject` as NON-bearer routes
      gated by the P1b dashboard session + CSRF/Origin AND a WebAuthn user-verification assertion
      over `action_id||accept_nonce`. Structurally reject all bearers incl. admin. Accept body
      carries ONLY action_id + assertion (+ CSRF). Must not merge until P1b is shipped+tested.
      Tests: bearer (incl. admin) rejected; missing/invalid assertion rejected; assertion for a
      different action_id rejected.
- [ ] Prepare group under `RequireStrictAuth + RequireExactScope(ScopeAssistant)`:
      `POST /assistant/actions` (create pending), `GET /assistant/actions/{id}` (status only,
      never the nonce). The three `request_*` guarded tools return ONLY
      `{action_id, status:'parked'|'awaiting_human_accept', effect_summary}`. `action_id` is high-entropy
      server-generated. Canonical state mapping: `parked` is stored and visible only as a
      count/summary before card delivery; `pending_acceptance` is stored after first delivery
      with the review window and `accept_nonce` active; `awaiting_human_accept` is the API/tool response
      label for a delivered `pending_acceptance` row, never a persisted DB state. At most ONE
      outstanding action per session. Endpoint-response tests cover the mapping.
- [ ] `backend/internal/assistant/policy` engine: `effective = code_ceiling AND admin_policy`
      (narrow-only). Ceiling (non-editable): never resolve/downgrade, never wildcard/standing
      suppress, never act on critical/high, never act on the shared predicate. Fail-closed:
      unknown severity ⇒ blocked; null/unknown ioc_strength ⇒ strong ⇒ suppress blocked.
      Default matrix over the REAL enum {critical, high, medium, low} + unknown: critical/high/
      unknown blocked; medium and low = ack + investigating `requires_human_accept`, suppress
      BLOCKED (admin-widenable). Overlay V1 (trusted-IOC, all actions) and V2 (ioc_strength
      strong/NULL, suppress only). Enforced at BOTH prepare and accept.
- [ ] `PUT /api/v1/assistant/action-policy` behind `RequireStrictAdmin`, versioned +
      append-only audited, assistant read-only via `get_action_policy`. Editable surface = the 6
      cells {medium, low} × {3 actions}; widening a suppress cell auto-inherits suppress friction;
      widen writes an audit row.
- [ ] Execute path: on valid accept re-derive params from CURRENT finding state, re-verify
      params_hash, re-render effect, VOID (409) on ANY material drift; re-check
      ceiling+policy+band+ioc_strength (fail-closed); atomic single-use CAS
      (`UPDATE ... WHERE status='pending_acceptance' AND review_window_expires_at > ?` with a
      Core-supplied UTC timestamp parameter) so replay/double-submit/expired → 0 rows/409;
      consume `accept_nonce`; re-check `assistant.enabled` and the creator assistant token's current
      validity/revocation/expiry state at accept time before execution; execute via the
      BYTE-IDENTICAL guard stack (`SuppressFinding` single-instance at
      finding_suppression.go:22, ack path, finding-status set) under the approver's identity,
      using only stored server params.
- [ ] Review-window semantics: window starts at FIRST card delivery to an accept-capable
      session (ack/investigating 5m, suppress 3m, hard ceiling 10m, admin range [1m,10m]). An
      action with no accept-capable session PARKS; on next login it is RE-PREPARED (fresh
      action_id, re-derive, re-check, fresh `accept_nonce`), never revived stale. Test the
      park→login re-prepare path and the endpoint response mapping above.
- [ ] Real-time approval card over an authenticated session channel (SSE/websocket bound to an
      accept-capable logged-in session, never anonymous/read-tier): server-computed effect diff,
      raw finding, quoted-untrusted rationale, `injection_suspected` banner; suppress renders the
      raw finding before Accept is reachable and captures an approver rationale (audit artifact,
      not a control). Rationale is capped at 512 UTF-8 bytes after normalization, sanitized for
      controls/zero-width/bidi/tag characters, retained with `assistant_audit`, and context-encoded
      on UI/export/log/SIEM output. Optional cloud-session banner naming the cloud model (friction only).
- [ ] Per-token rate limits + circuit breaker auto-pausing abnormal action bursts (reuse
      `api/ratelimit.go`); admin kill switch (`assistant.enabled=false` or token revoke) cuts off
      instantly. Tests prove disabling `assistant.enabled` or revoking/expiring the creator
      token after prepare but before accept causes accept to fail and the pending row to become
      invalid/voided rather than execute.
- [ ] Reversibility surfaced in an operator digest (`DeactivateFindingSuppression` at
      finding_suppression.go:113; unack; restore status). Append-only `assistant_audit`:
      approval/rejection/execution/reversal rows generated ONLY by Core from authenticated admin
      state transitions; test that no store method UPDATE/DELETEs an audit row.
- [ ] Tool-poisoning audit re-run for the added guarded tools; owner sign-off on GATE-3.

## Phase 4 - Remote transport hardening (optional; owner-gated)

- [ ] HTTP/SSE transport in `vedetta-mcp`, opt-in and OFF by default; binds `127.0.0.1` by
      default; explicit tailnet/WireGuard bind only via config; NEVER `0.0.0.0`. Hard-refuse an
      unauthenticated non-loopback listener (test: non-loopback bind without secret fails fast).
      A non-loopback "local" misconfig is force-classified remote for the P2b minimizer.
- [ ] Per-install MCP session secret distinct from the Core token, constant-time compare,
      rotatable. Deny CORS; validate Origin/Host against DNS rebinding. Tests: missing/short/wrong
      secret rejected; Origin/Host mismatch rejected; constant-time compare.

## Delivery

- [ ] Run all Go build/vet/race/migration tests; SBOM + secret + diff/sanitization checks; iCloud
      dup sweep; clean-tree check before any handoff, citing the pushed commit.
- [ ] Update API/schema/operator docs; document forward-only migration + rollback notes.
- [ ] Open draft PRs per shippable milestone (P1a, then P2a); owner-gated phases held for
      sign-off; never self-merge.
- [ ] Request independent adversarial review; address release-relevant findings.

## Constitution check

Each phase stays privacy-first (local default, off on fresh install, allowlist-only egress,
never-egress denylist in Core, no telemetry/community coupling), least-privilege (dedicated
non-admin scope isolated via exact-scope + explicit gate membership, admin-superuser rule
untouched), human-in-the-loop / auditable / reversible (every mutation a present-human passkey
accept under the approver's identity, append-only audited), and safe-by-default (subsystem off;
propose-only until the human-presence primitive ships; stdio/loopback transport; policy
narrows-only and fails closed on both axes). RFC 5737 / synthetic fixtures only.
