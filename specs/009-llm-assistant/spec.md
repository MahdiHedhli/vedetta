# Spec: LLM Assistant via Model Context Protocol (MCP)

Status: **Draft — awaiting owner sign-off (Phase 0).** No code ships against this
spec until it is approved. See [threat-model.md](threat-model.md) for the security
analysis every requirement here traces back to.

Revision note (owner decisions): v1 posture is **human-accepted execution** — "more
than propose, but no action without user acceptance; human in the loop" — and the
**cloud LLM backend is an opt-in part of v1** (a local-only feature would lock out
users without the hardware to run a capable local model).

## Objective

Ship a Vedetta MCP server that lets a prosumer's own LLM — a local model (Ollama,
LM Studio) or a cloud client (Claude Desktop) — **read their security findings,
separate real threats from noise, and troubleshoot**, and **carry a tightly bounded
set of reversible actions to completion, each gated on a genuine, server-
authenticated human acceptance.**

The design treats the LLM as an **untrusted, injectable, confused-deputy-by-default
component**. Every attacker-controllable telemetry string it sees is data, never
instructions; it holds a new least-privilege scope that is never admin; and it can
never mutate protected operational state on its own authority. Its only writes are
explicitly scoped pending actions plus server-generated audit entries for reads and
action submission; a client-supplied `confirmed` flag is never the authorization
boundary. Correctness of the model is a usability property, never a security control.

## User-visible outcome

A non-expert opens their LLM client and asks *"is anything wrong on my network?"*
The assistant answers per finding in plain English: what tripped, a confidence
level **with caveats** ("the threat feed backing this was stale"), a base rate
("findings like this are dismissed as noise 82% of the time"), the device
involved, and one recommended next step.

When the recommended step is a state change, the assistant **prepares** it and asks
the user to accept it — it does not act on its own. A real-time **approval card**
appears in the operator's authenticated Vedetta dashboard showing the exact
server-computed effect, the raw finding, and the model's rationale as visibly-quoted
untrusted text. One present-human **Accept** executes the action in Core, and the
assistant reports "done — applied at 14:03, reversible from the audit log." From the
user's chat view the assistant carried the whole workflow; under the hood, Core
executed only on a real human acceptance the model could not forge. The default local
model keeps everything on the LAN; the cloud backend is opt-in, with an honest
per-session disclosure of exactly what leaves. The operator can always see the raw
finding alongside the narrative, and every assistant read and every action is
auditable and reversible.

## Functional requirements

### Read tools (over dedicated, redacted projections)

No tool proxies a raw `models.*` DTO. Every read goes through a new Core
assistant-projection endpoint that emits an **allowlist-only** redacted shape, so a
struct field added later is dropped by default.

- **`list_findings(status, priority, disposition, session_device_alias, page,
  limit≤50)`** →
  a summarized triage worklist: `{finding_id, detector, category, priority, status,
  disposition, occurrence_count, first/last_seen, allowed/blocked/observed counts,
  sanitized title, session_device_alias, needs_identification}`. The raw primary
  observable is not emitted — only `observable_type` and a **defanged** form. Backed
  by a new `GET /api/v1/assistant/findings`, never raw `/findings`.
- **`get_finding(finding_id, evidence_limit, event_limit)`** → exactly these
  top-level keys and no raw Finding DTO fields: `{finding_id, detector, category,
  priority, status, disposition, occurrence_count, first_seen, last_seen,
  observable{type,defanged_value}, device{session_alias,type,is_new,
  needs_identification},
  reason, recommended_action, evidence[], supporting_events_summary,
  injection_suspected}`. Every user-, device-, feed-, and event-controlled string is
  emitted only through the sanitizer: NFC-normalized, control/zero-width/bidi/tag
  stripped, defanged when it looks like a domain/IP/URL, length-capped, and wrapped
  in nonce-labelled `untrusted_*` containers. `evidence[]` is bounded by
  `evidence_limit` and may contain only `{detector, category, rationale,
  observable_type, defanged_observable, source_confidence, feed_freshness,
  score_contribution, outcome}`. `supporting_events_summary` is count-only by
  source/outcome/window and never includes raw rows. `json.RawMessage` blobs
  (`Finding.Details`/`Evidence`, `device_context`, `IdentityEvidence`) are excluded
  from the projection and may only contribute values after allowlist projection and
  sanitization — see [Injection hardening](#injection-hardening).
- **`explain_finding(finding_id)`** — the flagship. A **composed verdict**, not an
  endpoint passthrough: `{headline, what_tripped, confidence{level,score,drivers,
  caveats}, base_rate{how_common, similar_total, dismissed_pct, interpretation},
  device{session_alias,is_new,needs_identification}, recommended_action{verb,
  guarded_tool_to_call, reversible}}`. `recommended_action` only **names** a guarded
  tool; it never executes. This is the core "triage for non-experts" surface.
- **`finding_stats()`** → 7-day aggregate counts by priority/status/disposition;
  feeds `explain_finding`'s base rate. No attacker-controlled strings.
- **`summarize_events(window, bucket, session_device_alias?, category?)`** →
  aggregate/timeline counts only, never raw event rows (event bodies carry the most
  attacker-controlled content).
- **`list_devices(new_only, needs_identification, page, limit)`** → per device
  `{session_device_alias, sanitized display_alias, OUI-derived vendor (low trust),
  is_new, needs_identification, active_finding_count}`. Raw MAC, raw hostname,
  `CustomName`, and `Notes` are never emitted.
- **`get_system_status()`** → Core health, sensor liveness, detection-pipeline/feed
  freshness, and update posture through assistant-projection endpoints. It may reuse
  existing status query internals, but it must not authorize the assistant token
  against generic `RequireRead` routes. Backs the troubleshooting use case.
- **`list_suppressions()`** → existing finding-suppression rules so the model can
  avoid recommending a duplicate or over-broad suppression.
- **`get_action_status(action_id)`** → the lifecycle status of a pending action
  (`awaiting_human_accept` | `accepted` | `executed` | `rejected` | `expired`).
  **Never** returns the accept nonce or any accept material — status only.
- **`get_action_policy()`** *(optional)* → the effective severity/risk policy, so the
  model avoids requesting a blocked action and can explain a refusal. Read-only.

### Guarded tools (human-accepted execution)

Each guarded tool **creates a pending action** and performs no mutation. It returns
**only** `{action_id, status:"awaiting_human_accept", effect_summary}` — no accept
link/URL and no nonce. Execution happens only on a present-human accept (see
[Human-accepted execution](#human-accepted-execution-the-security-boundary)).

- **`request_acknowledge_event(event_id, rationale)`** — lowest risk; reversible ack.
- **`request_set_finding_status(finding_id, status='investigating', rationale)`** —
  *investigating* only (does not hide the finding). Never `resolved`, never downgrade
  out of active, never act on critical/high.
- **`request_suppress_finding_as_noise(finding_id, rationale)`** — highest risk.
  Scoped to the **single current finding instance**; it never creates a
  standing/pattern/wildcard future-matching rule. Hard-blocked on critical/high and
  on any finding where the shared findings processor classifies evidence as
  `trusted_high_confidence_ioc_or_ips` per spec 007 ("Every trusted high-confidence
  IOC/IPS result can create a finding regardless of allowlist, blocked state, or
  suppression"). Community-only evidence stays advisory, but a community-corroborated
  public IOC linked to trusted IOC/IPS evidence is included in the same predicate.
  Un-suppression stays human/admin-only.

### Least-privilege scope

Add `ScopeAssistant TokenScope = "assistant"` in `backend/internal/auth/auth.go`.
`ScopeAssistant` is a distinct, non-hierarchical scope: it satisfies itself only,
never `ScopeRead` or `ScopeAdmin`. `ScopeAdmin` continues to satisfy `ScopeRead` for
the existing dashboard/API hierarchy, but does not satisfy `ScopeAssistant`.
Existing generic `RequireRead` route groups remain unavailable to assistant tokens,
including raw events, devices, findings, and status endpoints that were not designed
as assistant projections.

Add an assistant-read gate for the new projection route group only, for example
`RequireAssistantRead`, that admits `ScopeAssistant` and `ScopeAdmin` but always
returns 403 for other scopes. Assistant tokens read only these allowlisted
projection endpoints; admins may inspect the same projection shape for debugging.
Admins mint assistant tokens and approve proposals through strict-admin routes, but
they do not call assistant-proposal routes under admin scope.

The assistant credential's only write is creating a pending action:
`POST /api/v1/assistant/actions` and reading its status `GET
/api/v1/assistant/actions/{id}`, both gated by
`RequireStrictAuth + RequireExactScope(ScopeAssistant)` (mirrors the sensor group):
strict auth closes the zero-token bootstrap bypass; exact-scope keeps action
provenance clean (even an admin token does not create actions). The
**accept/reject** routes — `POST /api/v1/assistant/actions/{id}/accept` and
`.../reject` — are the security boundary and are **not** bearer routes: they are
gated by the human-presence primitive below and **structurally reject all bearer
tokens, including admin**. **Every existing `RequireStrictAdmin` mutation route is
left untouched** — the assistant scope literally cannot call any of them.

Token minting stays `RequireStrictAdmin`: `handleCreateToken` accepts
`scope=assistant` alongside `admin`, `ingest`, `read`, and `sensor` only from an
admin caller, never during bootstrap; its validation error must list `assistant`.
Assistant tokens always receive a non-NULL, server-selected `expires_at` no later
than the configured maximum assistant-token TTL. The `api_tokens` migration adds
`assistant` to the stored scope constraint, adds `expires_at`, and updates the
token model plus persistence/issuance path to store assistant expirations
(forward-only migration; `NULL` = legacy for non-assistant scopes only);
`ValidateToken` rejects expired assistant tokens, assistant tokens with NULL
`expires_at`, and assistant tokens whose expiry exceeds the configured bound while
preserving NULL-as-legacy behavior for existing non-assistant tokens. Tests cover
admin issuance, rejected non-admin/bootstrap issuance, max-TTL enforcement, expired
assistant rejection, and legacy non-assistant NULL compatibility. The adapter is
provisioned only an assistant token (file mode `0600`, never echoed into
output/logs/prompts) and **refuses to boot with an admin-scoped token**.

### Human-accepted execution (the security boundary)

The assistant **prepares** an action but Core **executes** only on a real,
server-authenticated, **present-human** acceptance the model/adapter/local-harness
cannot forge, auto-trigger, or replay. Client-side confirmation is never the
boundary (a local harness can auto-approve). The boundary is
**model-location-independent**: the accept is always the operator's **local** session
against Core on the LAN, so a cloud-hosted model changes only egress/injection stakes,
never the auth model.

**Flow.**
1. **Prepare.** The guarded tool calls `POST /assistant/actions`. Core evaluates the
   code-constant ceiling **and** the severity/risk policy server-side, rejects
   ineligible targets early with a typed refusal the model can relay, computes the
   exact action + effect diff **from the params** (never model text), and inserts an
   `assistant_actions` row: `{action_id = high-entropy server-generated (never
   model-supplied), action_type, target_id, params_json, params_hash pinned at
   create, server_computed_effect, severity_class, ioc_strength,
   status='pending_acceptance', accept_nonce (server-only, never on any MCP channel),
   expires_at = now+TTL (default ~5m), accepted_by=NULL, reverse_handle,
   injection_suspected}`. It does not mutate; it returns only the pending handle.
2. **Card (low-friction, not the boundary).** Core pushes the card only to
   accept-capable operator sessions over an authenticated session channel (never an
   anonymous/read-tier subscriber): the server-computed effect diff, the raw finding,
   the quoted-untrusted rationale, and an `injection_suspected` banner. If no
   accept-capable session is connected, the action queues and a pending count surfaces
   on next login — it does not silently expire into a re-propose loop.
3. **Accept (the boundary).** Reachable **only** from the server-rendered card, and
   requires a **human-presence primitive a bearer token cannot satisfy**:
   - **Primary (owner-chosen):** a WebAuthn/passkey **user-verification** assertion
     bound to `action_id || accept_nonce` — Core issues a challenge derived from those
     values and accepts only after validating the returned challenge, `webauthn.get`
     type, RP ID, origin, registered operator credential, and user-verification flag.
     The model host cannot produce a user-verified assertion, so accept is provably a
     present human bound to the exact action. The preferred UX is a **platform
     authenticator** (Touch ID / Windows Hello) — one tap — while cross-platform
     authenticators such as hardware security keys remain a supported fallback for
     operators without platform biometric/PIN hardware. (Owner considered a session-only
     accept given the bounded, reversible action set, but a session proves "a browser is
     logged in," not "a human approved this now"; a platform-passkey tap is nearly
     frictionless and is the chosen v1 default.)
   - **Supporting browser hardening:** real server-side dashboard sessions (HttpOnly,
     `SameSite=Strict` cookie + CSRF + Origin/Host allowlist) **distinct from API
     bearers**; the accept route rejects **all** bearer tokens (admin included).
     Session + CSRF/Origin checks are not sufficient human presence by themselves; if
     WebAuthn/passkey or an equivalent step-up/user-presence primitive is absent, v1
     remains propose-only.

   The accept body carries **only** `action_id` (+ the WebAuthn/equivalent step-up
   proof, with any browser CSRF token as supporting channel hardening) and zero params.
4. **Execute.** On a valid accept, Core: re-derives params from **current** finding
   state and re-verifies `params_hash`; re-renders the effect and **voids (409, forces
   a fresh request)** on **any** material drift — not just severity escalation but any
   change (e.g. an identity merge that grew the finding between render and accept);
   re-checks ceiling + policy + severity/IOC-strength (fail-closed); performs an atomic
   single-use compare-and-set (`UPDATE ... WHERE status='pending_acceptance' AND
   expires_at>now()`), so replay/double-submit/expired all resolve to 0 rows / 409;
   consumes the nonce; then executes the underlying mutation through the
   **byte-identical guard stack** the direct-admin dashboard route uses (or with all
   checks in the handler body, never route-group middleware), **under the human
   approver's identity**, using only stored server params.
5. **Loop-close.** The model polls `get_action_status(action_id)` (status only) and
   reports completion. TTL and any bounded long-poll are UX-only, never load-bearing.
   At most **one outstanding pending action per session** so chat narrative and card
   cannot be desynchronized into wrong-action acceptance.

> **Hard prerequisite.** The human-presence primitive is a **code-first Phase-3
> prerequisite, not an open question.** Vedetta's current auth is Bearer-only (no
> cookie/session/CSRF); a `RequireStrictAdmin`-only accept route would degrade to
> "possession of an admin bearer executes," and the model's own host is in-scope to
> reach that. **Until the human-presence primitive ships and is tested, the assistant
> is capped at propose-only** and the spec must not claim a human-execution boundary.

Server-side hard constraints, enforced regardless of the model (evaluated at **both**
prepare and accept): assistant-scope suppression affects only the single current
finding and provably cannot install or reuse a future-matching rule (the
instance-write is separated from the rule-write in the store); the assistant can never
set `resolved` or downgrade out of active; critical/high findings and findings
matching the shared `trusted_high_confidence_ioc_or_ips` predicate are ineligible for
assistant status-change or suppression; per-token rate limits + a circuit breaker
auto-pause on abnormal action bursts; and an admin-only kill switch
(`assistant.enabled=false`, or revoke the token) cuts off instantly.

**Hard rule:** community or LLM output can never *silently* resolve, downgrade,
suppress, or reprioritize a finding. Every such change is a present-human acceptance
with an audit trail. The assistant can only **add friction**, never **relax** detection.

### Severity/risk policy layer (to-be-finalized)

A configurable, Core-enforced policy governs per-class eligibility. **Owner has not
finalized the bands/axis/friction** — only the construction and a conservative default
are fixed here.

- **Construction (non-negotiable):** `effective = code_constant_ceiling AND
  admin_policy`. Policy can only **narrow**, never widen. The ceiling is a **code
  constant** (not editable matrix cells): never resolve/downgrade, never
  wildcard/standing suppress, never act on critical/high or the shared
  `trusted_high_confidence_ioc_or_ips` predicate. A misconfigured, injected, or
  mis-migrated policy therefore fails **safe** (blocks more).
- The configurable surface is only `{medium, low, info} × {ack_event,
  set_status_investigating, suppress_as_noise}`; cells are `{blocked |
  requires_human_accept}` — there is **no** "auto" or "standing pre-authorization"
  cell in v1.
- Core-stored, **strict-admin-write only** (`PUT /api/v1/assistant/action-policy`),
  versioned + append-only audited, **assistant read-only**. Enforced at **both**
  prepare-time and accept/execute-time (closes the prepare→accept TOCTOU).
- **Fail-closed on both axes:** unknown/unclassified **severity** ⇒ most-restrictive
  (blocked); null/unknown/unenriched **IOC-strength** ⇒ treated as **strong** (blocked)
  — a medium finding with `ioc_strength=NULL` (enrichment pending) is ineligible for
  suppression.
- **Conservative default (ships safe; owner may tighten/loosen within the ceiling):**
  critical/high/trusted-IOC = blocked (ceiling); medium = ack + investigating via
  `requires_human_accept`, suppress **blocked**; low/info = all three via
  `requires_human_accept`.
- **To-be-finalized (owner-gated):** which bands are eligible; severity-only vs
  severity × confidence × IOC-strength; discrete classes vs a continuous risk score +
  threshold; per-class friction (typed justification / step-up WebAuthn on
  higher-risk-but-eligible accepts); per-action TTL; whether policy is stricter under a
  cloud model. **Recommendation: no standing pre-authorization in v1.**

### Injection hardening

Injection is assumed **not** defeated; these controls reduce it, but the real
backstops are the scope ceiling and the human-presence accept.

- **Data/instruction separation.** Telemetry is placed only in the tool-**result**
  channel under typed `untrusted_*` keys — never concatenated into system prompts,
  tool descriptions, or any instruction position.
- **Nonce-delimited untrusted containers.** Every untrusted field is wrapped in a
  per-response, nonce-labelled container; the value is stripped of the sentinel/nonce
  first so injected content cannot forge a closing tag. A standing system-prompt
  contract states that such content is observed network data to analyze, never
  instructions, and can never authorize a tool call.
- **Unicode hardening** before egress: NFC-normalize; strip C0/C1 controls,
  zero-width chars, bidi overrides (U+202A–202E, U+2066–2069) and the Unicode Tag
  block (U+E0000–E007F); punycode-decode domains and flag homographs.
- **Length caps** with explicit truncation markers (hostname/QNAME 253, User-Agent
  512, description 1 KB, log line 2 KB).
- **Never emit `json.RawMessage` blobs raw.** Project through a server-side key
  allowlist, coerce to strings, recursively strip control/zero-width/bidi/tag chars,
  cap nesting depth and serialized size, drop unknown keys. The projector is
  fuzz/property-tested against adversarial blobs as a build gate.
- **Defang** all URLs/domains; no clickable links.
- `injection_suspected` flags instruction-shaped fields as a **quality signal**
  surfaced on the approval card — never as the security boundary.
- **Static tool manifest.** Tool names/descriptions/schemas are code constants with
  zero runtime/telemetry-derived content, pinned by hash to an in-repo manifest
  (rug-pull defense); the hash is exposed in `/status`.

### Privacy & data egress

- **Local-first, off by default.** The whole subsystem is off on a fresh install
  (`assistant.enabled=false`, `assistant.mode=read_only`) until an admin mints a
  token **and** flips the mode. Local model is the default and the only
  fully-private path.
- **Cloud is an opt-in v1 backend** (not deferred): opt-in per install **and**
  re-surfaced per session with an honest disclosure that names the destination, states
  retention, and enumerates exactly which field classes leave (category, priority,
  registrable domain, OUI vendor, rotating device alias) vs. which never do. Cloud
  requires a second explicit acknowledgement.
- **Full-fidelity is a property of the session's ultimate model destination, not the
  MCP transport.** In MCP the *client* accumulates the conversation, so Core's
  per-result minimization cannot retroactively govern data a client already holds
  before it talks to cloud next turn, and "verified loopback" is meaningless when the
  loopback client *is* a cloud client. Therefore the full-fidelity (raw QNAME) tier is
  **forbidden whenever any cloud/remote endpoint is configured or reachable in the
  session**; no local→cloud downgrade mid-session; the minimized tier applies to the
  **whole session** including previously-fetched data; Core **independently verifies
  loopback** (Core makes the full-fidelity LLM call itself to a verified loopback
  endpoint, or full QNAME is gated behind distinct per-request consent confirming that
  Core-verified loopback destination) rather than trusting an adapter-declared
  endpoint. Per-request consent can never select a remote/cloud destination and can
  never override the cloud/remote full-fidelity prohibition; a non-loopback "local"
  misconfig is force-classified remote. The **same Core-side minimizer** applies to the model
  rationale and any conversation context egressed to cloud, not just tool telemetry.
- **Never-egress denylist, enforced in Core** (not the adapter) and tested: raw
  MAC, raw client/source IPs, the per-install HMAC key / `SourceHash` preimage, API
  tokens/secrets/config, `Device.Notes`/`CustomName` free text, and full bulk DNS
  QNAME history must never appear in any projection response or tool parameter.
- Redaction happens **server-side before the byte leaves Core**; the adapter is a
  dumb pipe over already-minimized data. Cloud projections always emit domain
  observables at registrable-domain (eTLD+1) granularity, including public IOC
  matches; no public-IOC exception bypasses this minimization. Full raw QNAME is
  reachable only on a verified-loopback local endpoint behind explicit per-request
  consent, and that endpoint is disabled for cloud transports.
- Device aliases are session-scoped and rotating, derived from a key **distinct**
  from the telemetry HMAC key, so a provider cannot build a durable cross-session
  identity graph. Tool outputs and tool parameters use `session_device_alias`; Core
  keeps the per-session alias-to-canonical-`device_id` mapping server-side and never
  sends canonical persistent device IDs in cloud projections.
- **No coupling to telemetry/community.** No assistant read or action path can
  trigger an outbound telemetry or community-DB submission (verified by test); the
  "community data never linked to install/UID/IP" guarantee is untouched.
- A per-session, user-visible **egress ledger** ("this session sent N findings /
  M bytes to <destination>"); TLS-only; no observable/domain/IP/identifier ever in a
  URL path or query string (body-only).

### MCP transport & adapter hardening

- **stdio is the default transport** (client spawns the adapter locally). HTTP/SSE
  is opt-in and off by default; when enabled it binds `127.0.0.1` by default, allows
  an explicit tailnet/WireGuard bind only via config, and **never `0.0.0.0`**; the
  server hard-refuses to start an unauthenticated non-loopback listener.
- HTTP/SSE requires a per-install MCP session secret (distinct from the Core token,
  constant-time compare, rotatable); deny CORS; validate Origin/Host against DNS
  rebinding.
- The adapter has **no outbound/network/file tools of its own**; egress is
  restricted to the Core loopback API and the single configured LLM endpoint.
- Hard server-side caps on every read tool (max rows, mandatory pagination, max time
  window, response-byte ceiling), per-session rate limiting, and query deadlines.
  Assistant reads use a dedicated read-only SQLite connection pool opened with
  `mode=ro`, WAL journal mode, a short busy timeout, bounded read transactions, and
  context deadlines on every query. This reduces writer contention but is not magic:
  long reads may still pin checkpoints and grow the WAL, and cancellation behavior
  depends on the SQLite driver actually interrupting blocked calls. Tests must cover
  writer progress under assistant reads, checkpoint/WAL-growth monitoring or
  mitigation, and the selected driver's query-cancellation limits.
- Runs unprivileged with resource limits; a circuit breaker sheds assistant load
  when `/health/detection` shows ingest lag.
- MCP/transport dependencies pinned by exact version + hash (prefer a lean
  first-party Go implementation over a large tree), SBOM scanned in CI. Run the
  tool-poisoning audit as a pre-ship gate.

### Audit, reversibility, kill switch

Every read and every proposed/approved/rejected/executed action writes an
**immutable, append-only** `assistant_audit` row (actor = assistant token id,
model/deployment id, transport = local vs cloud, evidence hash, rationale,
`injection_suspected`, human-approver id, lifecycle state) that no scope can update
or delete. Assistant-originated audit entries are limited to server-generated read
and proposal-submitted events; approval, rejection, execution, and reversal audit
rows are generated only by Core from authenticated admin state transitions, never
from assistant-supplied lifecycle fields. Every assistant-caused mutation is
reversible (deactivate suppression, unack, restore status) and surfaced in an
operator digest. An admin-only kill switch (`assistant.enabled=false` and token
revoke) is always present.

## Phasing

- **Phase 0 (this spec):** author spec + threat model; owner sign-off; no code.
- **Phase 1 — least-privilege foundation:** `ScopeAssistant` + the `ScopeSatisfies`
  self-scope rule + assistant-read middleware + negative/positive scope tests;
  `api_tokens.expires_at` migration + TTL enforcement;
  `assistant.enabled`/`assistant.mode` settings (default off/read-only);
  `assistant_audit`, `assistant_actions`, and `assistant_action_policy` tables
  (forward-only); **human-presence-primitive groundwork** (WebAuthn/passkey or
  equivalent step-up, plus browser-session CSRF/Origin hardening), since it gates Phase 3.
- **Phase 2 — read-only assistant, local + cloud:** dedicated assistant-projection
  endpoints (allowlist DTOs) + the sanitizer/hardening layer with the injection-corpus
  build gate; the stdio MCP adapter with **read tools only**; **both** the local
  backend and the cloud opt-in read path, with cloud consent + redaction tier + egress
  ledger + whole-session minimization as Phase-2 acceptance criteria. Delivers the full
  "help me triage" value with zero mutation capability; independently shippable.
- **Phase 3 — human-accepted execution:** `POST /assistant/actions`, the `request_*`
  tools, the accept/reject routes behind the **human-presence primitive (hard
  prerequisite)**, the real-time card, severity-policy enforcement at prepare + accept,
  rate limits/circuit breaker/kill switch, reversibility + operator digest.
  Backend-agnostic. Gate: every acceptance gate green + tool-poisoning audit signed off.
- **Phase 4 — remote transport hardening:** HTTP/SSE session secret, loopback/tailnet
  bind, origin checks (for split-host local models). (The old standalone "cloud" phase
  is folded into Phase 2.)

Phases 3 and 4 are owner-gated per the spec-kit human-gate convention.

## Migration and compatibility

- Additive, forward-only migrations: extend the `api_tokens` scope constraint to
  include `assistant`, add `api_tokens.expires_at` (NULL = legacy unaffected for
  non-assistant scopes), add `assistant_audit`, `assistant_actions`,
  `assistant_action_policy`, and `assistant.*` settings.
- `ScopeAssistant` is additive and does not change existing `ScopeRead` /
  `ScopeAdmin` authority. Existing `RequireRead` / `RequireStrictAdmin` route groups
  are unchanged for current tokens, while assistant access is isolated to the new
  assistant projection and action route groups; the accept/reject routes require the
  new human-presence primitive and no bearer token can reach them.
- The MCP adapter is a separate, optional component; Core with the assistant
  subsystem disabled behaves exactly as today.

## Non-goals

- **No autonomy and no direct-execute mode** (no `execute_bounded` tool). The model
  never executes on its own authority and cannot forge, guess, auto-trigger, or replay
  a human accept. "More than propose" means loop-closure + a real-time bound accept —
  execute-on-accept is Core acting under the human approver, not the LLM.
- **No policy setting can yield model/local-harness auto-execution** or relax the
  critical/high + trusted-IOC ceiling. **No standing pre-authorization in v1.**
- The assistant scope does not expose token minting/revocation, sensor
  enrollment/management, device confirm/merge/update, whitelist writes,
  pattern/global suppression CRUD, scan triggering, or settings/telemetry writes —
  those stay strict-admin, dashboard-only.
- The assistant can only **add friction** (ack, mark investigating, suppress one
  finding instance), never **relax** detection: no wildcard/pattern/standing
  suppression or whitelist, no deleting existing safety rules, no resolve/downgrade,
  no action at all on critical/high findings or findings matching the shared
  `trusted_high_confidence_ioc_or_ips` predicate.
- Not a cloud data pipeline by default; local is the only fully-private path and the
  default. No community/telemetry submission ever occurs on the assistant path.
- Not a new privileged Core trust boundary or a new default listening service
  (stdio-first); no on-box ML runtime is added to Core.
- Raw event bodies are out of scope for v1 tool output (summaries/evidence only).
- Client-side confirmation is not a security control; a misleading model *narrative*
  within read-only bounds is a residual risk, mitigated by always surfacing the raw
  finding alongside the assistant summary.

## Constitution check

- **Privacy-first:** local default, off on fresh install, allowlist-only redacted
  egress, never-egress denylist in Core, no telemetry/community coupling.
- **Least privilege:** dedicated non-admin scope; the credential can read (via the
  assistant-read gate) + create a pending action, nothing else; accept is a separate
  human-presence boundary that rejects all bearers.
- **Human-in-the-loop / auditability / reversibility:** every mutation is a present-
  human accept under the approver's identity, append-only audited, reversible.
- **Safe by default:** subsystem off by default; propose-only until the human-presence
  primitive ships; stdio/loopback transport; hard refusal of unauthenticated
  non-loopback listeners; policy narrows-only and fails closed.
- **No homelab data:** spec, threat model, and fixtures use RFC 5737 / synthetic
  values only.

## Open questions for owner

1. *(Resolved)* v1 posture = **human-accepted execution** (more than propose; no action
   without a genuine present-human accept) — not propose-only, not direct-execute.
2. *(Resolved)* Cloud is **in v1** as an opt-in backend, not deferred.
3. *(Resolved in review)* The non-actionable ceiling is bound to spec-007's shared
   `trusted_high_confidence_ioc_or_ips` predicate (plus critical/high).
4. *(Resolved)* Human-presence primitive = **WebAuthn/passkey user-verification via a
   platform authenticator by default** (Touch ID / Windows Hello) — one tap, with
   cross-platform authenticators supported as fallback — bound to
   `action_id || accept_nonce`. Real server-side sessions (HttpOnly `SameSite=Strict`
   cookie + CSRF + Origin/Host, rejecting all bearers incl. a stolen admin bearer) are
   the required transport hardening beneath it, but are not sufficient human presence by
   themselves. Still a code-first Phase-3 prerequisite (Vedetta has neither sessions nor
   WebAuthn today).
5. **Severity/risk policy (to-be-finalized):** eligible bands; severity-only vs
   severity × confidence × IOC-strength; discrete vs continuous score; medium-suppress
   default (proposed: **blocked**); per-class friction; per-action TTL; stricter under
   a cloud model?
6. **Accept UX vs security:** confirm pending-action TTL (~5m) and any bounded long-poll
   are UX-only; confirm one-outstanding-pending-action-per-session.
7. **Card transport:** confirm SSE/websocket bound to an accept-capable logged-in
   session (no anonymous/read-tier subscriber); confirm queue+notify (not silent-expire)
   when no operator session is connected.
8. **Cloud minimization scope:** confirm the Core-side minimizer covers the model
   rationale + conversation context egressed to cloud, and Core-independent loopback
   verification for any full-fidelity path.
9. **Carried over:** `base_rate` backing (new per-detector aggregate vs existing stats);
   token lifecycle (short-TTL manual vs auto-rotating — matters more with a cloud
   client); audit home (Core SQLite vs SIEM export); per-token read + action rate limits
   + circuit-breaker thresholds for a single-operator homelab; adapter co-location over
   loopback with the deploy's real Core port; optional one-click Reject-with-reason
   feeding noise learning (quoted-untrusted the same way).
