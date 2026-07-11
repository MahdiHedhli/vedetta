# Post-Beta Hardening Backlog

Non-blocking items surfaced by the public-beta security review (Sol **GO** on
`89185fe`). None are beta-gating; none grant access or privilege escalation.
Ready to file as GitHub issues.

---

## 1. Canonicalize `sensor_id` (trim/normalize whitespace) — LOW

`sensor_id` is `hostname-os-arch` and is not canonicalized, so whitespace/lookalike
variants (`...-arm64` vs `...-arm64 `) register as *distinct* identities.

- **Impact:** LOW — a lookalike cannot take over the original or expand authority;
  enrollment/reset authz (bound codes, identity-existence, unique active-token
  index) still holds. Tidiness / anti-confusion only.
- **Fix:** `TrimSpace` + reject embedded control/whitespace chars on
  `POST /sensor/register` and reset-code minting; optionally fold a stable
  machine-id into the sensor-side id to reduce natural collisions.
- **Where:** `backend/internal/api/router.go` (`handleSensorRegister`),
  `sensor/internal/client/core.go`.

## 2. Move `is_primary` election entirely behind the admin route — LOW

`is_primary` is client-controlled on *any* authenticated registration, so a
newly-enrolled sensor (with a valid code) can send `is_primary:true` and demote
the current primary.

- **Impact:** LOW — needs a valid code; only affects primary election.
- **Fix:** move primary election to an admin-only endpoint; ignore client
  `is_primary` on self-registration (keep the auto-promote-first-sensor default).
- **Where:** `backend/internal/store/sensors.go` (`registerSensorOn` `makePrimary`),
  `backend/internal/api/router.go`.

## 3. Tighten enrollment recovery window + existence oracle — LOW / informational

1. Idempotent recovery (#44) lasts ~15 min *from redemption* and codes TTL ~15 min
   *from mint*, so a redeemable `(code, sensor_id)` can be exposed ~30 min from
   mint. Document precisely and/or shorten the redemption-memory TTL.
2. The register endpoint returns distinct 401 bodies for existing vs. unknown
   `sensor_id` (a rate-limited existence oracle). Consider a uniform 401 body.

- **Impact:** LOW / informational — neither grants access.
- **Where:** `backend/internal/api/router.go` (redemption-replay branch),
  `backend/internal/api/enrollment.go` (TTLs).

## 4. Return 500 (not 409) for genuine internal DB errors on register — cosmetic

The mint-block error `switch` maps any non-sentinel `ProvisionSensorToken` error to
`409` ("retry"). A genuine internal DB error is therefore reported as retryable.

- **Fix:** keep `409` only for `ErrSensorExists` / `ErrSensorNotFound` / true
  UNIQUE conflicts; return `500` otherwise.
- **Where:** `backend/internal/api/router.go` (mint block error `switch`).

---

### Also tracked elsewhere
- Rotate the UniFi credentials that leaked into a review transcript (owner action;
  never in the repo).
- Behavioral-sharing telemetry redesign (domain-free `behavior_summary_v2` →
  Privacy Pass + OHTTP → Prio/DAP) — see the project notes; a design brief +
  Sol red-team precede implementation.
