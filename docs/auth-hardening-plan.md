# Vedetta Admin Auth Hardening Implementation Plan

**Goal:** Complete VED-007 (Move dashboard-facing sensor management routes under admin auth) + deliver the broader first phase of UI authentication so the product is safe for alpha users who want to expose the dashboard on their LAN.

**Date:** 2026-04 (current session)
**Status:** In progress (autonomous execution)

## Current State (Audit Summary)

### What is already solid
- Excellent token model (`auth.Token` with `ScopeAdmin` / `ScopeSensor`)
- `GenerateToken`, `HashToken`, storage in `api_tokens` table (14th migration)
- `RequireAuth` (bootstrap bypass when zero tokens) + `RequireStrictAuth`
- `RequireScope` and `RequireExactScope` middleware
- Sensor m2m path is correctly locked down (`/sensor/devices`, `/dns`, `/work` use `RequireStrictAuth` + `ExactScope(Sensor)`)
- `handleSensorRegister` has good logic for one-time token minting + re-registration with existing token
- `POST /auth/tokens` already has bootstrap logic (first token can be created without auth)
- `handleSetupStatus` already reports `auth_configured: tokenCount > 0`

### The gaps (why this task exists)
1. **Two routes explicitly called out in code** (router.go:117-120):
   - `GET /api/v1/sensor/list`
   - `PUT /api/v1/sensor/{id}/primary`
   These sit **outside** any auth middleware inside the `/sensor` group. Once any admin token exists, they will start 401'ing the dashboard.

2. **Almost the entire dashboard surface is still unauthenticated**:
   - All device management, suppression, whitelist, scan targets, manual scans, events ack, logs, etc.
   - The frontend currently makes zero `Authorization` headers.

3. **No UI path to create the first admin token** or persist it for subsequent calls.

4. **No logout / token management surface** in the SPA (though backend handlers exist).

## Design Decisions (for this implementation)

### Protection Model (Pragmatic for Alpha Self-Hosted)
- **Public (always allowed)**:
  - `/status`, `/version`, `/healthz` (liveness), `/readyz` (readiness)
  - `/auth/setup-status`
  - `POST /auth/tokens` (special bootstrap behavior already exists)

- **Admin scope required** (once ≥1 token exists in DB):
  - Every other `/api/v1/*` route the dashboard uses (list devices, update device, suppression, whitelist, scan targets, trigger scan, logs, sensor list + set primary, list/revoke tokens, etc.)

- **Sensor scope (already correct)**:
  - Sensor ingest + work endpoints.

- **Rationale**: For a homelab/SMB self-hosted tool, requiring an admin token for the UI after initial setup is the expected and safest model. Bootstrap mode makes first-run painless.

### Frontend Auth Strategy (Minimal Friction)
- Use **localStorage** to hold one admin bearer token (simple and works offline).
- Create a tiny `useAuth` hook or fetch wrapper that automatically adds `Authorization: Bearer <token>` to all API calls.
- On first run (`auth_configured: false`):
  - Show a prominent "Create Initial Admin Access Token" step in the existing setup flow (or a new modal).
  - Call `POST /auth/tokens { "scope": "admin", "label": "Initial Admin" }`
  - Display the raw token **once** with strong "copy and save" warning.
  - Auto-store it in localStorage and reload the app authenticated.
- If token is missing or 401s, show a "Enter Admin Token" prompt (paste field) — allows recovery without container shell.
- All existing fetch calls will be upgraded to go through an authenticated fetch helper.

This pattern is battle-tested in many excellent self-hosted projects.

## Implementation Phases (Execution Order)

### Phase A — Backend Hardening (No UI breakage yet)
1. Create a new middleware helper `RequireAdminAuth` (or reuse `RequireAuth` + `RequireScope(ScopeAdmin)`).
2. Move the two sensor management routes under admin protection.
3. (Optional but recommended) Wrap the largest groups of dashboard routes under a single admin-protected sub-router to avoid repetition.
4. Ensure `POST /auth/tokens` continues to work for the very first admin token.
5. Add a small helper to reject non-admin tokens on sensitive mutating endpoints if we want defense-in-depth.
6. Update `handleSetupStatus` if needed to expose more auth state.

**Deliverable**: Backend now properly 401/403s when an admin token is required and none is presented. Old bootstrap behavior preserved for zero-token installs.

### Phase B — Frontend Auth Layer
1. Create `frontend/src/lib/api.js` (or add at top of App.jsx for now) with:
   - `getAuthToken()`, `setAuthToken()`, `clearAuthToken()`
   - `authFetch(url, options)` wrapper that adds the header.
2. Replace (or monkey-patch) the existing `fetch(...)` calls in App.jsx to use `authFetch`.
3. Add state: `adminToken`, `isAuthenticated`.
4. Modify the existing `SensorSetupDialog` (or add a new "Admin Access" step) to include:
   - "Create Initial Admin Token" button (only visible when !auth_configured).
   - Display + copy of the returned raw token.
   - "I have saved the token" → store it → continue.
5. Add a "Settings → Admin Tokens" section (or a simple "Authenticated as Admin" badge + "Manage Tokens" that calls the existing `/auth/tokens` endpoints).
6. Handle 401 responses globally: show "Session expired / token invalid" + re-enter token prompt.

**Deliverable**: Dashboard can create, store, and use an admin token. All current functionality continues to work when a token is present.

### Phase C — Polish + Hardening
1. Protect the remaining sensitive routes explicitly (even if we do a broad admin group, double-check mutating ones).
2. Add "Revoke this token" / "Create new admin token" flows in the UI.
3. Improve error messages ("Admin access required — please provide an admin token").
4. Update `handleSetupStatus` response to be richer for the UI wizard.
5. Add basic tests (router_test.go style) for the new protected routes.
6. Update docs/backlog.md, mark VED-007 done, add short note in architecture.md and README "Alpha Auth Model".

## Risk Mitigation (Important for Autonomous Work)

- **Backward compatibility for zero-token installs**: Must remain fully open (current behavior).
- **One-token bootstrap UX**: The very first `POST /auth/tokens` must succeed without any header.
- **Token display only once**: Backend already does this correctly; UI must not re-fetch the raw value.
- **Lost token recovery**: Provide a clear "Paste existing admin token" path + document that container shell + `sqlite3` can be used as last resort.
- **No breaking change to sensor side**: Sensor tokens must continue working exactly as today.

## Files That Will Change

**Backend**:
- `backend/internal/api/router.go` (main wiring)
- `backend/internal/api/auth_handlers.go` (minor improvements)
- Possibly new middleware helper in `backend/internal/auth/middleware.go`
- `backend/internal/api/router_test.go` (new tests)

**Frontend**:
- `frontend/src/App.jsx` (heavy changes — consider extracting later)
- New: `frontend/src/lib/api.js` (recommended for cleanliness)

**Docs**:
- `docs/auth-hardening-plan.md` (this file)
- `docs/backlog.md`
- `docs/architecture.md` (short section)
- `README.md` (auth model note)

## Success Criteria

1. Fresh install (no tokens) → everything works exactly as before.
2. After creating first admin token via UI or API:
   - Unauthenticated requests to dashboard routes → 401
   - Requests with valid admin token → full access
   - Sensor registration + reporting continues to work with sensor tokens
3. User can lose the token in browser, paste it back in, and regain access without restart.
4. Sensor list + set-primary now require admin scope (the original VED-007 item).
5. All existing tests still pass + new auth tests added.

---

**Execution Note for Agent**:
Proceed in the order of the todos. After each logical group of changes, run `go build`, `go test ./backend/...`, and (if frontend changed) note that `npm run build` in frontend/ should succeed. Use clear commit-style messages in thinking. When complete, update this plan with "Implementation complete" + any deviations.

This plan is self-contained enough for autonomous execution.