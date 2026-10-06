# Build tasks

- [x] Trace the primary vulnerability and campaign research.
- [x] Specify evidence distinctions, scope cuts, and privacy/resource bounds.
- [x] Implement portable observation types and bounded passive packet detector.
- [x] Implement safe local/extracted-filesystem auditing with coverage output.
- [x] Add sensor capture, explicit audit CLI, bounded delivery and shutdown.
- [x] Add authenticated Core route and strict observation validation.
- [x] Integrate stateless evidence evaluation and actionable durable findings.
- [x] Test positive fixtures, benign STUN, malformed inputs, confinement,
      authentication, provenance, replay, identity and suppression.
- [x] Build and test backend and sensor; build the frontend.
- [x] Document operation and limits, inspect the diff, and obtain independent
      code review before publishing the feature branch for human review.

## Validation results

- Core: `go build ./...` and the complete `go test ./... -short` suite passed.
- Sensor: native Linux build, focused delivery/CLI/detection tests, detection
  race tests, and Windows audit-package compilation passed. The complete build
  and short test suite passed in an isolated macOS arm64 checkout with Go 1.26.2.
  The local Linux sandbox blocks OS operations used by existing credential,
  ownership, and interface tests; Linux CI remains the integration gate.
- Frontend: `npm run build` passed; existing findings views accept the additive
  detector evidence without frontend changes.
- A synthetic sensor-to-Core JSON check validated four generated observations
  and all five expected packet/audit detections, preserving explicit filesystem
  provenance. Published digest matches are covered by Core regression fixtures.
- Independent review covered ingestion authentication, replay, identity,
  suppression, filesystem confinement, bounded capture/delivery, and IOC source
  accuracy. Registration chronology and persistence-source findings were fixed
  and their regression tests passed.
- Windows CI exposed a Unix execute-permission assumption in an audit fixture.
  Audit coverage and platform-specific assertions explicitly preserve Windows'
  inability to establish Unix executable eligibility.
- `git diff --cached --check` and the repository sanitation gate passed before
  publication. No live traffic, malware execution, or device exploitation was
  used for validation.

## Constitution Check

Each implementation task follows spec and plan. Validation runs without live
network data or exploitation. The final change retains the native/Core split and
existing schema, and remains subject to independent review before merge.
