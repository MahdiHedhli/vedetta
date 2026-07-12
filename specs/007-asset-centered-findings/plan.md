# Plan: Asset-Centered Findings and Detection Fusion

> Spec: `specs/007-asset-centered-findings/spec.md`
> Status: Implemented, validated, and independently reviewed

## Existing paths and defects

Production writes currently take five paths:

1. Sensor DNS -> `/api/v1/sensor/dns` -> handler normalization -> Enricher -> InsertEvents
2. Collector/syslog -> `/api/v1/ingest` -> handler normalization -> Enricher -> InsertEvents
3. Pi-hole API poller -> local normalization -> Enricher -> InsertEvents
4. AdGuard API poller -> local normalization -> Enricher -> InsertEvents
5. Direct UniFi REST -> FirewallEvent.ToEvent -> InsertEvents (currently unscored)

Additional defects addressed by the processor: DNS/firewall allowlists currently return
before IOC/IPS checks; enrichment replaces source metadata; only the first DNS answer is
checked; suppression is browser-side; event/device joins use current IP; address history
does not exist; alias ambiguity cannot be represented by the compatibility table's key.

## Processor contract

```go
type IngressEnvelope struct {
    Event       models.Event
    Origin      string
    SensorID    string
    ReceivedAt  time.Time
    SourceMeta  map[string]any
}

type ProcessRecordResult struct {
    EventID    string
    FindingIDs []string
    Inserted   bool
    Duplicate  bool
    Err        error
}

type Processor interface {
    ProcessBatch(context.Context, []IngressEnvelope) []ProcessRecordResult
}
```

Adapters retain source-specific parsing and authentication. The processor performs:

1. Normalize/default and namespace source metadata.
2. Extract all typed observables.
3. Resolve device at the event timestamp.
4. Run detectors and threat intelligence into typed evidence.
5. Apply device and benign context after evidence exists.
6. Derive priority once and evaluate suppression disposition.
7. In one per-event SQLite transaction, insert the event, evidence, update/reopen/create
   findings, and link supporting events.

Per-event atomicity preserves partial-batch commits. Any processor failure returns a
retryable non-2xx response to Fluent Bit; committed siblings are safe because adapters
derive normalized replay-stable IDs. For generic collector ingest, an upstream event ID
is preserved as audit/replay material but is not the database key: Core namespaces the
key with the collector trust domain and normalized record material. A collector record
with neither an upstream event ID nor a timestamp is rejected because it cannot
distinguish a retry from a second occurrence. Duplicates do not increment findings.

## Identity resolution order

1. Operator-confirmed binding or canonical merge redirect valid at the timestamp.
2. Unique stable local-HMAC identity (DHCP client ID or SSDP UUID).
3. Exact MAC; globally administered is strong, local/private MAC is segment-scoped.
4. Unique corroborated alias/fingerprint inside its recency window; strong conflicts veto.
5. Unique temporal address binding matching timestamp, segment, and sensor.
6. Conflict/ambiguity -> unresolved or low confidence, never newest-current-IP guessing.

Address bindings are interval-preserving. A new owner closes the previous active interval;
an observation of the same owner/address extends it. Compatibility projections continue
to show the most recent address/segment.

## Finding identity and recurrence

Normalized key material:

```text
identity = device:<uuid>
        or unresolved:<source_hash>:<sensor_id>:<segment>
finding_key = sha256(identity | detector | observable_type | normalized_observable)
```

Behavioral detectors use their documented signature instead of an arbitrary tag. A
partial unique index enforces one non-resolved finding per key. Recurrence within seven
days reopens the last generation; later recurrence inserts generation+1 with
`previous_finding_id`.

## Schema direction (migration 025)

- Add event identity/origin/disposition columns.
- Rebuild `events` data-preservingly to remove the legacy query-type enum CHECK;
  Core must accept standard types such as SOA/SVCB/HTTPS and surface non-PK
  constraint failures instead of reporting them as duplicates.
- `device_address_history`: timestamped address ownership intervals.
- `device_identity_evidence`: many-to-many aliases/fingerprints with provenance.
- `device_identity_actions`: confirm/merge/split/reassign audit and merge redirects.
- Add soft-merge redirect columns to devices.
- `event_detection_evidence`: typed immutable detector results.
- `findings`, `finding_events`, `finding_status_history`.
- `finding_evidence` for exact detector-evidence membership.
- `finding_suppression_rules` for detector/observable plus canonical-device or
  unresolved-source policy; `finding_suppression_history` audits activation and
  deactivation without deleting evidence.
- `collection_source_health` for persisted collection status; threat-feed scheduler
  exposes last success, count, stale/error in the same health response.

The inline fallback mirrors the migration. Existing event rows are not backfilled.

## API

- `GET /api/v1/findings`
- `GET /api/v1/findings/{findingID}`
- `PATCH /api/v1/findings/{findingID}/status` (admin)
- `POST /api/v1/findings/{findingID}/suppress` (admin)
- `GET /api/v1/finding-suppressions`
- `DELETE /api/v1/finding-suppressions/{ruleID}` (admin; deactivate, not erase)
- `GET /api/v1/findings/stats`
- `GET /api/v1/health/detection`
- `POST /api/v1/sensor/heartbeat` (sensor scope; process reachability only)
- `POST /api/v1/devices/{deviceID}/confirm` (admin)
- `POST /api/v1/devices/merge` (admin)
- `POST /api/v1/device-merges/{actionID}/split` (admin; undo)

Existing event/device APIs remain available. Findings link to exact `device_id`.

## UI slice

- Add Vitest, React Testing Library, and jsdom.
- Extract a findings API/state hook and findings components from the monolithic App.
- Findings is the primary threat tab; Raw Events is an explicit drill-down.
- Actionable, suppressed, and resolved result sets have independent server pagination
  and explicit load-more controls.
- Lifecycle actions require reasons where specified and refresh server state.
- Device navigation selects by `device_id`, never current IP.
- Explicit loading/healthy-empty/stale/failure/auth states and feed/collection health.

## Success metrics

The persisted schema and current-state APIs support the sprint metrics without external
analytics or telemetry. Exact local queries and interpretation notes live in
[`metrics.md`](metrics.md).

Public-beta boundaries and deferred work are explicit in
[`known-limitations.md`](known-limitations.md).

## Compatibility risks and controls

- Telemetry consumes existing event provenance/tags: keep them and add new evidence.
- Stable occurrence IDs exposed a pre-existing telemetry cursor replay defect for events
  sharing one timestamp. The release candidate now persists the exact bounded ID cohort
  at its inclusive timestamp, accepts late same-time IDs, and holds the cursor visibly
  rather than truncating an extraordinary over-cap cohort.
- Merge deletion would break device references: convert to soft redirects first.
- Migration runner has an inline fallback: mirror every table/column and extend migration
  manifest/fresh-upgrade tests.
- Enrichment order changes may surface IOC evidence hidden by allowlists. This is intended;
  tests assert disposition rather than disappearance.
- Processor routing can double-enrich during transition: adapters are migrated one at a
  time and production direct-persistence call sites are removed and verified by a
  production-call-site audit.
- The frontend had no test runner before this sprint: introduce Vitest/RTL before
  replacing browser-local grouping logic.

## Rollback

Migration 025 is forward-only. A rollback across it means stopping Core, restoring the
pre-upgrade SQLite backup, and starting the matching prior image. Running a prior image
against the populated expanded database is unsupported: older merge and retention code
does not preserve the new finding/evidence relationships. Do not drop the new tables or
attempt an in-place down migration.

## Constitution check

The spec's constitution check is unchanged. No active network behavior, external identity
database, telemetry policy/payload change, or environment-derived tracked data is
introduced. The telemetry change is local cursor correctness only.
