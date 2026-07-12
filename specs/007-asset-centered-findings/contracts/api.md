# API Contract: Findings and Identity Actions

All routes are under `/api/v1`. Read routes accept `read` or `admin`; operator state
changes require `admin`. The findings/identity additions are backward compatible. The
intentional collector hardening at the end of this contract requires every `/ingest`
record to carry a timestamp or upstream event ID.

## Finding reads

- `GET /findings?status=active&priority=high&disposition=active&device_id=<uuid>&page=1&limit=50`
  returns `{findings,total,page,limit}`. `status=active` includes Open and
  Investigating; explicit lifecycle values are also accepted. Device filtering follows
  audited merge redirects to the canonical asset.
- The dashboard requests and pages three queues independently: actionable
  (`status=active&disposition=active`), suppressed
  (`status=active&disposition=suppressed`), and resolved (`status=resolved`). Each
  queue's `total`, `page`, and `limit` apply only to that query.
- `GET /findings/{finding_id}` returns the finding, typed evidence, status history,
  supporting events, and canonical device projection. `evidence_limit` /
  `evidence_offset` and `event_limit` / `event_offset` page the two exact relationship
  sets (maximum 500 per page) and totals are returned separately.
- `GET /findings/stats` returns open counts by priority, affected asset/source count,
  recently resolved count, and processing timestamp. The compatibility response field
  remains `affected_devices`, but its distinct count includes unresolved fallback
  identities as well as canonical devices.
- `GET /health/detection` returns collection sources and threat feeds with
  `state=initializing|healthy|stale|error|unauthorized`, last attempt/success, item/event
  count, and an operator-safe error.

## Finding lifecycle

`PATCH /findings/{finding_id}/status`

```json
{"status":"investigating","reason":"Checking the camera firmware"}
```

`status` is `open`, `investigating`, or `resolved`; resolution requires a non-empty
reason. The response contains the updated finding. Supporting events are unchanged.
Finding/evidence outcome is `blocked`, `allowed`, `observed`, or aggregated `mixed`;
missing enforcement state is never represented as allowed. `mixed` means that more
than one of those three concrete outcomes occurred, including allowed+observed or
blocked+observed as well as allowed+blocked.

## Finding suppression

- `POST /findings/{finding_id}/suppress` with `{"reason":"Expected lab traffic"}`
  requires admin scope. Core creates or reuses an exact typed rule from the finding's
  detector and primary observable, scoped to its canonical device when resolved or to
  its fallback source identity when unresolved. The response is
  `{"finding":...,"rule":...}`.
- `GET /finding-suppressions` accepts read or admin scope and returns
  `{"rules":[...]}`, including inactive rules.
- `DELETE /finding-suppressions/{rule_id}` requires admin scope and deactivates the
  rule. It makes findings directly dispositioned by that rule actionable again and
  returns `{"deactivated":true,"affected_findings":N}`. It does not delete the rule,
  evidence, finding, lifecycle state, or audit trail.

Rule activation and deactivation are recorded in `finding_suppression_history` with
actor, reason, finding when applicable, and timestamp. Suppression controls noise;
resolution continues to describe incident lifecycle independently.

## Identity actions

- `POST /devices/{device_id}/confirm` records an operator-confirmed evidence binding
  with `{evidence:{type,value},segment,sensor_id,reason,observed_at}`.
- `POST /devices/merge` with `source_device_id`, `target_device_id`, and `reason` creates
  a soft redirect and returns an auditable `action_id`.
- `POST /device-merges/{action_id}/split` with `reason` undoes that merge when it has not
  already been undone. It does not offer arbitrary evidence partitioning.

Examples use only `192.0.2.0/24` and `00:00:5E:00:53:xx` fixtures in tests/docs.

## Ingestion retry contract

For generic `POST /ingest`, the caller's `event_id` is upstream audit/replay material,
preserved with the collector source metadata, not an authoritative database key. Core
derives a collector-namespaced, replay-stable UUIDv8 from that value, stable source
context, upstream timestamp, and normalized record material. Reusing an upstream ID for
different content therefore cannot collide, and an ingest principal cannot pre-seed IDs
used by sensor, poller, or UniFi trust domains.

A collector record without a timestamp is accepted only when it supplies an upstream
`event_id`; a record with neither is rejected and counted in
`missing_event_identity`. Each accepted event/evidence/finding mutation commits
atomically. `POST /ingest` returns a retryable 5xx if processing an accepted record
fails; already committed siblings deduplicate on retry and do not inflate findings.
