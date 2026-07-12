# Known Limitations And Deferred Work

These are deliberate public-beta boundaries of the asset-centered findings sprint, not
silent failure modes.

- **No historical IP guesswork.** Existing events remain unresolved unless identity was
  known at ingestion time. Core does not attach old events to whoever owns an IP now.
- **Ambiguity stays unresolved.** An adapter using segment `default` may resolve a unique
  cross-segment temporal IP binding at reduced confidence. If the same address is valid
  in more than one segment, Core leaves the event unresolved.
- **Split is an exact merge undo.** The beta workflow reverses one audited soft merge.
  It does not repartition selected identity evidence or occurrences that were already
  aggregated into a finding while two records were merged. Raw event/finding identity is
  preserved, so a future assisted repartition can remain auditable.
- **Generic ingest requires a replay boundary.** `/api/v1/ingest` rejects a collector
  record that has neither a timestamp nor an upstream event ID; accepting it would make
  a retry indistinguishable from a second identical occurrence. An upstream ID without
  a timestamp is accepted, but Core still derives a collector-namespaced database key
  from the ID and normalized record material.
- **DNS poller cycles remain bounded.** AdGuard follows `older_than` in 100-row pages up
  to 1,000 rows per poll; Pi-hole v6 uses its snapshot cursor and server-side offset in
  1,000-row pages up to 10,000 rows (legacy v5 is also capped at 10,000 but exposes no
  cursor). Exceeding a bound is a visible collection error and does not advance the
  replay watermark, so no partial snapshot is reported as healthy. A source that
  continuously exceeds its bound can stall until the operator reduces
  `VEDETTA_ADGUARD_INTERVAL` or
  `VEDETTA_PIHOLE_INTERVAL`.
- **Merges do not coalesce existing open findings.** New events follow the canonical
  device redirect, but two equivalent active findings that existed before an operator
  merge remain separate audited records rather than being destructively combined.
- **Related detectors remain separate findings.** Two detector categories that match the
  same device and observable keep distinct finding keys. This preserves explanation and
  lifecycle semantics, but can show adjacent cards for one underlying incident until an
  evidence-preserving fusion policy is designed.
- **Sensor DNS retry buffering is memory-resident.** The native sensor now uses bounded
  immutable retry batches and an explicit shutdown drain, so short Core outages do not
  silently drop a batch. A process or host restart during an outage still loses queued
  observations; a future encrypted on-disk spool should make delivery durable and expose
  queue depth/shedding as collection health.
- **Telemetry's equal-timestamp cursor cohort is capped.** Telemetry remembers the exact
  event IDs consumed at its inclusive Core timestamp so a quiet tail cannot replay and
  a late same-time event is not lost. More than 50,000 events at one exact timestamp
  stalls that tick visibly and holds the prior cursor instead of truncating into silent
  loss or count inflation. This is well above the expected LAN workload.
- **Finding evidence outlives ordinary retention.** Events linked to findings are exempt
  from raw-event retention so operator drill-down remains intact. This can grow storage
  over time; a future evidence-preserving archival policy should give operators an
  explicit, auditable storage control.
- **Community intelligence is corroborating only.** Anonymous reporter consensus cannot
  eliminate Sybil risk. A community-only match stays advisory, cannot create a finding,
  and cannot raise a trusted finding's priority.
- **Identity is deterministic, not a commercial fingerprint database.** DHCP, SSDP,
  mDNS, MAC/OUI, hostname, segment, authenticated sensor, and operator evidence are used
  when present. Vedetta does not promise model-perfect device classification.
- **No opaque anomaly model.** First-seen and per-device context corroborate evidence;
  they are not treated as malicious on their own.

Rollback across migration 025 requires the pre-upgrade SQLite backup and matching prior
image. See [Backup, Restore & Rollback](../../docs/backup-restore-rollback.md).
