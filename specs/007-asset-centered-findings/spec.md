# Spec: Asset-Centered Findings and Detection Fusion

> Feature directory: `specs/007-asset-centered-findings/`
> Status: Implemented, validated, and independently reviewed
> Created: 2026-07-12

## Objective

Turn Vedetta's source-specific raw events into durable, device-centered findings that
tell an operator what happened, which asset is affected, why the evidence matters,
whether the activity was allowed or blocked, and what to do next. Raw events remain
immutable supporting evidence and a troubleshooting surface.

The sprint delivers one vertical slice across stable event identity, a single
server-side processor, persistent findings, lifecycle APIs, explicit collection/feed
health, and a findings-first dashboard.

## User-visible outcome

An operator can see a durable finding such as:

> Living-room camera contacted a Feodo C2 address - allowed
> 17 attempts in 12 minutes - high confidence - device is end-of-life
> Recommended: isolate the camera and check for firmware updates.

The card links to the stable device and every supporting event. It remains correct
after DHCP changes the device's address.

## Functional requirements

### Identity

- Events gain nullable `device_id`, identity confidence, a deterministic resolution
  reason, and structured evidence.
- Core records timestamped address bindings by device, address, segment, authenticated
  sensor, evidence source, and confidence. Resolution uses evidence valid at the event
  timestamp; current IP alone is never treated as historical truth.
- Identity evidence is many-to-many so a shared hostname/mDNS name is ambiguous rather
  than silently reassigned. Strong contradictions produce low confidence or no match.
- DHCP option 55/61, SSDP UUID/device type, mDNS service/stable TXT, MAC/OUI,
  hostname, sensor, segment, and observation time are accepted as optional evidence.
  Sensitive enumerable identifiers are persisted only as keyed local HMACs.
- Operator confirm, merge, and split actions are audited. Merges are soft redirects;
  beta split means undoing a recorded merge, not arbitrary evidence partitioning.

### Processing

- Every production writer (sensor DNS, generic `/ingest`, Pi-hole API, AdGuard API,
  direct UniFi REST) calls one backend processor before persistence.
- Source adapters parse only. The processor owns normalization, observable extraction,
  timestamp-valid identity, detection, context, priority, suppression disposition,
  and transactional event/evidence/finding persistence.
- Domain, destination IP, every DNS answer/CNAME, destination port, protocol, and real
  URLs are typed observables. Unsupported observables are not advertised.
- Detector evidence records detector, observable, source, confidence/freshness,
  rationale, score contribution, outcome, and relevant device context.
- Source metadata is preserved under namespaced JSON; enrichment never replaces it.
- IOC/IPS evaluation precedes allowlist/known-good context. Benign context may alter
  disposition or weak-signal priority but never erases strong evidence.
- Existing `/ingest` partial-batch behavior remains compatible, while each accepted
  event plus its evidence/finding mutations is atomic.
- Collector `event_id` values are preserved in source metadata as upstream audit/replay
  material, not used as database keys. Core derives a collector-namespaced key from that
  value and normalized record material so an ingest principal cannot collide with a
  sensor or poller event. A collector record with neither an upstream ID nor a timestamp
  is rejected because it has no safe retry boundary.

### Findings

- Findings persist stable key, generation, device/fallback identity, detector/category,
  primary observable, time range, counts, score/priority, enforcement outcome
  (`allowed`, `blocked`, `observed`, or aggregate `mixed`), status, rationale,
  recommendation, last event, evidence, and suppression disposition.
- Key material is stable device ID (or local `source_hash + sensor_id + segment`
  fallback), explicit detector, and normalized observable/behavior signature.
- One active finding exists per key. A resolved finding recurring within seven days is
  reopened with status history; after seven quiet days a linked generation is created.
- Statuses are Open, Investigating, and Resolved. Investigating/resolution are admin
  actions; resolution requires a reason and never mutates supporting events.
- Legacy event acknowledgement remains a per-event review marker only. It does not
  change finding lifecycle or disposition, and finding actions do not acknowledge raw
  evidence. The three operator concepts are intentionally independent.
- Suppression is separate from resolution. Strong evidence remains stored and visible
  even when disposition is suppressed.
- Finding suppression is an exact typed policy: detector + observable + canonical
  device, or detector + observable + unresolved fallback source. Creating and
  deactivating rules is audited; rules are deactivated rather than deleted.

### Priority defaults

- Every trusted high-confidence IOC/IPS result can create a finding regardless of
  allowlist, blocked state, or suppression. Community-only evidence is explicitly
  excluded: it may be retained and linked as corroboration, but cannot independently
  create a finding or raise priority.
- Other deterministic detector evidence creates a finding at score `>= 0.30`; weaker
  advisory evidence requires corroboration.
- Critical: `>= 0.85`; High: `>= 0.60`; Medium: `>= 0.30`; Low: corroborating/advisory.
- Blocked state changes outcome and recommendation, not evidence-derived priority.

### Dashboard and health

- Findings replace browser-local threat groups as the primary threat view. Raw events
  remain available as drill-down.
- Cards answer what, asset, why, allowed/blocked, frequency/window, action, and evidence.
- Empty, initializing, stale, failure, and authentication states are distinct. No UI may
  claim the network is secure after a failed read.
- Native sensors send a dedicated authenticated process heartbeat every 30 seconds;
  heartbeat does not drain scan work and cannot by itself prove packet capture healthy.
- Dashboard summary uses open critical/high findings, affected assets/sources (including
  unresolved fallback identities), recent resolutions, collection health, and feed
  health rather than lifetime anomaly counts.
- Actionable, suppressed, and resolved queues page independently; loading later history
  cannot crowd an actionable finding out of the primary queue.

## Migration and compatibility

- Add forward-only migration 025; do not edit migrations 001-024.
- Migration 025 performs one data-preserving `events` table rebuild to remove the
  obsolete DNS query-type enum constraint; existing rows and indexes are copied.
- Existing event fields, tags, APIs, acknowledgement, and device projections remain
  additive/backward compatible for at least one release. The deliberate collector
  hardening exception is that `/ingest` records now require either a timestamp or an
  upstream event ID; records without either are rejected instead of being assigned an
  unsafe receipt-time identity.
- Existing events remain `device_id = NULL`. There is no historical current-IP backfill.
- Existing aliases/current attachments may seed explicitly low-confidence
  `legacy_snapshot` evidence at their recorded last-seen time only.
- Existing `devices.ip_address`, `segment`, `device_identities`, and `device_networks`
  remain compatibility projections while append-only evidence becomes authoritative.
- Existing automatic destructive merge is replaced before device foreign keys become
  load-bearing.

## Non-goals

- New feed count, opaque ML, commercial fingerprint databases, behavioral telemetry,
  telemetry defaults, community Sybil redesign, TLS fingerprints not actually captured,
  and unrelated beta cleanup. Release review did include a telemetry cursor correctness
  fix so equal-timestamp Core events cannot inflate existing advisory signal counts.
- Arbitrary manual repartitioning of a device's historical evidence. This sprint's split
  is a reversible merge undo backed by an audit record.

## Constitution check

- **Native sensor split / passive-first:** new DHCP/mDNS/SSDP parsing stays in the native
  sensor; no active probes or Docker-only replacement.
- **Pi-hole optional:** native sensor + Core provides the complete vertical slice;
  pollers are parity adapters only.
- **V1 scope / Pi 4:** deterministic indexed SQLite lookups, bounded JSON/evidence, no
  external service or ML runtime.
- **SNR:** strong evidence precedes benign context; suppression changes disposition,
  and source-parity tests are mandatory.
- **Migration:** new sequential migration only, additive compatibility projections.
- **Privacy:** sensitive identity values are locally keyed/HMACed and never exported.
- **Environment data:** tracked examples use RFC 5737 and RFC 7042 values only.
