# UniFi Ingestion Implementation Plan (V1, planning only — DO NOT IMPLEMENT)

End-to-end path targeting the EXISTING /ingest + firewall filters on main.

## High-Level Flow
1. UniFi export: Admin configures Integration > System Logging / SIEM (or CyberSecure Traffic Logging) → SIEM Server, pointing at the Vedetta collector (Fluent Bit syslog listener, typically UDP 514 or dedicated port). Categories: Security (Firewall + Intrusion Prevention).
2. Collector (existing fluent-bit.conf + new UniFi transform):
   - INPUT: syslog (or modified for CEF) on the UniFi port.
   - Parser: syslog-rfc3164 (or CEF-aware).
   - Filters: modify (Add event_type=firewall_log, Rename host→source_hash, message→raw_log), then Lua (unifi_transform.lua modeled on pihole_transform.lua).
   - Lua responsibility (per spec + Stage 1 in-scope): parse CEF (or the message) and lift/emit the structured fields (action, protocol, src/dst, ports, interface) either as top-level Event keys or inside metadata so json_extract works. Preserve verbatim raw_log. Emit clean JSON for /ingest.
   - OUTPUT: http to http://core:8080/api/v1/ingest (Json_date_key, auth token or reuse mechanism).
3. Core ingest handler (already present): accepts, parses (single/array/Fluent shape), lifts non-Event top-level into metadata if needed, defaults, InsertEvents (with server_ip etc already wired), 202.
4. Store: events table (metadata JSON for the firewall details until a future additive mig if justified), devices unchanged for V1. QueryEvents already supports the json_extract filters for action/protocol etc.
5. Query/UI: /events?source=unifi&action=blocked... works; L5+ frontend can surface firewall events with the new fields.
6. SNR: source="unifi" tag/metadata; suppression rules can target it; volume-aware retention; Pi-4 backpressure (batch, limits in collector, EnforceRetention).

## Schema / Migration Implications
- NO edits to 001 or 016.
- If additive columns needed for first-class firewall fields (beyond metadata), a **NEW** migration file only (e.g. siem/migrations/017_unifi_firewall_fields.sql) with guarded ALTERs + INSERT OR IGNORE in the runner (idempotent).
- For V1: start with metadata storage (already proven by pipeline) + the parse in collector so filters function immediately. Future mig only if query perf or UI requires first-class columns.
- Device side: no change (UniFi may enrich devices later via other means; V1 focuses on events).

## Pi-4 Volume / Backpressure
- UniFi "block" + threat logs can be very chatty (every denied flow or signature match).
- Mitigations (design in):
  - Collector: rate limiting / drop on backpressure, short flush intervals, small batch.
  - /ingest: already accepts batch; handler is fast.
  - Store: EnforceRetention (daily, retention_config) + WAL + incremental_vacuum + scheduled VACUUM (documented for SD longevity).
  - SNR: default suppression or low-score for pure "blocked by policy" with no other signals; source="unifi" specific rules; UI grouping/filtering.
- Monitor via existing health scripts + new source=unifi cardinality in collection-health.

## Where source="unifi" SNR Suppression Lives
- Collector: optional early drop of pure noise categories (configurable).
- Core: suppression rules (existing) + tag `source:unifi` or metadata.source; Enricher can apply source-specific caps.
- UI: context filter or quick "Suppress all unifi blocks" (extend existing patterns).
- Docs: explicit call-out in connector-guide.md and this plan.

## Risks & Mitigations
- CEF parsing fragility across UniFi OS versions → start with thin slice (common security fields), keep raw_log verbatim, version the transform.
- Volume surprise on real Pi-4 → thin slice first (one gateway, limited categories), measure before widening.
- Filter inertness if parse wrong → the explicit in-scope parse + faithful test (like the pipeline faithful collector shape test) required in tasks.
- Constitution: passive syslog only for V1; no new full LAN scan or exploit code.

## End State for V1 Slice
- UniFi gateway sending CEF syslog → Fluent Bit normalizer → /ingest → queryable/filterable events with action etc populated → basic SNR guard (source tag + suppression) → docs updated.
- No device import from UniFi, no REST, no changes to sensor, no new migrations in first slice.

See tasks.md for the thin-slice, testable breakdown mapped to VED-002 / VED-005.
