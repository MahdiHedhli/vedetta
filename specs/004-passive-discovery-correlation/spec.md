# Spec: Passive Discovery Correlation, Labeling & Multi-Network Handling

> Feature directory: `specs/004-passive-discovery-correlation/`
> Status: Draft
> Backlog: VED-012
> Created: 2026-07-03

## Summary

Vedetta's passive discovery (ARP/DHCP/mDNS/SSDP) already produces device observations, but they are stitched together naively: device identity is MAC-first with a raw IP+segment fallback, per-field metadata (vendor, model, hostname) is effectively last-writer-wins, mDNS TXT/PTR metadata attaches to the wrong host in multi-record packets, and the PTR service-extraction branch is dead code. This feature makes passive observations correlate into stable, well-labeled device records: multi-signal identity resolution that survives DHCP IP churn (MAC + IP + hostname + mDNS instance-name continuity), confidence-weighted merging of vendor/model/services signals with per-field provenance, correct mDNS record-graph parsing (PTR→SRV→TXT→A/AAAA), per-segment disambiguation for multi-network deployments, and a derived human-readable display name for every device. User-visible outcome: one device row per physical device with a friendly name like "Living Room TV (Samsung UN65CU8000)" instead of duplicated rows named by vendor string, and fewer spurious `new_device` alerts.

## Motivation & Evidence

- **Roadmap**: "Better passive discovery correlation/labeling/multi-network" is an explicit "Planned next" roadmap item (docs/roadmap.md; docs/backlog.md follows VED-006, which shipped the raw listeners in 2026-04).
- **Research**: `research/01-passive-discovery-fingerprinting.md` (P0 core differentiator) and `research/08-device-fingerprint-database.md` both call for multi-signal fusion — "No single fingerprint method is 100% reliable. The highest accuracy comes from combining multiple signals" — and note that "full mDNS service types/TXT records ... are not yet preserved" for the fingerprint layer.
- **Known parser defect** (`sensor/internal/passive/parse.go`): TXT and PTR metadata is attached to `hosts[len(hosts)-1]`, a documented heuristic that mislabels hosts when one mDNS packet carries records for multiple devices. Worse, the PTR service branch is dead code: `trimDNSName` strips names beginning with `_` to `""`, so the subsequent `strings.HasPrefix(svc, "_")` check can never be true — passive service discovery via PTR has never emitted a service.
- **Known identity defect** (`backend/internal/store/devices.go`): the IP+segment fallback plus unconditional MAC overwrite means a device record can silently change identity when DHCP reassigns an IP; MAC-less mDNS/SSDP observations create duplicate rows for devices already known by MAC. The `GetMinFirstSeenForIP` workaround exists precisely because duplicate records were causing spurious `new_device` / `very_new_device` tags — evidence the root cause is correlation, not tagging.
- **Risk accuracy**: the just-shipped device risk categories (`known_exploited` / `eol_eos` / `high_risk_iot`, migration 016) and sensor actionability payloads (migration 017) key scoring boosts off device attributes. Wrong or fragmented device records mean wrong risk attribution on DNS events.
- **Multi-network reality**: SMB and prosumer deployments run multiple segments (IoT VLAN, guest, LAN). The current single `segment` column cannot represent one device seen on two segments, and sibling work on UniFi log ingestion (`specs/001-unifi-log-ingestion/spec.md`) will introduce VLAN-tagged device sightings that need a home.

## User Stories

- As a homelab user, I want my phone to remain one device record when DHCP hands it a new IP, so that my inventory doesn't fill with duplicates and I don't get false "new device" alerts.
- As a homelab user, I want devices labeled "Living Room Chromecast" rather than "Google, Inc.", so that I can immediately tell which device an alert is about.
- As a small business operator with an IoT VLAN and a staff LAN, I want devices attributed to the correct network segment — and a laptop that roams between them tracked as one device — so that segment-based context (e.g. "camera on IoT VLAN doing DNS tunneling") is trustworthy.
- As a small business operator, I want a device's model/vendor identification to come from the most reliable signal seen (mDNS TXT model beats OUI vendor guess) and not be overwritten by a weaker later signal, so that risk classifications (EOL router, high-risk camera) stay accurate.
- As an MSP evaluating Vedetta, I want to see which signal identified each device (provenance + confidence), so that I can trust or correct the inventory.

## Requirements

### Functional

- FR-1: **mDNS record-graph correlation (sensor).** Rework `hostsFromMDNS` to correlate records by owner name within a packet: PTR (service type → instance), SRV (instance → target host + port), TXT (instance → key/values), A/AAAA (host → IP). TXT model/vendor metadata and PTR-derived service types MUST attach to the host they belong to, never to "the last host seen".
- FR-2: **Fix PTR dead code (sensor).** Service types MUST be extracted from the raw PTR owner name before underscore-stripping (`trimDNSName` currently reduces `_http._tcp.local` to `""`, so the `HasPrefix("_")` branch never fires). Emitted service values keep the existing `_service._proto` form already stored in `devices.services` (wire-compatible with migration 017).
- FR-3: **Friendly-name extraction (sensor).** Extract human-friendly instance names where devices advertise them: mDNS TXT `fn=`/`n=` keys and the mDNS service-instance label (e.g. `Living Room TV._googlecast._tcp.local` → `Living Room TV`), SSDP `USN`/header-derived names. Carried as a new optional `friendly_name` field on the sensor device payload (additive; old Cores ignore it, old sensors simply don't send it).
- FR-4: **Multi-signal identity resolution (Core).** Replace the two-step MAC-then-IP match in `UpsertDevice` with an ordered resolver: (1) MAC exact match; (2) mDNS instance-name + segment match within a recency window; (3) hostname + segment match, only when the hostname is not on a generic-hostname stoplist (e.g. `localhost`, `android-*`, `espressif`, `unknown`) and is unique within the segment; (4) IP + segment match, only when the stored record has no MAC or the observation has no MAC. An IP+segment match MUST NOT re-assign a record whose stored MAC differs from the observation's MAC — that is a new/different device (DHCP churn), not an update.
- FR-5: **Duplicate linking/merge.** When an observation carries a MAC that matches record A and an identity signal (hostname / mDNS name / IP+segment) that matches a MAC-less record B, the records MUST be merged (A survives; B's higher-confidence fields, identity aliases, and earliest `first_seen` are folded in; B is deleted). Merges are logged for audit. `first_seen` after merge is the minimum of both records, which retires the `GetMinFirstSeenForIP` workaround's root cause.
- FR-6: **Confidence-weighted field merging.** Vendor, model, hostname, OS, device type, and friendly name MUST be stored with per-field provenance (source + confidence + last-observed) and only overwritten by an equal-or-higher-confidence source (same source may refresh its own value). Baseline trust order: user correction (1.0, locked) > mDNS TXT model/fn (0.9) > SSDP SERVER/USN (0.75) > DHCP hostname opt 12 (0.7) > DHCP vendor class opt 60 (0.6) > hostname-pattern engine (existing 0.5–0.8) > OUI (0.2). This replaces the current last-writer-wins `COALESCE(NULLIF(...))` update paths.
- FR-7: **Multi-network attachment model.** A device MUST be representable on multiple segments simultaneously via a `device_networks` attachment table (device × segment × IP × sensor, with first/last seen). Same MAC on two segments = one device, two attachments. Same IP on two segments remains two distinct devices (existing semantics preserved). `devices.segment` / `devices.ip_address` remain as the most-recent attachment for backward compatibility.
- FR-8: **Human-readable labeling.** Every device gets a derived `display_name` with precedence: user `custom_name` > friendly name (mDNS/SSDP) > model (+ vendor) > cleaned hostname > vendor + last MAC octets (e.g. "Espressif 53:2A") > IP address. Recomputed on upsert, stored, and returned by `GET /api/v1/devices` and used in event context surfaces.
- FR-9: **Provenance API.** Device API responses expose identification provenance (which signals contributed, per-field source and confidence) so users can audit and correct labels; user corrections via the existing `PUT /devices/{deviceID}` fingerprint path continue to take absolute priority.
- FR-10: **Fingerprint engine input widening.** The fingerprint engine (`backend/internal/fingerprint`) receives the correlated signal set (services, TXT-derived model, friendly name) instead of only hostname/vendor/MAC, so risk categories (`known_exploited`/`eol_eos`/`high_risk_iot`) key off the best available evidence.

### Non-Functional

- NFR-1: Pi 4 hardware floor — correlation adds at most a small constant number of indexed SQLite lookups per reported host and one batched signal write per report; no measurable change to the <200 MB RAM / <5% CPU idle budget. Sensor-side mDNS correlation is per-packet, allocation-bounded, and stays within the existing passive-capture footprint (<1% CPU).
- NFR-2: Works with Core + native sensor only — no new required dependencies, no external fingerprint database or cloud lookup. All correlation is local.
- NFR-3: Backward compatibility — sensor wire format changes are additive-only (`friendly_name`); old sensors against new Core and new sensors against old Core both keep working. Existing `devices` columns keep their meaning; new state lives in new tables/columns via a new sequential migration.
- NFR-4: Determinism and auditability — identity decisions (match rule used, merges performed) are logged; merging is conservative (prefer a duplicate row over a wrong merge).

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | Yes | All packet-level work (mDNS record-graph parsing, PTR fix, friendly-name extraction) stays in the native sensor binary (`sensor/internal/passive`). Core does only DB-level correlation. No change to the Docker Core + native sensor split. |
| Pi-hole optional | Yes | No Pi-hole/AdGuard involvement; feature operates purely on sensor passive observations. Pi-hole-sourced DNS events are unaffected. |
| Passive-first | Yes | Strengthens the passive path exclusively. Explicitly excludes new active probing — no SSDP `LOCATION` XML fetches, no mDNS queries, no nmap changes (see Out of Scope). |
| V1 scope (no LAN scan/exploit) | Yes | No scanning, no exploit verification. Pure correlation/labeling of data already captured. Scope cuts listed below keep complexity bounded. |
| SNR re-tune for new sources | Yes | No new data source, but identity semantics change affects `new_device`/`very_new_device` tagging and risk-category attribution — a dedicated SNR validation pass is required and planned (see SNR Impact and plan.md). |
| Privacy / opt-in telemetry | Yes | No telemetry. Friendly names / hostnames are potentially personal (e.g. "Alice's iPhone") and remain local-only; nothing added to any export path. |
| Environment data handling | Yes | All examples in this spec directory use RFC 5737 IPs, `00:00:5E:00:53:xx` MACs, and placeholder hostnames. Live-capture validation notes go to gitignored `analysis-notes/` only. |

## Signal-to-Noise Impact

This feature is itself an SNR improvement (fewer duplicate devices → fewer false `new_device` alerts, better risk attribution), but it introduces new noise/error modes that demand tuning shipped with it:

1. **Wrong-merge risk.** Hostname- or mDNS-name-based matching can merge two distinct devices (e.g. two devices both named `printer`). Mitigation shipped with the feature: generic-hostname stoplist, uniqueness-within-segment requirement, recency window, MAC-conflict veto (never merge two records with different known MACs), and merge audit logging so a bad merge is diagnosable.
2. **Split risk (churn).** The new MAC-conflict veto on IP+segment matches means DHCP churn now correctly creates a new record instead of silently stealing one — this can *increase* `new_device` events for MAC-randomizing clients (iOS/Android private Wi-Fi addresses). Mitigation: hostname/mDNS continuity matching usually re-links them; residual randomized-MAC devices are a documented limitation and the `new_device` tag description mentions private-MAC churn as a benign explanation.
3. **Re-labeling churn.** Confidence-weighted merging changes existing device labels/models on upgrade (one-time). `display_name` recomputation is deterministic and user `custom_name` always wins, so no user data is lost.
4. **First-seen semantics.** Merges take the earliest `first_seen`, which *suppresses* spurious `new_device` tags (net SNR gain) — the existing `GetMinFirstSeenForIP` behavior is preserved during transition and can be retired after validation.

Validation loop before calling this done: replay of recorded synthetic packet fixtures (multi-host mDNS packets, DHCP churn sequences) plus a live soak on the development network with before/after device-count and `new_device`-event-count comparison recorded in the SNR log (gitignored analysis notes; sanitized summary in the repo).

## Out of Scope

- **Fetching SSDP `LOCATION` device-description XML** — it is an active HTTP request; violates passive-first for this feature. Revisit as an explicit opt-in later.
- **Fingerbank / DHCP option 55 fingerprint database integration** — separate, larger effort (bundled DB, licensing, matching engine); this feature only makes the correlation substrate ready for it (per-field provenance).
- **TCP/JA3/JA4 passive fingerprinting** — research Phase 3 (research/01); out of V1 correlation scope.
- **LLDP/CDP parsing** — low prevalence on target networks; additive later without schema change.
- **Cross-sensor deduplication policy beyond segment attachment** — two sensors on the same segment already converge via MAC; sophisticated sensor-preference policies are deferred.
- **UI redesign of the device inventory** — only display_name/provenance surfacing; full inventory UX is separate work.
- **Automatic un-merge tooling** — merges are logged and rare; manual correction via device edit suffices for alpha.

## Open Questions

- [ ] Recency window for hostname/mDNS-name identity matching: proposal is 7 days (mDNS name) / 24 h (IP+segment fallback when both sides lack MAC). Validate against live soak before freezing.
- [ ] Should merge events surface in the UI (low-severity audit feed) or remain log-only for alpha? Current plan: log-only plus device history note.
- [ ] Exact generic-hostname stoplist contents — seed list in plan.md; expected to grow during live validation.
- [x] Sibling spec path for UniFi ingestion — resolved: it landed as `specs/001-unifi-log-ingestion/`; segment naming aligns with its interface→segment mapping (plan.md Decision 2 there).
- [ ] Retire `GetMinFirstSeenForIP` immediately after merge logic ships, or keep one release as belt-and-braces? Current plan: keep one release, remove in the next.
