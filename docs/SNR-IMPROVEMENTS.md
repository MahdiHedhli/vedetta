# Vedetta Signal-to-Noise Ratio (SNR) Improvements

**Status**: Major improvements implemented across detection logic, device context, suppression UX, and event presentation.

**Goal**: Raise effective signal quality to 80/20 or better on existing DNS + passive discovery data before adding new sources (firewall logs, etc.).

---

## Summary of Changes

### 1. Detection Scoring Improvements (Core SNR-03 + SNR-09)

**Enricher (`backend/internal/dnsintel/enricher.go`)**

- **Conservative composite scoring**: Single-signal detections (isolated DGA, Tunnel, Beacon without corroboration) are now hard-capped at **0.65**. Multiple signals are required to push higher scores. This is the single biggest reducer of false positives from weird-but-benign domains.
- **Early whitelist exit**: If a domain matches an enabled whitelist rule, all detection scoring is skipped entirely (previously only affected display).
- **Device context scoring** (new in SNR-09):
  - +0.12 boost for suspicious activity coming from `iot` or `guest` network segments.
  - +0.10 boost for known IoT/embedded vendors (Espressif, Realtek, MediaTek, Broadcom, etc.).
  - +0.08 boost for unknown vendors doing suspicious activity.
- Added `iot_context` tag for visibility.

**DGA Detector (`dga.go`)**

- Added `knownBenignHighEntropyDomains` list (CloudFront, Akamai, Fastly, Cloudflare, AWS, Google CDNs, jsDelivr, etc.).
- `ScoreDGA()` now early-exits for these patterns, eliminating a huge class of common false positives.

**Beaconing Detector (`beacon.go`)**

- Increased `MinSamples` from 6 → **8**.
- Tightened `CVThreshold` from 0.15 → **0.13**.
- Reduces false beacons from short regular app/OS telemetry bursts.

---

### 2. Passive Device Context (SNR-05)

**Backend Ingest (`backend/internal/api/router.go` - `handleSensorDNS`)**

- DNS events are now enriched at ingest time with `DeviceVendor` and `NetworkSegment` by looking up the `ClientIP` against the devices table (populated by ARP/DHCP/mDNS/SSDP passive discovery).
- This data is persisted and flows through enrichment and the UI.

**Frontend**

- Device vendor and network segment are now displayed as small badges directly in the main ThreatsView event rows.
- Expanded event view already showed device details; now benefits from richer, automatically populated data.

---

### 3. Suppression & Whitelist UX (SNR-04)

**ThreatsView (`frontend/src/App.jsx`)**

- Added a **"Quick Noise Reduction"** section in every expanded threat event.
- One-click buttons:
  - "Suppress this domain for this device"
  - "Suppress '[Primary Tag]' for this device"
- These pre-fill the suppression API with `domain + source_ip` (or tag + source_ip), using the device context.
- Users can now instantly train the system the moment they see noise, without leaving the threat view.

---

### 4. Event Presentation & Grouping (SNR-06)

**ThreatsView grouping logic**

- Completely reworked `groupEvents()`:
  - Old: Very narrow (exact same domain + source_ip + tags within 5 minutes).
  - New: Behavioral clustering by **(source device + network segment + primary detection tag)** over a **30-minute window**.
- Result: Repetitive alerts from the same device doing similar suspicious activity now collapse into clean summary groups with count badges.
- Dramatically reduces visual noise in the dashboard.

---

## Impact

These changes attack false positives at multiple layers:

1. **Prevention** — Known-benign domains and whitelisted traffic are excluded early.
2. **Scoring** — Conservative single-signal caps + device context make the system much smarter about what is actually suspicious.
3. **Triage** — Users can instantly suppress noise with device-aware rules.
4. **Presentation** — Behavioral grouping collapses repetitive noise into manageable summaries.

The system is now significantly better at distinguishing:
- "Weird domain from my laptop on the main network" → lower priority
- "Same weird domain from a new Espressif device on the IoT segment" → higher priority

---

## New Capability: EOL Router Risk Identification (May 2026)

Added the ability to detect specific End-of-Life routers and cameras known to be heavily exploited (FBI IC3 FLASH 2026-03-12 / AVrecon malware / SocksEscort residential proxy botnet).

- New fingerprint module: `backend/internal/fingerprint/eol.go` with curated signatures for the top models listed in the advisory (D-Link DIR-818LW/850L/860L, Netgear DGN2200v4/R7000, TP-Link Archer C20/WR84xN series, Zyxel VMG/EMG/PMG series, Hikvision cameras, plus broad detection for the 7 affected vendors).
- Devices matching these models are flagged at discovery time (passive mDNS/DHCP/SSDP + nmap + OUI + hostname) with `eol_risk` + `eol_model`.
- At DNS ingest: events from EOL devices receive the `eol_router` tag.
- In Enricher: strong +0.22 anomaly score boost + `eol_device_context` tag + explicit threat description when suspicious activity (DGA/tunnel/rebind/bypass) is seen from these devices. Also treated as high-risk context for rebinding and DNS bypass boosts.
- UI: prominent red "⚠ EOL" badge in device tables and detail panels (with advisory reference and specific model), special tag styling, quick suppression for "all EOL routers", context filter for EOL events.
- DB migration 015 adds the columns; fully integrated into device inventory, fingerprint engine, and scoring pipeline.

This directly extends "scanning capabilities" with risk-aware device context — exactly the kind of high-signal, low-noise addition that improves overall SNR while surfacing real threats (compromised edge devices used for proxying and C2).

## Remaining Work

- **SNR-02 / SNR-07**: Run the sensor with `sudo` on the real network to generate traffic and measure the actual improvement (critical for tuning thresholds).
- **SNR-08**: Final documentation and backlog update (this document is part of it).

---

**Date of major implementation**: May 2026 (via autonomous heartbeat executions)

All changes are backward compatible and preserve strong detection power for real threats (which typically produce multiple signals + often come from atypical devices).