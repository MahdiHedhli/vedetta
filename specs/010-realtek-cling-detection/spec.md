# Realtek and Cling detection

## Goal

Detect evidence relevant to CVE-2021-35394 and Cling on networks monitored by
Vedetta. Keep potentially affected components, observed attacks, suspicious
behavior, and confirmed malware artifacts distinct. A missing observation never
establishes that a device is clean.

## Requirements

1. Collect narrowly filtered UDP observations on native Unix sensors. Recognize
   Realtek `orf;` attack traffic to UDP 9034 without sending any diagnostic command.
2. Detect repeated structurally valid STUN Binding Requests with zero transaction
   IDs across multiple peers. Correlate known infection-method registration tags
   with those requests. Ordinary STUN, Google destinations, and an isolated zero
   transaction ID must not create a compromise finding.
3. Provide a bounded, read-only audit of the sensor host or an explicitly supplied
   extracted filesystem. Inspect known Cling paths, hashes, init persistence, and
   wget replacement artifacts. Never execute an inspected file or follow a path
   outside the selected filesystem root.
4. Report Realtek UDPServer component/version evidence as potentially affected.
   SDK versions in the published range do not prove that an OEM backported patch
   is absent. Component presence does not prove that the service is running or
   reachable. OUI-only evidence is insufficient.
5. Deliver observations through authenticated sensor ingestion, stable retry IDs,
   the existing event-time device identity resolver, immutable detector evidence,
   durable findings, and suppression. Core owns verdicts.
6. Record collection coverage, read failures, and unsupported capture platforms.
   Local host inspection does not inspect other LAN devices' filesystems.
7. Tests use synthetic packets and files. No malware execution, real-device
   exploitation, or connections to botnet infrastructure are needed.

## Scope cuts

No active vulnerability assessment, remote shell collection, generic file crawl,
payload execution, automatic quarantine/remediation, or assertion that a network
is clean. No blanket STUN destination blocklist. Windows supports portable audit
logic for explicitly supplied extracted filesystems but no native packet capture
in this feature. DNS-only installations retain their existing coverage limits.

## Evidence states

| Evidence | Meaning |
| --- | --- |
| Realtek component and SDK marker | Potentially affected component; patch/exposure unknown |
| `orf;` request to UDP 9034 | Exploit attempt, not proof of successful execution |
| Zero-ID requests to at least three distinct peers in 60 seconds | Suspicious STUN behavior |
| Recognizable registration correlated with zero-ID requests | Probable Cling behavior |
| Known file digest | Confirmed malware artifact, execution unknown |
| Cling-like executable, distinctive markers and matching init persistence | Probable compromise |
| No match or incomplete collection | Not observed or not assessed, never clean |

The three-peer/60-second threshold is Vedetta policy, not a claim from the source
research. Keep state and queues bounded for small sensors.

## Constitution Check

- Native sensor plus Core architecture retained; Pi-hole remains optional.
- Passive-first: no exploit verification or UDP probing.
- Reuses existing anomaly event and finding storage; no migration necessary.
- Additive endpoint and flags preserve independently upgraded components.
- No live environment data; public research supplies protocol facts and hashes.
- Read/build/test the affected modules and build the frontend before commit.
- Changes remain on a feature branch for independent review.

## Primary sources

- https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-
- https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
- https://www.onekey.com/resource/advisory-multiple-issues-realtek-sdk-iot-supply-chain
- https://www.realtek.com/images/safe-report/Realtek_APRouter_SDK_Advisory-CVE-2021-35392_35395.pdf
- https://unit42.paloaltonetworks.com/realtek-sdk-vulnerability/
- https://datatracker.ietf.org/doc/html/rfc8489
