# Realtek CVE-2021-35394 and Cling detection

Vedetta evaluates Realtek component evidence and Cling compromise evidence
separately. These checks use passive packet collection and read-only filesystem
inspection. They do not send an exploit, start UDPServer, execute an inspected
binary, or change a device's configuration.

## What the detections mean

| Observation | Interpretation |
| --- | --- |
| Realtek SDK marker and an ELF UDPServer component in the audited filesystem | Potentially affected component; confirm the OEM firmware and backported patch status |
| UDP traffic to port 9034 beginning with `orf;` and additional content | Exploit attempt targeting the destination, execution and vulnerability unconfirmed |
| Valid zero-ID STUN Binding Requests to at least three distinct peers in 60 seconds | Suspicious behavior, not sufficient by itself to identify Cling |
| A recognized infection-method registration on the same source/peer socket as a zero-ID request | Probable Cling behavior |
| A published Cling campaign file digest | Confirmed campaign artifact; whether it executed is unknown |
| A Cling-like executable, distinctive embedded markers, and matching init persistence | Probable compromise |
| Missing files, no observed traffic, or a failed collection check | Not observed or not assessed within the reported coverage |

Realtek MAC addresses, generic IoT device labels, port numbers alone, Google STUN
traffic, normal randomized STUN transaction IDs, and an isolated zero-ID request
do not establish compromise. A zero-ID response to a zero-ID request is ordinary
STUN behavior and does not count as a second signal. The fan-out threshold is a
Vedetta heuristic and can miss variants that do not meet it.

## Enable passive detection

Upgrade both Core and the native sensor. Passive IoT detection is enabled by
default in normal sensor operation on supported Unix hosts. It uses libpcap and
the same capture privileges required by passive DNS. Pin the interface when
automatic selection does not match the intended monitoring point:

```sh
vedetta-sensor --core http://192.0.2.10:8080 --cidr 192.0.2.0/24 --iot-iface eth0
```

The additional BPF is restricted to UDP 9034, 3478, and 19302. Detection subjects
are restricted to the configured local target network. Normal sensor scanning
behavior remains controlled by the existing flags. The added detectors transmit
no diagnostic probes. Disable packet collection with `--iot-detection=false`.

An ordinary host on a switched LAN usually cannot observe other devices' unicast
traffic. A gateway, bridge, or mirrored port can provide broader coverage, subject
to the actual interface and capture configuration. For an authorized mirror port,
add `--iot-promiscuous`; the configured subject CIDR still limits detections.
The current BPF expects untagged frames or a capture path that strips VLAN tags;
raw tagged trunk mirrors are not covered by this filter.
Fragmented packets and IPv6 extension headers are not inspected. Joining the same
Wi-Fi network does not grant complete traffic visibility. DNS-only input cannot supply these
UDP protocol detections. Windows' current ETW DNS path does not capture them.

## Audit a host or extracted firmware

Linux sensors also audit a fixed set of local filesystem paths at startup and
every 15 minutes. Disable this with `--iot-host-audit=false`. This checks the
sensor's own filesystem only. Installing Vedetta on a computer does not grant
access to a router or camera's filesystem.

For an explicitly obtained firmware extraction or mounted filesystem, run:

```sh
vedetta-sensor --iot-audit-root /path/to/extracted-root
```

This mode prints a JSON observation and exits before nmap, registration, or
packet capture. It does not need a Core connection. Use `--iot-audit-root /` to
inspect the current host; privileges determine which fixed paths can be read.
Run this mode on an already mounted or extracted tree, not a firmware archive.

To attach the observation to the inspected device, an existing enrolled sensor
can submit it explicitly:

```sh
vedetta-sensor --iot-audit-root /path/to/extracted-root \
  --iot-audit-ip 192.0.2.25 \
  --iot-audit-submit --core http://192.0.2.10:8080
```

Choose the IP of the device whose filesystem was inspected. Core resolves the
device association using the observation time and retains identity uncertainty
when no suitable inventory binding exists. An offline firmware image does not
establish what is currently installed or running on that device.
The observation records whether it came from an automatic live sensor-root audit
or an explicit filesystem audit, so that distinction remains with the evidence.

The audit checks the documented `.cling` paths, selected init files, common
`wget`/`wget.r`/`wget.p` locations, selected UDPServer locations, and SDK markers
in `/etc/version` and `/etc/motd`. It limits file size and path count, refuses
special files and escapes from the selected root, and does not crawl the disk.
Symlinked files are skipped and reported in coverage, including BusyBox layouts
that link the inspected path to another executable. Unreadable or unsupported
layouts therefore reduce coverage rather than producing a clean verdict.
Persistence checks recognize straightforward init commands. Complex shell
constructs, continuations, functions, heredocs, and multiline quoting leave
persistence coverage partial; the audit still checks the file's digest.
Windows filesystem metadata does not preserve Unix execute permissions. An audit
run on Windows reports that limitation and leaves permission-dependent
persistence checks unassessed. File digest, marker, init-reference, and SDK
collection remain available for explicitly supplied extracted filesystems.

## Findings and coverage

Core creates separate durable findings for potential Realtek vulnerability,
observed exploit attempts, suspicious STUN behavior, probable Cling behavior, and
confirmed artifacts. Each includes the detection rationale, supporting evidence,
and recommended action. Existing finding investigation, resolution and
suppression controls apply. Suppression preserves the observation and evidence.

Coverage observations are retained as events and sensor logs explain unavailable
or disabled collection. A service that predates the new endpoint returns an
unsupported result; the sensor stops that delivery stream for the current run
and continues its other functions. Upgrade Core and restart the sensor to enable
it. Queues and retry backoff are bounded. Transient failures retain observation
IDs so retries do not inflate finding counts. In-memory observations may be lost
when a queue overflows or shutdown reaches its deadline; logs report this limit.
Core rejects malformed or out-of-window evidence with HTTP 400. A partially
persisted batch returns HTTP 503; the sensor retries the same observation IDs
so successfully stored entries remain duplicates.

Only bounded protocol evidence and fixed-path file observations are sent to the
local Core. Realtek attack observations retain the four-byte signature, not the
attacker's shell command. Whole packet captures and inspected binary contents are
not uploaded. The community exporter does not export these anomaly observations.

## Response guidance

For potential exposure, identify the exact device model, installed firmware and
OEM advisory. The published affected SDK range is 2.0 through 3.4.14B, but fixes
can be backported without changing the SDK marker. A UDPServer binary may also be
dormant, so its presence is not proof of a listening service or WAN exposure.

For probable compromise or a confirmed malware artifact, isolate the affected
device, preserve the available evidence, and use the vendor's supported recovery
procedure with known-good firmware. Patch or retire the vulnerable device and
review credentials used on it. Rebooting or deleting a `.cling` file alone does
not establish recovery because the documented malware modifies startup files and
can replace wget. Review the finding's evidence and coverage before concluding
that a device is currently infected or has been successfully restored.

## Sources and limitations

Research reviewed on 2026-10-06:

- [Nozomi Networks: Cling analysis, 2026-10-01](https://www.nozominetworks.com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-)
- [FortiGuard Labs: ClingSTUN analysis, 2026-10-05](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [ONEKEY: original Realtek SDK advisory](https://www.onekey.com/resource/advisory-multiple-issues-realtek-sdk-iot-supply-chain)
- [Realtek: SDK vendor advisory](https://www.realtek.com/images/safe-report/Realtek_APRouter_SDK_Advisory-CVE-2021-35392_35395.pdf)
- [Unit 42: CVE-2021-35394 analysis](https://unit42.paloaltonetworks.com/realtek-sdk-vulnerability/)
- [IETF RFC 8489: STUN](https://datatracker.ietf.org/doc/html/rfc8489)

This is targeted coverage for documented behaviors and artifacts. Variants can
change file hashes, paths, registration tags, timing, ports, or protocol behavior.
No absence of these indicators establishes that a device is clean.
