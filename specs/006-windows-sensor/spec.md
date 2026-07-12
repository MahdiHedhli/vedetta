# Spec: Windows Sensor

> Feature directory: `specs/006-windows-sensor/`
> Status: **Shipped (v0.1.0-beta.2)** — v1 complete on `main`
> Backlog: VED-018
> Created: 2026-07-11

## Overview

> Problem statement below reflects the pre-006 state; the Windows sensor described here
> shipped in v0.1.0-beta.2 (driver-free: ETW DNS + native ICMP/ARP; see the tasks list).

Vedetta's sensor is a Go binary that today builds and runs natively only on Linux
and macOS. This feature adds a first-class **Windows** sensor so a Windows 11 /
Windows 10 22H2 (and, smoke-tested, Windows Server 2022) host can enroll into a
Core and contribute passive DNS and device-discovery telemetry like any other
sensor.

Much of the sensor — flag parsing, the scan loop, batching, the enrollment
handshake, HTTP/JSON client, `runtime.GOOS/GOARCH` identity, `net.Interfaces()`
enumeration, and the nmap XML parser — is already portable and compiles on
Windows unchanged. The Windows-specific work concentrates in four areas:

1. **Packet capture.** `internal/dnscap` and `internal/passive` use `gopacket/pcap`.
   On Unix that binds libpcap via cgo; on **Windows** `gopacket/pcap` loads
   `wpcap.dll` at **runtime** (no cgo, no SDK) — so the sensor *already*
   cross-compiles to `windows/amd64` with `CGO_ENABLED=0` (verified), but the pcap
   path *runs* only if **Npcap** (whose free license forbids redistribution/silent
   install, caps at 5 installs) is installed. Rather than take that runtime
   dependency, the default Windows DNS path uses the built-in **ETW
   `Microsoft-Windows-DNS-Client` provider** (no driver, no `wpcap.dll`); the
   pcap path becomes the Phase-3 opt-in when the user has installed Npcap.
2. **Service lifecycle.** `cmd/vedetta-sensor/main.go` shuts down on `SIGINT/SIGTERM`.
   Under the Windows Service Control Manager (SCM) those signals are never delivered,
   so today's graceful `shutdownCaptures` path would never fire on `net stop`. Needs
   an SCM handler.
3. **Interface naming/classification.** `internal/netinfo/capture_selection.go` keys
   every heuristic off POSIX names (`en`, `eth`, `lo`, `utun`, `docker`…). On Windows
   `net.Interface.Name` is a friendly string ("Ethernet"), so the classifier must be
   Windows-aware.
4. **Installer + token security.** `deploy/install.sh` is POSIX-only. Windows needs a
   net-new PowerShell installer + service registration. And `client/core.go`'s `0600`
   chmod is a **no-op on NTFS** — the token would be world-readable without an ACL fix.

The recommended shape is an **endpoint agent**: on Windows the default DNS-capture
path uses ETW (pure-Go), and device discovery uses **native-Go Windows APIs**
(neighbor-table read + unprivileged ICMP sweep + the existing mDNS/SSDP listeners).
Npcap and nmap become **optional, user-installed** enhancements the sensor detects
at runtime — never bundled. The Windows sensor is therefore a single static,
cgo-free binary with no kernel driver and no per-company license fee.

## Goals

- A supported `vedetta-sensor_windows_amd64` build that enrolls into a Core using the
  existing single-use enrollment-code / admin-bearer flow, unchanged on the wire.
- Passive DNS telemetry on Windows with **zero driver install**, via ETW — the same
  query-name/type/answer signal `internal/dnscap` emits today.
- Native-Go device discovery (neighbor table + ICMP sweep + mDNS/SSDP) that runs
  without Npcap, without nmap, and without a kernel driver.
- Correct operation as a Windows service under the SCM, with graceful shutdown that
  drains captures within the existing ~10s window.
- A `deploy/install.ps1` that mirrors the `install.sh` UX (checksum-verified release
  asset, service registration with flags inlined, single-use enroll-code caveat).
- Token stored at `%ProgramData%\Vedetta` with an ACL matching the `0600` intent
  (SYSTEM + Administrators only).
- No new required third-party dependency and **no regression on Linux/macOS** — all
  Windows code sits behind `//go:build windows`.

## Non-Goals

- **Network-wide / SPAN / gateway passive capture on Windows.** ETW sees only this
  host's OS-resolver DNS; it cannot mirror a whole LAN. Network-wide mode stays a
  Linux/macOS + pcap story.
- **Bundling or silently installing Npcap or nmap.** Both require paid OEM licenses
  to redistribute or silent-install; out of scope (see Risks & Licensing).
- **MSI / WiX installer, Add/Remove Programs entry, GPO/Intune packaging.** Deferred
  until there are enterprise users and an OEM license.
- **DoH/DoT visibility.** ETW DNS-Client does not see app-embedded DoH (browsers),
  containers, or VMs with their own resolver stack. Documented limitation.
- **Windows `arm64`.** amd64 only for v1; arm64 can follow once amd64 is proven.
- **DPAPI encryption-at-rest of the token.** ACL-locked `%ProgramData%` matches the
  current threat model; DPAPI is a later hardening option.

## Scope

### v1 (this feature) — Endpoint DNS + native discovery

Per the owner decision, v1 ships passive DNS **and** native device discovery
together as the first Windows release. It comprises:

- **ETW DNS capture** — a `//go:build windows` `dnscap` implementation mirroring the
  `dnscap.Capturer` interface, consuming `Microsoft-Windows-DNS-Client` events
  (3006/3008) and emitting the same query/type/answers the pcap path does today.
- **SCM service wrapper** — a `service_windows.go` + a `signal.NotifyContext` refactor
  of the run loop so one binary serves both interactive and service modes; the Unix
  path is unchanged. Reports `StartPending→Running→StopPending(WaitHint ~12s)→Stopped`.
- **Native-Go active discovery** — Windows neighbor-table read (`GetIpNetTable2` via
  `iphlpapi.dll`) + an unprivileged ICMP sweep (`IcmpSendEcho`) to populate IP↔MAC and
  host liveness, feeding the same device-observation path the nmap `-sn` sweep feeds on
  Unix. No admin, no driver, no cgo.
- **mDNS/SSDP listeners** — the existing cross-platform UDP listeners in `internal/passive`
  (the L2/pcap ARP/DHCP parts stay `!windows`).
- **Windows interface classifier** — a Windows-aware `is*Interface` classifier and
  capture-selection so `--dns-iface` / device selection behave sensibly.
- **`%ProgramData%\Vedetta` token path + ACL** — Windows branch in `client/core.go`;
  the installer applies `icacls` to match the `0600` intent.
- **`deploy/install.ps1`** — elevated one-liner mirroring `install.sh`: checksum-verify
  the release asset, drop the binary to `%ProgramFiles%\Vedetta`, `New-Service` with
  `--core/--enroll-code/...` inlined, `sc.exe failure` restart parity, single-use
  enroll-code caveat print.
- **CI** — a cgo-free `windows/amd64` release asset + checksum entry.
- **"Run as Administrator"** operator messaging replacing "run with sudo" on Windows.

### Later (Phase 3, optional power-user tier — NOT this feature)

- Runtime-detected **Npcap** enables full L2 passive capture (ARP/DHCP) and
  **nmap**-backed deep scan (`-sS`, fingerprinting) — **only** when the user has
  installed Npcap + nmap themselves. Gated behind a detection check; never required.
  This is the only path that could later justify an OEM license.
  - **Npcap is necessary-but-not-sufficient for network-wide DNS.** On a normal
    endpoint a NIC sees only this host's + broadcast/multicast traffic, so Npcap there
    buys roughly what ETW already gives for DNS (plus L2 discovery). Capturing *other*
    devices' resolver DNS additionally requires network **placement** — a switch
    SPAN/mirror port, a TAP, or the host acting as gateway/resolver. It is not a
    "see everything" toggle; that network-sensor mode stays the Linux/macOS
    on-a-gateway story.

### Out of scope

- Everything under Non-Goals.

## Architecture & Windows-specific components

| Component | File(s) | Change |
| --- | --- | --- |
| DNS capture (Windows) | new `internal/dnscap/capture_windows.go` (`//go:build windows`) | ETW `Microsoft-Windows-DNS-Client` real-time session via a pure-Go ETW consumer; emits the same query/type/answers the pcap path does. Existing `capture.go` gets `//go:build !windows`. |
| Passive L2 capture | `internal/passive/capture.go` | Stays pcap/`!windows`. mDNS/SSDP UDP listeners are already cross-platform and stay shared. Phase 3 later adds a Windows pcap variant only when Npcap is detected. |
| Service wrapper | new `cmd/.../service_windows.go` (`//go:build windows`) + refactor `main.go` | Extract the post-setup body into `runLoop(ctx)`. Unix/interactive: `signal.NotifyContext(SIGINT,SIGTERM)`. Windows service: `svc.Run` mapping `svc.Stop/Shutdown`→`cancel()`. `svc.IsWindowsService()` picks the front-end. Uses `golang.org/x/sys/windows/svc`. |
| Discovery (native) | new Windows files under `internal/netscan` | `GetIpNetTable2` neighbor read + `IcmpSendEcho` sweep via `x/sys/windows` `LazyDLL`. No cgo, no admin. Shares the device-observation/report path with the Unix nmap path. |
| Interface classify | new `capture_selection_windows.go` | Windows `is*Interface` classifier keyed off friendly name / adapter type. Scoring math reused. |
| Token path + ACL | `internal/client/core.go` | `runtime.GOOS=="windows"` branch → `%ProgramData%\Vedetta\sensor-token` (keep `VEDETTA_SENSOR_TOKEN_FILE` override first). Installer applies `icacls /inheritance:r /grant:r SYSTEM:F Administrators:F`. |
| Installer | new `deploy/install.ps1` | Mirrors `install.sh`. |
| Elevation messaging | `main.go` | `runtime.GOOS`-keyed "Run as Administrator" vs "run with sudo". |

## Build & packaging

- **The v1 binary is pure-Go and cross-compilable**: ETW + native discovery need no
  cgo and no SDK, so `GOOS=windows GOARCH=amd64` builds from the existing CI runners
  with a checksum entry alongside the linux/darwin assets. This is the reason to
  prefer ETW over Npcap.
- **Phase 3 (optional pcap) would be the only cgo path** and stays isolated behind its
  own build tag so the default asset remains cgo-free.
- **Service registration** is done by the installer (`New-Service` + `sc.exe`), with a
  `--install-service`/`--uninstall-service` convenience path using `x/sys/windows/svc/mgr`.
- **Distribution stance:** fetch, never redistribute, any third-party dependency.

## Testing on Proxmox Windows VMs

Test matrix (owner-approved): **Windows 11** (client, primary), **Windows 10 22H2**
(client, floor), **Windows Server 2022** (server, smoke). Provision as Proxmox VMs.

- **ETW DNS:** enroll against a loopback/reverse-proxied Core; generate DNS from the VM
  (`nslookup`, browser via system resolver) and assert events reach Core with correct
  qname/type/answers. Verify the service starts on boot, survives `net stop`/`net start`
  with a clean capture drain, and that LocalSystem resolves the token to
  `%ProgramData%\Vedetta` with the ACL locked (a non-admin user cannot read it).
- **Enroll-code lifecycle:** confirm the installer prints the caveat and that re-running
  without `--enroll-code` rewrites the service command line (a restart doesn't replay a
  consumed code).
- **Native discovery:** on a small test segment, verify neighbor-table + ICMP sweep
  discovers other VMs and attaches MACs, with no admin and no Npcap. Document the
  firewalled-host under-count ceiling.
- **Regression:** full Linux/macOS build+vet+test to prove the `//go:build` tags didn't
  disturb the Unix paths (per [[error-check-before-handoff]]).

## Risks & licensing

- **Npcap free license** forbids redistribution, caps at 5 installs, and has no silent
  installer; silent + redistributable requires a paid, per-company **Npcap OEM**
  license. *Mitigation:* v1 bundles neither — ETW + native-Go make the default path
  driver-free and license-clean; Npcap/nmap are user-installed opt-ins. Subprocessing a
  user-installed nmap is explicitly free use.
- **ETW coverage ceiling.** Sees only OS-resolver DNS on the local host — misses browser
  DoH, containers, and other LAN devices. Acceptable because the Windows sensor is an
  endpoint agent, not a network sensor. Must be documented.
- **ETW requires an elevated runtime session** (Administrator / "Performance Log Users").
  Handled by running the service as LocalSystem. Not a driver install.
- **SCM shutdown is a latent bug today** — the refactor is required, not optional. Set
  `WaitHint` > the 10s drain.
- **NTFS token security.** `os.Chmod(0600)` silently does nothing on Windows; without
  the installer ACL the token is world-readable. A real security bug — the ACL step is
  mandatory.

## Environment-data handling note

Per [[no-homelab-data-in-commits]]: all spec examples, test fixtures, and any captured
sample DNS/device data committed for this feature MUST be anonymized to RFC 5737
addresses and synthetic hostnames — never real homelab IPs, MACs, device names, or
resolved domains. ETW DNS-Client events and mDNS/SSDP friendly names are potentially
personal (query history, "Alice's-PC"); they stay local-only and are never added to any
telemetry or export path. Vedetta telemetry remains opt-out/pseudonymous and unchanged
by this feature — no Windows-specific fields are added to the telemetry payload. The
env-data gate runs before every commit/push/merge for this feature.
