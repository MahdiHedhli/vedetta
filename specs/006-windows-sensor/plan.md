# Plan: Windows Sensor

> Spec: [spec.md](spec.md) · Status: Draft · Created: 2026-07-11

## Approach & sequencing

Build in an order that (a) lands the platform-agnostic refactors first so both
Unix and Windows share one run loop, then (b) adds Windows-specific files behind
`//go:build windows`, and (c) proves each layer on the Proxmox VMs before moving on.
Every step keeps Linux/macOS green (build tags isolate all Windows code).

1. **Cross-platform refactor (no behavior change).** Extract the post-setup body of
   `cmd/vedetta-sensor/main.go` into `runLoop(ctx context.Context)`. Interactive/Unix
   uses `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)` (SIGTERM is
   `!windows`). This is the seam the Windows service handler plugs into. Verify Unix
   build+vet+test unchanged.
2. **Windows service front-end.** `service_windows.go` implements `svc.Handler`:
   `svc.IsWindowsService()` decides service vs console; on `Stop/Shutdown` it cancels
   the same `ctx`, reporting `StartPending → Running → StopPending(WaitHint 12s) →
   Stopped`. Add `--install-service` / `--uninstall-service` via `svc/mgr`.
3. **Token path + ACL (security fix).** `client/core.go`: honor `VEDETTA_SENSOR_TOKEN_FILE`
   first, else `%ProgramData%\Vedetta\sensor-token` on Windows. `os.Chmod(0600)` is a
   no-op on NTFS, so the installer applies the ACL; the binary logs a warning if the
   token dir is group/world-readable.
4. **ETW DNS capture.** `dnscap/capture_windows.go` mirrors the `Capturer` interface,
   opening a real-time ETW session on `Microsoft-Windows-DNS-Client`, mapping event
   3006 (query) / 3008 (response) to the existing `Query` struct. Existing `capture.go`
   → `//go:build !windows`. Interface + tests shared.
5. **Native discovery.** Windows `netscan` file: `GetIpNetTable2` neighbor read +
   `IcmpSendEcho` sweep over the selected subnet, emitting the same host/MAC
   observations the nmap path emits. Shares report plumbing with Unix.
6. **Interface classifier.** `capture_selection_windows.go`: Windows-aware `is*Interface`
   + selection so device/`--dns-iface` UX is sane; scoring math reused.
7. **Installer + CI.** `deploy/install.ps1` + a cgo-free `windows/amd64` CI release asset
   with checksum. Elevation messaging (`"Run as Administrator"`).
8. **QA on Proxmox** (Win 11 / Win 10 22H2 / Server 2022) per the spec Testing section.

## Technical approach

- **ETW consumer library — CONFIRMED: `github.com/0xrawsec/golang-etw` v1.6.2.** The
  W0.1 spike proved this pure-Go consumer cleanly yields 3006/3008 (+3009/3016/3018/
  3020) with QueryName/QueryType/QueryResults/QueryStatus on Win 11, cgo-free. A new
  Go-module dependency is fine (cgo-free, like gopacket) — the "no new required
  dependency" goal is about kernel drivers (Npcap) / external binaries (nmap), not Go
  modules. Pin it; confirm its license is permissive before W4 lands (spike used it
  fine; do the formal license check at import time).
- **Service.** `golang.org/x/sys/windows/svc` (std-adjacent, already a transitive dep)
  over `kardianos/service` — fewer moving parts, no extra dependency, direct SCM
  control for the `WaitHint` drain.
- **Discovery.** `x/sys/windows` `LazyDLL`/`LazyProc` against `iphlpapi.dll`
  (`GetIpNetTable2`) and `IPHLPAPI` (`IcmpCreateFile`/`IcmpSendEcho`). No cgo. ICMP
  echo does not require admin on Windows; neighbor-table read is unprivileged.
- **Build tags.** Every Windows file is `//go:build windows`; every currently-pcap file
  that must not compile on Windows gets `//go:build !windows`. The default release asset
  is `CGO_ENABLED=0`.

## Dependencies

| Dependency | Purpose | Notes |
| --- | --- | --- |
| `golang.org/x/sys/windows` (+ `/svc`, `/svc/mgr`) | Service, ICMP, iphlpapi, ACL helpers | Already an indirect dep; promote to direct. cgo-free. |
| pure-Go ETW consumer (e.g. `0xrawsec/golang-etw`) | DNS-Client ETW session | Validate in the W1 spike; pin + license-check. cgo-free. |

## Testing strategy

- **Unit:** ETW event→`Query` mapping and native-discovery parsing get table tests with
  **synthetic, RFC 5737 / anonymized** fixtures (never real capture dumps).
- **Cross-platform regression:** `go build/vet/test` for all four modules on the Unix CI
  after every step (build tags must not break Unix).
- **Integration (Proxmox):** the spec Testing matrix — enroll, DNS event flow, service
  lifecycle (`net stop` drain), token ACL, native discovery on a test segment, enroll-code
  rewrite-on-reinstall.

## Risks / open spikes

- **W1 — ETW lib fit** (highest risk): does the chosen lib deliver 3006/3008 with qname,
  type, and answers reliably, on all three OS versions? De-risk before building the rest of
  the Windows path on it.
- **ETW elevation:** confirm LocalSystem gets the DNS-Client provider without extra config.
- **Discovery completeness:** firewalled hosts under-report; documented ceiling, not a bug.
- **CI Windows asset:** confirm the existing pipeline can emit a checksummed
  `windows/amd64` artifact with no MinGW.
