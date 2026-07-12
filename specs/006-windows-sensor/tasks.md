# Tasks: Windows Sensor

> Spec: [spec.md](spec.md) · Plan: [plan.md](plan.md) · Status: **v1 complete — shipped to `main`** · Created: 2026-07-11

Ordered so each step keeps Linux/macOS green. `[S]` = validate on a Proxmox Windows VM.

## W0 — De-risk (spike, do first)
- [x] **W0.1** ETW spike — **DONE, confirmed on Win 11 (VEDETTA-WIN).** A cgo-free
  Go probe using `github.com/0xrawsec/golang-etw` v1.6.2 opened a real-time
  `Microsoft-Windows-DNS-Client` session (GUID `{1C95126E-...DB4D}`) and captured, run
  elevated over SSH: **3006** = query (`QueryName`, `QueryType`), **3008** = response
  (`QueryName`, `QueryType`, `QueryResults`, `QueryStatus`), plus 3009/3010/3016/3018/3020.
  71 events / 65 with query names in 15s. **Lib decision: golang-etw** (pure-Go, no
  hand-roll needed). W4 mapping: `3006 → {Domain, QueryType}`, `3008 → {Domain,
  QueryType, Answers=QueryResults, Status}`. Probe: `scratchpad/etwspike/`.
  NOTE (dev tooling): Windows OpenSSH with DefaultShell=PowerShell **breaks legacy
  `scp`** — use `sftp` to push binaries to the VMs.
- [x] **W0.2** Confirm a `CGO_ENABLED=0 GOOS=windows GOARCH=amd64` binary builds with no
  MinGW. **Done** — `go build ./...` for windows/amd64 succeeds today (gopacket/pcap loads
  `wpcap.dll` at runtime on Windows, so no cgo at build time). CI wiring is W6.2.

## W1 — Cross-platform refactor (no behavior change) ✅
- [x] **W1.1** Extract `main.go`'s periodic loop into `sensorRun.loop(ctx)`.
- [x] **W1.2** Unix/interactive front-end via `signal.NotifyContext(os.Interrupt, SIGTERM)`.
  (SIGTERM compiles + is a harmless no-op on Windows, so no build tag was needed here.)
- [x] **W1.3** Verified: Linux/macOS `go build/vet/test` green (6 pkgs); windows/amd64
  cross-compiles clean; shutdown drain unchanged.

## W2 — Windows service front-end (`//go:build windows`) ✅
- [x] **W2.1** `runFrontend` split into `front_unix.go` (signal.NotifyContext SIGINT/SIGTERM)
  and `front_windows.go` (`svc.IsWindowsService()` → SCM via `sensorService` svc.Handler, else
  console Ctrl+C). The handler reports `StartPending → Running`, and on `Stop/Shutdown` cancels
  the run ctx and waits for the capture drain (`WaitHint 15s`) before `Stopped`. main.go now
  just calls `runFrontend(run)`.
- [x] **W2.2** ~~`--install-service`/`--uninstall-service`~~ — **deferred:** the installer (W6)
  registers/removes the service via `New-Service`/`sc.exe`, so a self-install flag isn't needed
  for v1.
- [x] **W2.3** `[S]` **validated on Win 11:** `New-Service` → `Start-Service` → **Running**;
  `Stop-Service` → **Stopped** cleanly (drain completed, no hang); service ran as LocalSystem.

## W3 — Token path + ACL (security fix) ✅
- [x] **W3.1** `client/core.go`: `%ProgramData%\Vedetta\sensor-token` on Windows
  (`VEDETTA_SENSOR_TOKEN_FILE` override still wins). Perm-hardening split into build-tagged
  `securePath`/`hasInsecurePerms` — POSIX `chmod` (`token_perms_other.go`) vs an NTFS ACL
  via `icacls /inheritance:r /grant:r *S-1-5-18:(F) *S-1-5-32-544:(F)` (`token_perms_windows.go`),
  since `os.Chmod` is a no-op on NTFS. Unix + windows cross-compile green; client tests pass.
- [x] **W3.2** `[S]` **validated on Win 11:** after `securePath`, the file ACL is exactly
  `NT AUTHORITY\SYSTEM:(F)` + `BUILTIN\Administrators:(F)` with inheritance removed — non-admins
  have no access.

## W4 — ETW DNS capture (`//go:build windows`) ✅
- [x] **W4.1** `dnscap/capture_windows.go` implements the `Capturer` (Start/Stop/Interface)
  via `golang-etw` on Microsoft-Windows-DNS-Client; `eventToQuery` maps 3006→{Domain,Type}
  and 3008→{Domain,Type,Answers}. `capture.go`/`capture_test.go` tagged `//go:build !windows`;
  `Query`/`Config` moved to shared `types.go`; pure parsers in shared `dns_parse.go`.
- [x] **W4.2** Table tests for `dnsTypeName` + `parseQueryResults` (RFC 5737/3849 fixtures) —
  run in the Unix CI (shared file). Green.
- [x] **W4.3** `[S]` **validated on Win 11:** the real `dnscap.Capturer` emitted Query objects
  from live DNS — e.g. `example.com A`, `example.com AAAA answers=[…]`, `one.one.one.one AAAA
  answers=[1.0.0.1 1.1.1.1]`, plus the synthetic `vedetta-etw-test.example`. (Core round-trip
  folds into the W6 end-to-end install test.)

## W5 — Native discovery (`//go:build windows`) ✅
- [x] **W5.1** Windows `netscan` native `Scanner`: bounded concurrent **`IcmpSendEcho`**
  (iphlpapi) sweep + **`arp -a`** MAC resolution, unioned with ARP-known neighbors (so
  firewalled hosts that drop ICMP but answer ARP are still found). `NewScanner()` no
  longer fatals on Windows (no nmap). `ScanResult`/`DiscoveredHost` → shared `types.go`;
  `scanner.go`/`scanner_test.go` tagged `!windows`; `main.go` scanner log made
  platform-neutral.
- [x] **W5.2** ~~Interface classifier~~ — **N/A for v1.** ETW DNS is host-scoped and the
  native ICMP scan isn't interface-bound, so there's no capture-interface to classify on
  Windows v1. (Only relevant if the Phase-3 pcap path lands.)
- [x] **W5.3** Unit tests for `enumerateHosts` + `isRealNeighbor` (RFC 5737/3849 fixtures),
  green in the Unix CI.
- [x] **W5.4** `[S]` **validated on Win 11:** discovered 8 hosts on the lab segment in ~2s
  with no admin/Npcap — 6 via ICMP + 2 firewalled Windows VMs via ARP; documented ceiling
  confirmed (Windows hosts drop ICMP but the sweep's ARP resolution still finds them).

### W5 follow-up (not blocking v1)
- [ ] Passive ARP/DHCP discovery on Windows uses `internal/passive` (pcap) → Npcap-gated
  (Phase 3). Decouple the mDNS/SSDP UDP listeners from pcap so they run driver-free in v1.

## W6 — Installer + CI + UX ✅
- [x] **W6.1** `deploy/install.ps1`: self-elevates (`Start-Process -Verb RunAs`),
  checksum-verifies the release zip (or `-Binary` escape hatch), drops to
  `%ProgramFiles%\Vedetta`, `New-Service` (LocalSystem, auto-start) with flags inlined,
  `sc.exe failure … restart/10000`, `icacls` token-dir ACL (SYSTEM + Administrators),
  single-use enroll-code caveat print. Pure ASCII (PS 5.1 reads without a BOM).
- [x] **W6.2** CI (`release.yml`): cgo-free `windows/amd64` matrix entry cross-compiled on
  ubuntu (no MinGW), packaged as `.zip`, stamp asserted via embedded string (the .exe can't
  run on the linux runner), added to `checksums.txt` + release files.
- [x] **W6.3** `runtime.GOOS`-keyed `elevationHint()` in `main.go` — "Run as Administrator,
  or install as a service" on Windows vs "sudo" elsewhere (Windows DNS elevation already
  comes from the ETW start error).
- [x] **W6.4** `[S]` **validated on Win 11:** `install.ps1 -Binary … -EnrollCode CODE` →
  service **Running**, binPath carries the code; re-run **without** `-EnrollCode` rewrites
  the binPath to drop it (no consumed-code replay); token dir ACL = `Administrators`+`SYSTEM`
  (OI)(CI)(F) only; service uninstalls clean.

## W7 — Docs + release ✅
- [x] **W7.1** README + `sensor-architecture.md` + site: Windows now a supported sensor —
  host-scoped ETW DNS + native ICMP/ARP discovery, driver-free (no Npcap/nmap), LocalSystem
  service, `%ProgramData%\Vedetta` token ACL; DoH/network-wide limits documented.
- [x] **W7.1b** `[S]` **Full end-to-end proven on Win 11** (Core + sensor on one host over
  localhost): install → enroll (single-use code) → ETW DNS capture → push → **stored in Core
  and queryable by domain** (events 0 → 24; both marker domains present). This test caught the
  empty-ClientIP drop bug (fixed, commit 9ca54be).
- [x] **W7.2** Pre-handoff gate: all 5 Go modules (backend, sensor, telemetry, threat-network,
  scripts/simulate) `build`/`vet`/`test` green on darwin; sensor `windows/amd64` cross-compiles
  cgo-free; env-data gate clean (no lab subnet/hostnames/MACs/creds in the diff — only generic
  RFC1918 examples); iCloud `* 2.*` dup sweep clean.
- [x] **W7.3** Windows sensor added to `docs/releases/v0.1.0-beta.1.md` (driver-free; Win 11 /
  10 22H2 / Server 2022; host-scoped v1).

## Later (not this feature) — Phase 3 optional tier
- [ ] Runtime-detected Npcap → pcap L2 passive capture; runtime-detected nmap → deep scan.
  Gated, never required. Would introduce the only cgo build.
