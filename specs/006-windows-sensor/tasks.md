# Tasks: Windows Sensor

> Spec: [spec.md](spec.md) · Plan: [plan.md](plan.md) · Status: Draft · Created: 2026-07-11

Ordered so each step keeps Linux/macOS green. `[S]` = validate on a Proxmox Windows VM.

## W0 — De-risk (spike, do first)
- [ ] **W0.1** ETW spike: minimal `main` on a Win 11 VM that opens a real-time
  `Microsoft-Windows-DNS-Client` session and prints event 3006/3008 with qname/type/
  answers, using the candidate pure-Go ETW lib. Decide lib-vs-hand-rolled. `[S]`
- [ ] **W0.2** Confirm CI can emit a `CGO_ENABLED=0 GOOS=windows GOARCH=amd64` binary +
  checksum with no MinGW.

## W1 — Cross-platform refactor (no behavior change)
- [ ] **W1.1** Extract `main.go` post-setup body into `runLoop(ctx)`.
- [ ] **W1.2** Unix/interactive front-end via `signal.NotifyContext(os.Interrupt, SIGTERM)`
  (`SIGTERM` behind `!windows`).
- [ ] **W1.3** Verify: full Linux/macOS `go build/vet/test` unchanged; graceful shutdown
  still drains captures.

## W2 — Windows service front-end (`//go:build windows`)
- [ ] **W2.1** `service_windows.go`: `svc.Handler` mapping `Stop/Shutdown`→`cancel(ctx)`,
  state reporting with `WaitHint 12s`; `svc.IsWindowsService()` picks service vs console.
- [ ] **W2.2** `--install-service` / `--uninstall-service` via `svc/mgr`.
- [ ] **W2.3** `[S]` `net stop`/`net start` drain cleanly on a VM.

## W3 — Token path + ACL (security fix)
- [ ] **W3.1** `client/core.go`: `%ProgramData%\Vedetta\sensor-token` on Windows
  (`VEDETTA_SENSOR_TOKEN_FILE` override still wins); warn if the dir is world-readable.
- [ ] **W3.2** `[S]` confirm a non-admin user cannot read the token after install (`icacls`).

## W4 — ETW DNS capture (`//go:build windows`)
- [ ] **W4.1** `dnscap/capture_windows.go` implementing the `Capturer` interface via ETW;
  map 3006/3008 → `Query`. Existing `capture.go` → `//go:build !windows`.
- [ ] **W4.2** Table tests for event→`Query` mapping with synthetic/RFC-5737 fixtures.
- [ ] **W4.3** `[S]` DNS from the VM (`nslookup`, browser) reaches Core with correct
  qname/type/answers.

## W5 — Native discovery (`//go:build windows`)
- [ ] **W5.1** Windows `netscan`: `GetIpNetTable2` neighbor read + `IcmpSendEcho` sweep →
  same host/MAC observations as the Unix nmap path.
- [ ] **W5.2** Windows interface classifier (`capture_selection_windows.go`).
- [ ] **W5.3** Parsing unit tests (synthetic fixtures).
- [ ] **W5.4** `[S]` discovers other VMs on a test segment with MACs, no admin/Npcap;
  document firewalled-host ceiling.

## W6 — Installer + CI + UX
- [ ] **W6.1** `deploy/install.ps1`: self-elevate, checksum-verify asset, drop to
  `%ProgramFiles%\Vedetta`, `New-Service` with flags inlined, `sc.exe failure` restart,
  `icacls` token ACL, single-use enroll-code caveat print.
- [ ] **W6.2** CI: cgo-free `windows/amd64` release asset + checksum entry.
- [ ] **W6.3** `runtime.GOOS`-keyed "Run as Administrator" messaging in `main.go`.
- [ ] **W6.4** `[S]` clean-VM install → enroll → running service; re-run without
  `--enroll-code` rewrites the service command line (no consumed-code replay).

## W7 — Docs + release
- [ ] **W7.1** README/architecture: Windows now a supported sensor (endpoint scope; ETW
  DNS + native discovery; DoH/network-wide limits documented).
- [ ] **W7.2** Full four-module build+vet+test + env-data gate + iCloud sweep (pre-handoff).
- [ ] **W7.3** Tag the Windows sensor in the next release notes.

## Later (not this feature) — Phase 3 optional tier
- [ ] Runtime-detected Npcap → pcap L2 passive capture; runtime-detected nmap → deep scan.
  Gated, never required. Would introduce the only cgo build.
