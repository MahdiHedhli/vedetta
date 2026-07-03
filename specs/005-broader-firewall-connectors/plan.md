# Plan: Broader Firewall Connectors (OpenWRT, pfSense/OPNsense, MikroTik)

> Spec: `specs/005-broader-firewall-connectors/spec.md`
> Status: Draft — STUB
> Created: 2026-07-03
>
> **Blocked on: specs/001 UniFi shipping + SNR validation.**

This plan is intentionally a stub. Per the constitution's one-source-at-a-time
rule, no technical planning for OpenWRT, pfSense/OPNsense, or MikroTik begins
until the UniFi connector (specs/001-unifi-log-ingestion/) is shipped as a
complete, tuned workflow with a recorded SNR validation pass.

When unblocked, each platform gets a full plan (architecture, data flow, Fluent
Bit parser design, SNR tuning plan, failure modes, test strategy) following
`.specify/templates/plan-template.md`, in roadmap order: OpenWRT →
pfSense/OPNsense → MikroTik. Starting points:

- `research/deep-dive-firewall-connectors.md` — filterlog field spec, parser +
  Lua design, polling/rate-limit guidance.
- `docs/connector-guide.md` — `firewall.Connector` interface in
  `backend/internal/firewall/`.
- The UniFi implementation and its SNR pass — reusable normalization, tagging,
  and suppression patterns.

No tasks.md exists for this spec; none will be created until this blocker
clears and a real plan replaces this stub.
