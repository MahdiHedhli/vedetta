# Spec: [FEATURE NAME]

> Feature directory: `specs/NNN-feature-name/`
> Status: Draft | In Review | Approved | Implemented
> Backlog: VED-xxx
> Created: YYYY-MM-DD

## Summary

One paragraph: what this feature is and the user-visible outcome.

## Motivation & Evidence

Why now. Cite primary sources (research/ deep dives, vendor docs, advisories,
observed gaps). Link related roadmap themes.

## User Stories

- As a [homelab user / small business operator / MSP], I want [capability] so that
  [outcome].

## Requirements

### Functional
- FR-1: ...
- FR-2: ...

### Non-Functional
- NFR-1: Pi 4 hardware floor — idle budget impact.
- NFR-2: Works with Core + native sensor only (no new required dependencies).

## Constitution Check

| Constraint | Applies? | How this feature complies |
| --- | --- | --- |
| L2 native sensor split | | |
| Pi-hole optional | | |
| Passive-first | | |
| V1 scope (no LAN scan/exploit) | | |
| SNR re-tune for new sources | | |
| Privacy / opt-in telemetry | | |
| Environment data handling | | |

## Signal-to-Noise Impact

New noise patterns this feature introduces and the tuning work it demands
(suppression rules, scoring context, whitelists). "None" requires justification.

## Out of Scope

Explicit cuts, with one-line rationale each.

## Open Questions

- [ ] ...
