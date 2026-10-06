# Implementation plan

## Architecture

Add a sensor `internal/iotsecurity` package for bounded UDP parsing/aggregation,
portable evidence types, and read-only filesystem inspection. A native pcap
collector supplies UDP packets. An explicit audit command prints local JSON and
can submit it to Core when a subject IP is supplied. Normal sensor operation
enables passive collection with a disable flag. Linux host auditing is local to
the sensor; extracted firmware auditing is explicit.

Add a matching Core observation contract, a sensor-authenticated
`POST /api/v1/sensor/security` route, and a stateless evaluator called from the
central processor only for that authenticated origin. Use `anomaly` events, with
the subject IP in `source_ip` for event-time device association. Preserve actual
packet endpoints in observation metadata. The endpoint derives event IDs from
sensor identity and observation identity; clients retain IDs during retry.

Core validates facts, recomputes signatures, owns scores/rationale/actions, and
produces separate exposure, attack, suspicious behavior and artifact evidence.
No generic ingest metadata or caller-provided tag may manufacture a finding.

## Resource and privacy bounds

Use a narrow BPF, bounded packet prefixes, a maximum of 256 tracked subjects,
60-second correlation windows, and per-subject/type cooldowns. Queue at most 128
observations. Bound every request and observation array. Audit only a fixed
allowlist of paths; regular-file checks and root containment prevent special
files and symlink escapes. Bound bytes per file, report incomplete coverage, and
never execute target binaries. Do not retain full packets or arbitrary files.

## Signal quality

Validate STUN length, cookie, message type and zero transaction ID. A response
echoing zero is ordinary protocol behavior. Require fan-out before standalone
STUN findings, or a recognized infection tag on the same source/peer flow.
Do not assign malicious reputation to Google or other public STUN services.
Hash matches identify artifacts, while persistence correlation supports probable
compromise. Firmware component versions remain potentially affected because of
OEM backports and dormant diagnostic binaries.

## Constitution Check

Passive collection, native sensor split, no new schema, additive wire contract,
bounded memory, no required external integration, no live environment fixtures,
primary-source detection, and independent review all remain satisfied.
