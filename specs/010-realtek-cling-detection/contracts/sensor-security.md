# Sensor security observation contract (v1)

`POST /api/v1/sensor/security` accepts a sensor credential bound to `sensor_id`.
Request: `{ "sensor_id": "sensor-example", "observations": [...] }`.
At most 32 observations and 256 KiB per request. Response uses `accepted`,
`duplicates`, `failed`; partial persistence failure returns a retryable status.
An invalid batch is rejected before processing. Retrying the same observation ID
does not add occurrences. An older Core can return 404; log unsupported coverage
and disable this delivery path for that process rather than spin on retries.

Both Go modules define these JSON types in `internal/iotsecurity/types.go`:

```go
type Observation struct {
    ObservationID string `json:"observation_id"`
    Timestamp time.Time `json:"timestamp"`
    SubjectIP string `json:"subject_ip"`
    Kind string `json:"kind"`
    Packets []PacketEvidence `json:"packets,omitempty"`
    Files []FileEvidence `json:"files,omitempty"`
    Persistence []PersistenceEvidence `json:"persistence,omitempty"`
    SDK *SDKEvidence `json:"sdk,omitempty"`
    Coverage []Coverage `json:"coverage,omitempty"`
}
type PacketEvidence struct {
    Timestamp time.Time `json:"timestamp"`
    SourceIP string `json:"source_ip"`
    DestinationIP string `json:"destination_ip"`
    SourcePort uint16 `json:"source_port"`
    DestinationPort uint16 `json:"destination_port"`
    PayloadHex string `json:"payload_hex"`
    PayloadLength int `json:"payload_length"`
}
type FileEvidence struct {
    Path string `json:"path"`
    SHA256 string `json:"sha256,omitempty"`
    SHA1 string `json:"sha1,omitempty"`
    Size int64 `json:"size"`
    MagicHex string `json:"magic_hex,omitempty"`
    Executable bool `json:"executable"`
    Markers []string `json:"markers,omitempty"`
}
type PersistenceEvidence struct {
    Path string `json:"path"`
    Target string `json:"target"`
}
type SDKEvidence struct {
    ComponentPath string `json:"component_path"`
    MarkerPath string `json:"marker_path"`
    Family string `json:"family"`
    Version string `json:"version,omitempty"`
}
type Coverage struct {
    Check string `json:"check"`
    Status string `json:"status"`
    Detail string `json:"detail,omitempty"`
}
```

Kinds: `realtek_exploit`, `stun_fanout`, `cling_registration`, `host_audit`,
`coverage`. `realtek_exploit` identifies the packet destination as subject. The
STUN kinds identify the source. Host audit requires a concrete operator-supplied
or local sensor IP; do not guess a remote device. Audit CLI output can omit the
subject when it is not submitted, but submitted observations require an IP.

Limits: 16 packets, each with at most 128 captured payload bytes, 32 files,
16 persistence entries, 64 coverage entries. Packet payload length records the
original UDP application length; STUN header length must agree with it. A
Realtek exploit observation retains only the `orf;` prefix, never the commands.
All packet times must be within the observation's preceding 60-second window.
Fan-out requires at least three distinct destination IPs with valid zero-ID
Binding Requests. Registration requires a recognized infection tag on UDP
3478/19302 and a preceding zero-ID request on the same source/peer/ports within
that window. Equal timestamps are allowed for capture timestamp resolution.

The sensor emits a fresh random observation ID once and preserves it on retry.
Core derives a separate sensor-scoped event ID. Core stores the observation in
`metadata.iot_observation`, sets `event_type=anomaly`, and admits detector
evaluation only with the server-selected `sensor_security` origin. Public
collector ingress cannot claim that origin. No schema migration is needed.

Filesystem audit provenance is carried by one coverage entry with
`check=audit_source`, `status=inspected`, and `detail=live_sensor_root` for the
automatic current-host audit or `detail=explicit_filesystem` for the explicit
CLI mode. Core preserves this scope with detector evidence. Missing scope is
unknown, never inferred to be the live installed firmware. Repeated or conflicting
audit source entries are rejected.

## Constitution Check

Additive endpoint, bounded local evidence, authenticated sensor identity,
Core-owned verdicts, stable retries, and existing storage preserve V1 constraints.
