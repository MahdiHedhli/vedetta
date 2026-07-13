# Device Corpus API v1

## Public snapshot

`GET /api/v1/device-corpus/manifest` returns the corpus schema version, current corpus
revision, snapshot SHA-256, profile/variant counts, generation time, and the relative
`snapshot_path` on the same origin.

`GET /api/v1/device-corpus/snapshot` returns the immutable current release. Responses
include `ETag`, accept `If-None-Match`, and contain only published privacy-reduced
records. Corpus schema versioning is independent of the community-feed schema.

## Management authentication

Management routes exist only on the management listener. Every request requires
`Authorization: Bearer <256-bit-secret>`. Missing and incorrect credentials return the
same `401` response. Tokens are read from a file, hashed in memory for comparison, and
never logged or returned.

## Strict request behavior

- JSON body maximum: 64 KiB.
- Every request body requires `Content-Type: application/json` (optional media-type
  parameters are accepted); a missing or different media type returns
  `422 STRICT_SCHEMA`.
- Unknown or duplicate keys at any depth, including case-folded duplicates:
  `422 STRICT_SCHEMA`.
- Schema-valid content with an unsupported enum, invalid range, or missing required field:
  `422 VALIDATION_FAILED` with a fixed generic message.
- Privacy-forbidden values: `422 FORBIDDEN_CONTENT` with a fixed generic message; the
  rejected value and internal rule name are never reflected.
- Missing/stale `If-Match`: `428`/`409`.
- Unsupported method: `405`.
- No destructive DELETE routes.

## Canonical shape v1

```json
{
  "schema_version": 1,
  "dhcp_option_55": [1, 3, 6, 15, 119],
  "dhcp_vendor_classes": ["android-dhcp-14"],
  "oui_prefixes": ["00005E"],
  "hostname_templates": ["camera-{hex}"],
  "mdns_services": ["_rtsp._tcp"],
  "mdns_models": ["Example Camera 2"],
  "mdns_vendors": ["Example Devices"],
  "ssdp_device_types": ["urn:schemas-upnp-org:device:DigitalSecurityCamera:1"],
  "ssdp_server_tokens": ["ExampleOS/2 UPnP/1.1 ExampleCamera/2"],
  "tcp_ports": [80, 443, 554],
  "udp_ports": []
}
```

Empty fields are omitted from canonical JSON. Set-valued arrays are sorted/deduplicated;
DHCP option order is significant. A hostname template contains exactly one supported
placeholder and at least one ASCII alphanumeric product literal outside it. This object
has no extension map.

## Mutation lifecycle

Creating or revising produces drafts. Publishing atomically promotes the current profile
draft and each variant draft, supersedes their prior curator revisions, builds a new
immutable release, and advances the public corpus revision. Firmware evolution creates a
new variant series with `predecessor_variant_id`; it does not revise an old series.
New root variants use `new_variant`, successor series use `firmware_evolution`, and a
discarded never-published series uses `restore_reviewed` when restarted. Revisions of
an existing series accept only `signal_correction` or `source_update`.
Withdrawal of published content and retirement of a published profile are soft state
transitions that create a new release. Retiring a draft-only profile creates no public
release because it was never present in the public corpus. Prior
release bytes remain available to management for inspection and manual recovery.

Publish, profile-retire, and full variant-withdraw requests require both
concurrency preconditions. The publish request body is:

```json
{
  "reason_code": "publish_reviewed",
  "expected_corpus_revision": 12
}
```

Publish accepts only the `publish_reviewed` reason. Profile retirement and full
variant withdrawal accept only `obsolete_product` or `privacy_withdrawal`, with
the same revision precondition.

`If-Match` binds the target profile/variant state. `expected_corpus_revision` binds the
rest of the complete public snapshot the curator reviewed. If either changed, the
release-producing action is rejected with `409`; revision 0 is valid for the first
release and omission is invalid. The check occurs in the same transaction before any
lifecycle state or audit record changes. Discarding only an unpublished variant draft
does not create a release and therefore does not send `expected_corpus_revision`.
For publish, the profile/variant content is identical to the preview when accepted. The
release's `generated_at` is assigned at the actual commit time.

An abandoned never-published variant can be restarted under the same `variant_key`.
This retains its stable ID and audit history while allowing its predecessor to be
corrected. A stable key is immutable from creation; a mistaken key is abandoned and
recreated as a new series. The predecessor becomes database-enforced immutable after
the variant's first publication. Discarding a correction draft never withdraws the
currently published revision.

## Management routes

- `GET|POST /api/v1/admin/device-corpus/profiles`
- `GET|PUT /api/v1/admin/device-corpus/profiles/{profile_id}`
- `GET /api/v1/admin/device-corpus/profiles/{profile_id}/preview` (requires `If-Match`)
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/variants`
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/publish`
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/retire`
- `PUT /api/v1/admin/device-corpus/variants/{variant_id}`
- `POST /api/v1/admin/device-corpus/variants/{variant_id}/discard-draft`
- `POST /api/v1/admin/device-corpus/variants/{variant_id}/withdraw`
- `GET /api/v1/admin/device-corpus/audit`
- `GET /api/v1/admin/device-corpus/releases`
- `GET /api/v1/admin/device-corpus/releases/{corpus_revision}`

Collection routes accept `limit` (1–100, default 50) and non-negative `offset` exactly
once. The profile collection additionally accepts one `search` value of at most 128
bytes. Unknown or duplicate query parameters return `400 INVALID_QUERY`.

Profile, audit, and release collections return:

```json
{"items": [], "total": 0, "limit": 50, "offset": 0}
```

`total` counts the complete filtered result before pagination. A profile detail response
sets its current opaque `ETag`; mutation and preview requests send that value in
`If-Match`.

The preview response is server-validated and transactionally consistent:

```json
{
  "etag": "opaque-profile-etag",
  "current_corpus_revision": 12,
  "proposed_corpus_revision": 13,
  "snapshot": {
    "schema_version": 1,
    "corpus_revision": 13,
    "generated_at": "2026-07-13T18:00:00Z",
    "profiles": []
  }
}
```

The accepted publication uses the same `If-Match` and sends
`expected_corpus_revision: 12`. Its profile and variant content matches the preview;
only the release `generated_at` is assigned at commit time.

Retire and full-withdraw use the corpus revision shown in the dashboard's currently
loaded public snapshot. An intervening release for any other profile yields
`409 CORPUS_ADVANCED` without changing lifecycle state, audit history, or releases; the
curator must reload and review the new snapshot before retrying.

Every version fact must use a nonempty request-local `source_ref` that resolves to a
source in the same request. Server output IDs (`source_id` and `fact_id`) are rejected
on writes. `import` sources additionally require a nonempty redistributable
`license_code` recorded by the curator. `confidence_bp` is required on every variant
create/revise request and on every included version fact; an explicit value of `0` is
valid, while omission or `null` returns `422 VALIDATION_FAILED`.
