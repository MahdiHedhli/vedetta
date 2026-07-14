# Plan: Curated Device Fingerprint Corpus

## Architecture

```text
Public Internet / Cloudflare                         Tailnet only
             |                                           |
             v                                           v
  public listener :9090                         dashboard shim :8787
  status/feed/corpus GET                         static UI + narrow proxy
             |                                  | public GET | admin CRUD
             |                                  v            v
             |                              :9090      127.0.0.1:9091
             |                                             |
             +---------------- SQLite ---------------------+
```

The public and management listeners share one `store.DB`, but admin routes are never
registered on the public mux. SQLite remains single-connection/single-writer; every
transactional helper performs all database work through its `*sql.Tx` to avoid waiting
on the only connection.

## Data model

- `device_corpus_state`: schema version and current immutable release pointer.
- `device_corpus_profiles`: stable product identities.
- `device_corpus_profile_revisions`: immutable manufacturer/model/type/OS labels.
- `device_corpus_shapes`: canonical typed shapes, deduplicated by SHA-256.
- `device_corpus_variants`: stable external firmware/hardware lineages.
- `device_corpus_variant_revisions`: immutable curator revisions referencing shapes.
- `device_corpus_version_facts`: typed version assertions per variant revision.
- `device_corpus_sources`: bounded public citations/coarse provenance.
- `device_corpus_audit`: append-only mutation audit without personal identity.
- `device_corpus_releases`: immutable complete public snapshots.

Foreign keys use `RESTRICT`. Stable identities and published history have no DELETE
workflow. SQLite triggers prevent deletion of immutable rows and content mutation after
creation.

## Canonicalization and privacy flow

1. Decode strict JSON with unknown and duplicate-key rejection.
2. Normalize each fixed shape field and reject prohibited identifier syntax.
3. Validate product labels, version facts, hostname templates, and source citations;
   treat this as accidental-leak defense in depth, not an adversarial text-channel proof.
4. Marshal the fixed canonical struct and compute the domain-separated SHA-256.
5. Persist the shape once; reference it from an immutable draft revision.
6. On publish, rebuild the full public snapshot from typed rows inside the transaction,
   run a snapshot-wide privacy scan, store immutable bytes/hash, advance the corpus
   revision, and append audit events.

The authenticated human curator and the dashboard's exact proposed-release preview are
part of this privacy boundary. No untrusted observation or reporter input is accepted.

## API contracts

Public listener:

- `GET /api/v1/device-corpus/manifest`
- `GET /api/v1/device-corpus/snapshot`

Management listener:

- `GET|POST /api/v1/admin/device-corpus/profiles`
- `GET /api/v1/admin/device-corpus/profiles/{profile_id}/preview`
- `GET|PUT /api/v1/admin/device-corpus/profiles/{profile_id}`
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/variants`
- `PUT /api/v1/admin/device-corpus/variants/{variant_id}`
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/publish`
- `POST /api/v1/admin/device-corpus/profiles/{profile_id}/retire`
- `POST /api/v1/admin/device-corpus/variants/{variant_id}/discard-draft`
- `POST /api/v1/admin/device-corpus/variants/{variant_id}/withdraw`
- `GET /api/v1/admin/device-corpus/audit`
- `GET /api/v1/admin/device-corpus/releases`
- `GET /api/v1/admin/device-corpus/releases/{corpus_revision}`

Mutations require `If-Match` once an entity exists and an operation-scoped
`reason_code`: profile creation uses `new_profile`, while profile-label revision uses
`label_correction`; discarding a pending variant correction uses `signal_correction`.
There are no DELETE endpoints. The dashboard displays a preview of the exact public
shape and uses text-only DOM rendering for corpus-provided values.

## Deployment

- `THREAT_NETWORK_ADMIN_ENABLED=true`
- `THREAT_NETWORK_ADMIN_ADDR=127.0.0.1:9091` for a native service
- `THREAT_NETWORK_ADMIN_TOKEN_FILE=/run/secrets/threat-network-admin-token`
- `THREAT_NETWORK_ADMIN_ALLOW_NON_LOOPBACK=false`
- `MON_UPSTREAM=http://127.0.0.1:9090`
- `MON_ADMIN_UPSTREAM=http://127.0.0.1:9091`
- `MON_ADMIN_TOKEN_FILE=/run/secrets/threat-network-admin-token`

Cloudflared continues to target only public port 9090. Tailscale Serve continues to
publish only the dashboard shim. The operations branch is deployed directly and is not
merged into product `main`.

## SNR and trust impact

This feature does not change detection or scoring. Published corpus labels are reference
data only. Future consumers must retain ambiguity when one shape maps to several profiles
and must never override a local operator correction.

## Constitution check

- Planning artifacts precede implementation.
- No sensor, active scan, telemetry, or community-ingest expansion.
- Additive SQLite migration and backward-safe older-binary rollback.
- Privacy enforcement is structural and covered by adversarial fixtures.
- Operations UI remains off the product mainline and public Cloudflare surface.
