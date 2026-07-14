# Tasks: Curated Device Fingerprint Corpus

## 1. Storage and canonical contract

- [x] Add additive threat-network migration and upgrade/idempotency tests.
- [x] Implement fixed `CanonicalShapeV1`, normalization, domain-separated hash, and
      strict product/version/source validators.
- [x] Implement immutable profile/variant revision persistence, version facts,
      provenance, append-only audit, optimistic concurrency, and releases.
- [x] Add golden canonical vectors and privacy/leak fixtures.

## 2. Public and management APIs

- [x] Add manifest/snapshot GET routes with deterministic ETag/304 behavior.
- [x] Add separate loopback management handler and token-file authentication.
- [x] Add strict CRUD/publish/retire/withdraw/audit/release routes.
- [x] Verify public listener returns 404 for every admin route and existing feed/ingest
      contracts are unchanged.

## 3. Operations dashboard

- [x] Port only the existing dashboard's three web files onto the current-main branch.
- [x] Preserve the Monitor view and add Device Corpus and Audit views.
- [x] Add typed create/edit/variant/version/source forms, privacy warnings, public
      preview, publish/withdraw/retire actions, and revision timelines.
- [x] Harden the dual-upstream proxy, server-side bearer injection, CSRF, headers,
      path/method/body allowlists, and upstream error handling.
- [x] Render all dynamic corpus strings as text and test XSS fixtures.

## 4. Documentation and verification

- [x] Document schema, privacy boundary, backup/rollback, token creation, standalone
      branch deployment, and future community-sharing boundary.
- [x] Run Go build/vet/test/race, file-backed migration tests, Python proxy tests,
      privacy reverse tests, dashboard smoke tests, and environment-data gates.
- [x] Independently adversarially review admin isolation, token leakage, canonical
      ambiguity, draft exclusion, concurrency, and immutable release rollback.
- [x] Push the standalone operations branch. Do not merge it into `main`.
