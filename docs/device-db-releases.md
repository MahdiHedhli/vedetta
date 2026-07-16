# Signed Device-DB Releases

Vedetta ships the IEEE OUI table (and, later, the fingerprint corpus) compiled into the
binary, so device identification works fully offline. This document covers the **optional,
opt-in** mechanism for delivering a *fresher* device DB between software releases: a signed
GitHub release that clients verify and apply.

The primary authenticity boundary is the **signature**, not transport. The client also binds
the signed manifest to the GitHub release tag and enforces monotonic `db-*` versions, so a
valid older bundle cannot be replayed as a newer release or installed as a downgrade.

## Trust model

- A bundle is a set of data files + a `manifest.json` (schema version, release tag, and
  each file's SHA-256) + a detached **ed25519** signature over the manifest's canonical
  bytes (`manifest.json.sig`).
- The **private** signing key exists only as the `VEDETTA_DB_SIGNING_KEY` CI secret. The
  **public** key is compiled into the client (`trustedPublicKeyBase64`).
- The client verifies the signature, signed release tag, and every file's size + SHA-256
  **before** installing anything. It writes a complete immutable generation and atomically
  switches one pointer, so readers never see a mixed bundle. A failed update or reload
  leaves (or restores) the last-good generation.
- With no public key configured the client **fails closed** — it never applies an
  unverifiable update.

## One-time setup (maintainer)

1. Mint the keypair:

   ```sh
   cd backend && go run ./cmd/dbkeygen
   ```

   It prints `PRIVATE_KEY=…` and `PUBLIC_KEY=…` once and stores nothing.

2. Add the **private** key as the repository Actions secret `VEDETTA_DB_SIGNING_KEY`.
   Treat it like any signing key — it is never printed by the release workflow and never
   written to disk.

3. Paste the **public** key into `trustedPublicKeyBase64` in
   [`backend/internal/dbupdate/trustkey.go`](../backend/internal/dbupdate/trustkey.go) and
   commit it. Until this is set, the updater is inert (fails closed) even when enabled.

## Cutting a release (maintainer)

Run the **release-db** workflow from the default protected branch (Actions → *release-db* →
Run workflow) with a monotonically increasing calendar tag such as `db-2026.07`,
`db-2026.07.15`, or `db-2026.07.15.1`. It:

1. bundles the current `oui.csv`, builds the manifest, and signs it with the secret (the
   key is streamed to the signer via stdin — never on disk or argv);
2. validates the same schema and size limits used by clients and self-verifies the signature;
3. creates a new **draft** release with `oui.csv`, `manifest.json`, and
   `manifest.json.sig`.

Review the draft and **publish** it by hand. Clients ignore product releases, drafts, and
prereleases and select the highest published valid `db-*` calendar version. The workflow
refuses to reuse any existing draft or published release, and asset overwrite is disabled.
If a run leaves an unusable draft, delete that draft before retrying the same tag. Never
reuse a tag after publication or decrease a DB tag.

## Enabling updates (operator, opt-in)

The updater is **off by default** — no network calls for the device DB unless you turn it
on. Enable it with:

| Env var | Default | Meaning |
| ------- | ------- | ------- |
| `VEDETTA_DB_UPDATE_ENABLED` | *(off)* | Set to `true` to enable the opt-in updater. |
| `VEDETTA_DB_UPDATE_INSTALL_DIR` | *(unset)* | Stable updater-owned generation pointer. Compose supplies `/data/device-db/current`; for a host install, use e.g. `/var/lib/vedetta/device-db/current`. |
| `VEDETTA_DB_UPDATE_INTERVAL` | `24h` | Re-check cadence (Go duration). |
| `VEDETTA_DB_UPDATE_REPO` | official repo | `owner/repo` to pull releases from. |

When enabled, the client checks on startup and every interval, and installs a newer
published release only after full verification. The directory containing `current` must be
writable by Core; `current` itself must be absent or a pointer previously created by the
updater. Core reloads the OUI index after a successful switch without requiring restart.
When disabled (the default), the embedded table—refreshed monthly in-repo by the
`update-oui` workflow—is authoritative even if a prior managed generation remains on disk.
The separate `VEDETTA_OUI_DB_PATH` variable remains available for a deliberate, manually
managed OUI override; Compose does not set it.

Dashboard notification for newer device-DB or Vedetta releases is planned separately; it is
not part of this updater or the current operator UI.
