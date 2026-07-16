# Signed Device-DB Releases

Vedetta ships the IEEE OUI table (and, later, the fingerprint corpus) compiled into the
binary, so device identification works fully offline. This document covers the **optional,
opt-in** mechanism for delivering a *fresher* device DB between software releases: a signed
GitHub release that clients verify and apply.

The trust boundary is the **signature**, not the transport — a bundle is applied only if it
is signed by the project's key and every file's hash matches, so how it is fetched or
mirrored does not affect safety.

## Trust model

- A bundle is a set of data files + a `manifest.json` (schema version, release tag, and
  each file's SHA-256) + a detached **ed25519** signature over the manifest's canonical
  bytes (`manifest.json.sig`).
- The **private** signing key exists only as the `VEDETTA_DB_SIGNING_KEY` CI secret. The
  **public** key is compiled into the client (`trustedPublicKeyBase64`).
- The client verifies the signature and every file's size + SHA-256 **before** installing
  anything. A failed or unverifiable update leaves the last-good DB untouched.
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

Run the **release-db** workflow (Actions → *release-db* → Run workflow) with a tag like
`db-2026.07`. It:

1. bundles the current `oui.csv`, builds the manifest, and signs it with the secret (the
   key is streamed to the signer via stdin — never on disk or argv);
2. **self-verifies** the bundle, so CI never publishes something the client would reject;
3. publishes a **draft** release with `oui.csv`, `manifest.json`, and `manifest.json.sig`.

Review the draft and **publish** it by hand. Publishing makes it the `latest` release that
clients pull. The workflow refuses to overwrite an already-published release.

## Enabling updates (operator, opt-in)

The updater is **off by default** — no network calls for the device DB unless you turn it
on. Enable it with:

| Env var | Default | Meaning |
| ------- | ------- | ------- |
| `VEDETTA_DB_UPDATE_ENABLED` | *(off)* | Set to `true` to enable the opt-in updater. |
| `VEDETTA_OUI_DB_PATH` | *(unset)* | File the OUI table is read from **and** installed to. The updater installs into this file's directory; point it at e.g. `/var/lib/vedetta/db/oui.csv`. |
| `VEDETTA_DB_UPDATE_INTERVAL` | `24h` | Re-check cadence (Go duration). |
| `VEDETTA_DB_UPDATE_REPO` | official repo | `owner/repo` to pull releases from. |

When enabled, the client checks on startup and every interval, and installs a newer
published release only after full verification. When disabled (the default), the embedded
table — refreshed monthly in-repo by the `update-oui` workflow — is authoritative.

## Update notifications

Whether or not auto-update is enabled, the dashboard can surface that a newer device-DB (or
Vedetta) release exists. That notifier is read-only (a version check) and is documented
separately.
