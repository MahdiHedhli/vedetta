# Backup, Restore & Rollback

Vedetta Core keeps all of its state in a **single SQLite database** on the
`vedetta-data` Docker volume (`/data/vedetta.db` inside the container). That
database holds your devices, events, durable findings and evidence links, identity and
finding-suppression audit histories, scan targets, whitelist/suppression rules, and your
**API tokens** — so backing it up is the one thing that matters most.

> **Before any update, take a backup.** Migrations run automatically on start and
> can change the schema; a backup is your rollback path if an upgrade misbehaves.

Find your exact volume name first (Compose prefixes it with the project name):

```sh
docker volume ls | grep vedetta-data      # e.g. vedetta_vedetta-data
```

The community stack (`--profile community`) adds two more volumes worth backing
up the same way: `telemetry-state` and `threat-network-data`.

---

## 1. Back up

### Option A — online backup (no downtime, recommended)

The Core image ships the `sqlite3` CLI, so you can take a consistent snapshot
while Core is running:

```sh
ts=$(date +%Y%m%d-%H%M%S)
docker compose exec backend sqlite3 /data/vedetta.db ".backup '/data/backup-$ts.db'"
docker compose cp backend:/data/backup-$ts.db ./vedetta-backup-$ts.db
docker compose exec backend rm /data/backup-$ts.db
```

Also copy your config (it is not in the volume):

```sh
cp .env ./vedetta-env-$ts.bak    # contains deployment config; keep it private
```

### Option B — cold volume tarball (Core stopped)

```sh
ts=$(date +%Y%m%d-%H%M%S)
docker compose down
docker run --rm -v vedetta_vedetta-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/vedetta-data-$ts.tar.gz -C /data .
docker compose up -d
```

Store backups off-box. Treat them as sensitive — they contain your network
inventory and API tokens.

---

## 2. Restore

### From an online backup (Option A)

```sh
docker compose stop backend
docker compose cp ./vedetta-backup-<ts>.db backend:/data/vedetta.db
docker compose start backend
docker compose logs -f backend      # confirm it opens the DB and migrations settle
```

### From a cold tarball (Option B)

```sh
docker compose down
docker run --rm -v vedetta_vedetta-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/vedetta-data-<ts>.tar.gz -C /data'
docker compose up -d
```

Verify:

```sh
VED_TOKEN='<read-or-admin-token>'
VED_BACKEND_PORT="$(docker compose port backend 8080 | awk -F: 'END {print $NF}')"
curl -fsS "http://localhost:${VED_BACKEND_PORT}/healthz"
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

---

## 3. Update safely

The `scripts/update-*.sh` helpers pull the latest code and rebuild. For a
predictable upgrade, prefer a **tagged release** over mutable `main` and always
back up first:

```sh
# 1. Back up (section 1).
# 2. Move to a released version rather than a moving branch:
git fetch --tags
git checkout <release-tag>          # e.g. v0.1.0-beta.1
# 3. Rebuild and restart:
docker compose up -d --build
# 4. Verify health + that your data is intact:
VED_TOKEN='<read-or-admin-token>'
VED_BACKEND_PORT="$(docker compose port backend 8080 | awk -F: 'END {print $NF}')"
curl -fsS "http://localhost:${VED_BACKEND_PORT}/healthz"
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

Watch `docker compose logs -f backend` on first start after an update — schema
migrations run there.

---

## 4. Roll back

If an update misbehaves, stop the upgraded Core before restoring. For any release
that ran a database migration, including migration 025 (asset identity and
findings), restore the pre-update database together with the previous image.
Do not run the older image against the expanded database: older device-merge,
suppression, and retention code does not understand the new finding/evidence/audit
relationships.

```sh
# 1. Stop Core and return to the previous version:
docker compose stop backend
git checkout <previous-release-tag>

# 2. Restore the pre-update database using section 2.

# 3. Rebuild/start the matching previous version and verify it:
docker compose up -d --build
VED_TOKEN='<read-or-admin-token>'
VED_BACKEND_PORT="$(docker compose port backend 8080 | awk -F: 'END {print $NF}')"
curl -fsS "http://localhost:${VED_BACKEND_PORT}/healthz"
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

Because the pre-update backup predates the new migration, restoring it returns
both the code **and** the database to a known-good, mutually-compatible state.

> Migration 025 is forward-only. Rollback across it requires the backup taken
> **before** updating; deleting its tables or reusing the migrated database with
> an older binary is not a supported rollback path.
