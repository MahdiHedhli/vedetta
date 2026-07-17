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

The central `threat-network-data` database also contains the curated device corpus,
its append-only audit trail, and every immutable published corpus release. Backing up
that one SQLite file therefore preserves both the community feed and corpus history.

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

For the central Threat Network database (community feed **and** curated corpus),
the runtime image also ships `sqlite3` so the same online-backup guarantee is
available without stopping ingestion. The service reads the database location
from `THREAT_NETWORK_DB` (default `/data/threat-network.db`). Discover the value
from the running container so these commands back up the configured database,
including when an operator uses a custom path:

```sh
ts=$(date +%Y%m%d-%H%M%S)
threat_db=$(
  docker compose --profile community exec -T threat-network \
    sh -eu -c 'printf "%s" "${THREAT_NETWORK_DB:-/data/threat-network.db}"'
)
threat_backup_in_container="/tmp/threat-network-backup-$ts.db"
docker compose --profile community exec threat-network \
  sqlite3 "$threat_db" ".backup '$threat_backup_in_container'"
docker compose --profile community cp \
  "threat-network:$threat_backup_in_container" "./threat-network-backup-$ts.db"
docker compose --profile community exec threat-network \
  rm -f "$threat_backup_in_container"
```

If you override `THREAT_NETWORK_DB`, its parent directory must be on the
persistent `threat-network-data` mount (or another persistent mount). A path in
the container's writable layer will not survive container recreation.

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
# Poll readiness — /readyz answers 200 only once migrations applied + DB intact
# (503 otherwise); a single-shot curl right after `up -d` races cold startup.
for i in $(seq 1 60); do
  curl -fsS --connect-timeout 1 --max-time 5 "http://localhost:${VED_BACKEND_PORT}/readyz" && break
  [ "$i" -eq 60 ] && { echo "backend never became ready — check docker logs vedetta-backend"; exit 1; }
  sleep 1
done
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

### Restore the community feed and curated corpus

Restore the full Threat Network database, not an individual corpus table or
release row. The first procedure is a same-version data recovery: stop the writer,
retain a safety copy, replace the file, and resume the unchanged container.
Derive `THREAT_NETWORK_DB` from the Compose configuration with a no-dependency,
shell-only one-off container. This also works when startup validation has already
put the service into a restart loop:

```sh
threat_db=$(
  docker compose --profile community run --rm --no-deps -T --entrypoint sh \
    threat-network \
    -eu -c 'printf "%s" "${THREAT_NETWORK_DB:-/data/threat-network.db}"'
)
docker compose --profile community stop threat-network
docker compose --profile community cp \
  "threat-network:$threat_db" ./threat-network-before-restore.db
docker compose --profile community cp \
  ./threat-network-backup-<ts>.db "threat-network:$threat_db"
docker compose --profile community run --rm --no-deps --entrypoint sh \
  threat-network -eu -c '
    db=${THREAT_NETWORK_DB:-/data/threat-network.db}
    rm -f "${db}-wal" "${db}-shm"
  '
docker compose --profile community start threat-network
docker compose --profile community logs --tail=100 threat-network
curl -fsS http://127.0.0.1:9090/api/v1/status
curl -fsS http://127.0.0.1:9090/api/v1/device-corpus/manifest
```

Startup revalidates the current immutable snapshot against its stored SHA-256,
schema, revision, timestamp, and counts. A mismatch prevents the listener from
starting, so do not ignore a validation failure.

For rollback across a Threat Network schema migration, do **not** use `start` on
the upgraded container. After replacing the full database as above, check out the
release that created the backup (or pin its exact image), then recreate the service:

```sh
git checkout <matching-release-tag>
docker compose --profile community up -d --no-deps --build --force-recreate threat-network
docker compose --profile community logs --tail=100 threat-network
curl -fsS http://127.0.0.1:9090/api/v1/device-corpus/manifest
```

---

## 3. Update safely

### Recommended: `scripts/upgrade.sh` (backup → migrate → verify → auto-rollback)

This is the one-command safe path and it does everything below for you. It
**snapshots the DB before the database can change**: with a healthy backend
the old stack keeps serving through checkout and build, and the online
`sqlite3 .backup` is taken **seconds before the container swap** — so a
rollback discards almost no ingested data; with a down/crash-looping backend
the stack is stopped and a cold tarball is taken **first**. It then restarts
and verifies the result with `PRAGMA foreign_key_check` and
`PRAGMA integrity_check`. On **any** failure it exits non-zero with the
captured backend log and *attempts* rollback: if the upgraded stack already
ran (a migration that crash-loops the backend, a corrupt graph), it restores
the pre-upgrade snapshot into the volume and relaunches the previous version;
if the failure came earlier (e.g. a build error), the database was never
touched — the old stack just keeps running.

Rollback is attempted, **not unconditionally completed**: when finishing it
would itself risk the data, the script **halts with the stack stopped**, the
snapshot intact, and explicit instructions instead. That happens when
`docker compose down` fails (containers may still hold the volume), when the
snapshot cannot be restored into the volume, when the previous version cannot
be checked out or rebuilt, and in in-place mode with no known-good ref (next
paragraph). After a halt, recover manually with sections 2 and 4.

```sh
git fetch --tags
./scripts/upgrade.sh v0.1.0-beta.1      # upgrade to a pinned tag/commit
# ./scripts/upgrade.sh --from <good-ref> # rebuild current checkout in place
# ./scripts/upgrade.sh -y v0.1.0-beta.1  # non-interactive (e.g. over SSH)
```

> **In-place rebuilds need `--from` for full auto-rollback.** Bare
> `./scripts/upgrade.sh` (no target ref) rebuilds the checkout you are on — if
> that version fails *after startup*, the failing code **is** the current
> checkout, so relaunching it would just re-run the failing migration.
> The script restores the DB snapshot and then **halts with the stack
> stopped**. Pass `--from <known-good-ref>` to give it somewhere safe to
> return to.

It snapshots the Core DB, a copy of `.env`, and best-effort `telemetry-state`
into `../vedetta-backups/upgrade-<timestamp>/` — a sibling of the repository,
**deliberately outside it**, so snapshots can never enter a Docker build context
or be affected by `git checkout` (override with `VEDETTA_BACKUP_DIR`). It holds
your DB and API tokens — keep it private. Keep each snapshot until the new
version has proven itself in daily use.

The script upgrades **Core services only** (the profile-less set: backend,
frontend, collector, telemetry). Community-profile services such as a locally
run `threat-network` are never rebuilt, restarted, or rolled back by it — they
keep their own data and runbook (docs/threat-network-operations.md). In
particular, `upgrade.sh` does not tar the live `threat-network-data` volume;
use the consistent online SQLite backup in section 1 for that database.

> **Crash-looping-backend caveat.** Migrations run on boot and are fail-closed:
> a failure aborts startup (`log.Fatalf`). When the backend is already down or
> crash-looping, the online `sqlite3 .backup` (Option A below) is **not**
> available — nothing is listening to `exec` into. In that state `upgrade.sh`
> automatically falls back to the **cold volume tarball** (Option B): it stops
> the stack and tars the `vedetta-data` volume directly. This is the path that
> works mid-incident, so reach for the cold tarball (not the online backup) when
> recovering a Core that will not start.

### Manual alternative

If you upgrade by hand, prefer a **tagged release** over mutable `main` and
always back up first:

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
# Poll readiness — /readyz answers 200 only once migrations applied + DB intact
# (503 otherwise); a single-shot curl right after `up -d` races cold startup.
for i in $(seq 1 60); do
  curl -fsS --connect-timeout 1 --max-time 5 "http://localhost:${VED_BACKEND_PORT}/readyz" && break
  [ "$i" -eq 60 ] && { echo "backend never became ready — check docker logs vedetta-backend"; exit 1; }
  sleep 1
done
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

Watch `docker compose logs -f backend` on first start after an update — schema
migrations run there.

> `scripts/update-core.sh` / `scripts/update-all.sh` rebuild in place and do
> **not** snapshot the DB. On a build failure they now stop rather than start
> stale images against a possibly-migrated schema; for a populated Core, prefer
> `scripts/upgrade.sh`.

---

## 4. Roll back

> `scripts/upgrade.sh` performs this rollback automatically when an upgrade it
> ran fails verification. The steps below are for a **manual** recovery — when
> you upgraded some other way, when you want to roll back later, or when an
> automatic rollback **halted** (it deliberately stops, stack down and snapshot
> intact, rather than restore over live containers, relaunch a failing
> checkout, or continue past a failed restore — the script says exactly why).

If an update misbehaves, stop the upgraded Core before restoring. For any release
that ran a database migration, including migrations 025–030 (asset findings,
retained sensor identities, and temporal ARP evidence), restore the pre-update
database together with the previous image.
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
# Poll readiness — /readyz answers 200 only once migrations applied + DB intact
# (503 otherwise). A release that PREDATES /readyz serves 404 for it; for those,
# fall back to /healthz so a successful rollback isn't misreported as a failure.
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 5 "http://localhost:${VED_BACKEND_PORT}/readyz")
  [ "$code" = "200" ] && break
  [ "$code" = "404" ] && curl -fsS --connect-timeout 1 --max-time 5 "http://localhost:${VED_BACKEND_PORT}/healthz" > /dev/null && break
  [ "$i" -eq 60 ] && { echo "backend never became ready — check docker logs vedetta-backend"; exit 1; }
  sleep 1
done
curl -fsS -H "Authorization: Bearer ${VED_TOKEN}" \
  "http://localhost:${VED_BACKEND_PORT}/api/v1/status"
unset VED_TOKEN VED_BACKEND_PORT
```

Because the pre-update backup predates the new migration, restoring it returns
both the code **and** the database to a known-good, mutually-compatible state.

> Migrations 025–030 are forward-only. Rollback across any of them requires the
> backup taken **before** updating; deleting its tables or reusing the migrated
> database with an older binary is not a supported rollback path.

The Threat Network corpus migration is likewise forward-only operationally.
Its state pointer is monotonic and must never be edited backward to "restore" a
historical release. To undo ordinary corpus content, publish a reviewed forward
correction/withdrawal. To recover the service or schema, restore the **entire**
pre-change Threat Network database (`THREAT_NETWORK_DB`, default
`/data/threat-network.db`) together with its matching binary, using the procedure
above.
