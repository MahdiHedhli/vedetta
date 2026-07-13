// Package store owns the threat-network service-local SQLite database:
// connection setup, a sequential migration runner mirroring Core's
// schema_migrations pattern, and CRUD for the aggregate-only data model.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps the SQLite connection for the threat-network service.
type DB struct {
	*sql.DB
	corpusCacheMu  sync.RWMutex
	corpusLoadGate chan struct{}
	corpusCache    *corpusSnapshotCache
}

// Open opens (or creates) the service-local SQLite database, applies the
// migration chain, and returns a ready DB. dbPath "" defaults to an in-memory
// database (used by tests); production passes a file path.
func Open(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = ":memory:"
	}
	dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	sqldb, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// A single connection avoids ":memory:" per-connection database surprises
	// and keeps the single-writer service simple. SQLite is fast enough for the
	// alpha volume documented in plan.md.
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	db := &DB{DB: sqldb, corpusLoadGate: make(chan struct{}, 1)}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// migrate applies every embedded migration whose version is higher than the
// current schema_migrations high-water mark, in ascending order. Re-running is
// a no-op (idempotent), as required by the constitution.
func (db *DB) migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		// filename form: NNN_description.sql
		prefix := name
		if i := strings.IndexByte(name, '_'); i >= 0 {
			prefix = name[:i]
		}
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("migration %q has no numeric prefix: %w", name, err)
		}
		migs = append(migs, mig{version: v, name: name})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.version, nowRFC3339()); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
