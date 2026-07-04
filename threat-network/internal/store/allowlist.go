package store

import (
	"bufio"
	"bytes"
	"embed"
	"strings"
)

//go:embed data/allowlist.txt
var allowlistFS embed.FS

// SeedDefaultAllowlist loads the embedded static top-domains snapshot
// (data/allowlist.txt) into allowlist_domains. Returns the number of entries.
func (db *DB) SeedDefaultAllowlist() (int, error) {
	body, err := allowlistFS.ReadFile("data/allowlist.txt")
	if err != nil {
		return 0, err
	}
	return db.LoadAllowlist(bytes.NewReader(body))
}

// LoadAllowlist seeds the allowlist_domains table from a newline-delimited list
// of registered domains (eTLD+1). Lines beginning with '#' and blank lines are
// ignored. Existing rows are replaced idempotently. rankFrom assigns an
// increasing rank starting at 1 in file order.
func (db *DB) LoadAllowlist(reader interface{ Read([]byte) (int, error) }) (int, error) {
	scanner := bufio.NewScanner(reader)
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO allowlist_domains (etld_plus_one, rank, loaded_at)
        VALUES (?, ?, ?)
        ON CONFLICT(etld_plus_one) DO UPDATE SET rank = excluded.rank, loaded_at = excluded.loaded_at`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	now := nowRFC3339()
	rank := 0
	loaded := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rank++
		if _, err := stmt.Exec(strings.ToLower(line), rank, now); err != nil {
			return 0, err
		}
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return loaded, nil
}

// IsAllowlisted returns true if the given eTLD+1 is on the allowlist.
func (db *DB) IsAllowlisted(etldPlusOne string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM allowlist_domains WHERE etld_plus_one = ?`,
		strings.ToLower(etldPlusOne)).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
