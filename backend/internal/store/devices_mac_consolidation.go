package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// MACConsolidationReport summarizes a one-time MAC-owner consolidation run.
type MACConsolidationReport struct {
	Groups        int      `json:"groups"`         // burned-in MACs with >1 owner that were collapsed
	AbsorbedCount int      `json:"absorbed_count"` // duplicate device rows hard-deleted
	Survivors     []string `json:"survivors"`      // surviving device_id per collapsed group
	FKClean       bool     `json:"fk_clean"`       // foreign_key_check was empty after the run
}

// ConsolidateMACOwners repairs the runaway MAC-conflict device sprawl. Before the
// resolver fix, a burned-in MAC bound to >1 canonical device made UpsertDevice mint
// a fresh device on every observation, adding another owner each time — an unbounded
// loop that produced thousands of duplicate rows for a single physical device.
//
// This is the one-time cleanup of that historical corruption (the resolver fix
// prevents any NEW sprawl). For every globally-administered MAC owned by more than
// one canonical device it keeps a single deterministic survivor — oldest
// devices.first_seen, tiebroken by lowest device_id, the SAME rule the resolver
// uses so there is no post-cleanup owner flip — and HARD-DELETES the duplicate
// device rows and their children. Association-preserving foreign keys (events,
// findings, suppression rules, and audit actions) are repointed to the survivor
// first so nothing is orphaned or nulled; NO-ACTION children are deleted in FK
// dependency order; evidence deletes cascade their strength/validity children.
//
// Soft-merge is deliberately NOT used: it is a pure redirect that leaves every
// duplicate's evidence in place, so the resolver's MAC lookup would keep scanning
// and canonicalizing thousands of rows on every observation of the busiest hosts.
//
// It is conservative and idempotent: randomized/locally-administered multi-owner
// MACs are never consolidated (a randomized MAC is not a stable identity); a device
// carrying a second distinct active MAC is excluded from its group (genuinely
// distinct hardware); a second run finds no >1 groups and is a no-op. The whole run
// is one transaction gated by PRAGMA foreign_key_check — any violation rolls it back.
func (db *DB) ConsolidateMACOwners(ctx context.Context) (MACConsolidationReport, error) {
	report := MACConsolidationReport{Survivors: []string{}}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()

	// Acquire the SQLite writer lock up front so the read/compute phase below cannot
	// be invalidated by a concurrent sensor commit — a deferred->write upgrade after
	// the reads would fail with SQLITE_BUSY_SNAPSHOT (not retried by the busy
	// handler) and abort the repair. Mirrors the writer-lock-first pattern used for
	// token provisioning. Operators should still take a backup and can quiesce
	// sensors for the one-time run; the operation fails closed either way.
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET value = value WHERE 0`); err != nil {
		return report, fmt.Errorf("acquire writer lock: %w", err)
	}

	key, err := db.identityHMACKeyTx(tx)
	if err != nil {
		return report, err
	}

	// Devices carrying a second distinct active MAC are ambiguous hardware — never
	// absorb them into a group (they may be the sole owner of the other MAC).
	multiMAC := map[string]struct{}{}
	mmRows, err := tx.QueryContext(ctx, `
		SELECT device_id FROM device_identity_evidence
		WHERE evidence_type = 'mac' AND valid_until IS NULL
		GROUP BY device_id HAVING COUNT(DISTINCT value_hmac) > 1`)
	if err != nil {
		return report, fmt.Errorf("scan multi-mac devices: %w", err)
	}
	for mmRows.Next() {
		var id string
		if err := mmRows.Scan(&id); err != nil {
			mmRows.Close()
			return report, err
		}
		multiMAC[id] = struct{}{}
	}
	if err := mmRows.Close(); err != nil {
		return report, err
	}
	if err := mmRows.Err(); err != nil {
		return report, err
	}

	// Group owners by the SAME key the resolver uses — active MAC-evidence
	// value_hmac (durable/append-only), NOT the mutable devices.mac_address column —
	// so the cleanup's owner set and its oldest-first survivor exactly match the
	// resolver's collapse target. That guarantees completeness (no evidence owner is
	// left behind) and no post-cleanup owner flip.
	type owner struct {
		id        string
		mac       string
		firstSeen time.Time
	}
	byHash := map[string]map[string]owner{} // value_hmac -> device_id -> owner
	rows, err := tx.QueryContext(ctx, `
		SELECT e.device_id, e.value_hmac, COALESCE(d.mac_address, ''), d.first_seen
		FROM device_identity_evidence e
		JOIN devices d ON d.device_id = e.device_id AND d.merged_into_device_id IS NULL
		WHERE e.evidence_type = 'mac' AND e.valid_until IS NULL`)
	if err != nil {
		return report, fmt.Errorf("enumerate mac evidence owners: %w", err)
	}
	for rows.Next() {
		var id, vh, mac string
		var firstSeen time.Time
		if err := rows.Scan(&id, &vh, &mac, &firstSeen); err != nil {
			rows.Close()
			return report, err
		}
		if byHash[vh] == nil {
			byHash[vh] = map[string]owner{}
		}
		byHash[vh][id] = owner{id: id, mac: mac, firstSeen: firstSeen}
	}
	if err := rows.Close(); err != nil {
		return report, err
	}
	if err := rows.Err(); err != nil {
		return report, err
	}

	// Build the absorbed->survivor mapping.
	type pair struct{ absorbed, survivor string }
	var pairs []pair
	for vh, ownerSet := range byHash {
		if len(ownerSet) < 2 {
			continue
		}
		members := make([]owner, 0, len(ownerSet))
		for _, m := range ownerSet {
			members = append(members, m)
		}
		// Verify this value_hmac is a burned-in MAC via a member whose plaintext
		// column hashes to it; skip if none can prove it (opaque) or it is randomized.
		plaintext := ""
		for _, m := range members {
			if m.mac != "" && identityValueHMAC(key, "mac", m.mac) == vh {
				plaintext = m.mac
				break
			}
		}
		if plaintext == "" || isLocallyAdministeredMAC(plaintext) {
			continue
		}
		sort.Slice(members, func(i, j int) bool {
			if !members[i].firstSeen.Equal(members[j].firstSeen) {
				return members[i].firstSeen.Before(members[j].firstSeen)
			}
			return members[i].id < members[j].id
		})
		survivor := members[0].id // oldest first_seen == the resolver's deterministic owner
		var absorbed []string
		for _, m := range members[1:] {
			if _, skip := multiMAC[m.id]; skip {
				continue // ambiguous hardware; must keep (owns another MAC)
			}
			absorbed = append(absorbed, m.id)
		}
		if len(absorbed) == 0 {
			continue
		}
		report.Groups++
		report.Survivors = append(report.Survivors, survivor)
		for _, a := range absorbed {
			pairs = append(pairs, pair{absorbed: a, survivor: survivor})
		}
	}

	if len(pairs) == 0 {
		report.FKClean = true
		return report, tx.Commit() // natural no-op (idempotent re-run)
	}
	report.AbsorbedCount = len(pairs)

	// A temp mapping table keeps every statement set-based and free of large IN
	// parameter lists (thousands of absorbed ids).
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE _mac_consolidate(
		absorbed TEXT PRIMARY KEY, survivor TEXT NOT NULL)`); err != nil {
		return report, fmt.Errorf("create consolidation map: %w", err)
	}
	for _, p := range pairs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO _mac_consolidate(absorbed, survivor) VALUES (?, ?)`, p.absorbed, p.survivor); err != nil {
			return report, fmt.Errorf("map absorbed device: %w", err)
		}
	}

	// Ordered to satisfy immediate (foreign_keys=ON) FK enforcement: repoint the
	// association-preserving refs, drop/repoint audit actions before their evidence
	// is deleted, delete NO-ACTION children, then delete the device rows last.
	steps := []string{
		`UPDATE events SET device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = events.device_id)
			WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`UPDATE findings SET device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = findings.device_id)
			WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`UPDATE finding_suppression_rules SET device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = finding_suppression_rules.device_id)
			WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		// Audit actions bound to evidence we are about to delete cannot be repointed
		// to a surviving evidence row, so drop them; the survivor's own actions and
		// evidence-less actions are repointed to the survivor.
		`DELETE FROM device_identity_actions WHERE evidence_id IN (
			SELECT evidence_id FROM device_identity_evidence WHERE device_id IN (SELECT absorbed FROM _mac_consolidate))`,
		`UPDATE device_identity_actions SET source_device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = source_device_id)
			WHERE source_device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`UPDATE device_identity_actions SET target_device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = target_device_id)
			WHERE target_device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		// Self-referential redirect safety (a device merged into an absorbed one).
		`UPDATE devices SET merged_into_device_id = (SELECT survivor FROM _mac_consolidate WHERE absorbed = devices.merged_into_device_id)
			WHERE merged_into_device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		// NO-ACTION children of the absorbed devices; evidence delete cascades its
		// strength/validity children.
		`DELETE FROM device_identities WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`DELETE FROM device_signals WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`DELETE FROM device_networks WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`DELETE FROM device_address_history WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`DELETE FROM device_identity_evidence WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
		`DELETE FROM devices WHERE device_id IN (SELECT absorbed FROM _mac_consolidate)`,
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return report, fmt.Errorf("consolidation step failed: %w", err)
		}
	}

	// Referential-integrity gate before committing a destructive one-time repair.
	fkRows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return report, fmt.Errorf("foreign_key_check: %w", err)
	}
	violations := 0
	for fkRows.Next() {
		violations++
	}
	// A driver/scan error makes Next() return false early; without checking Err()
	// a truncated iteration would read as zero violations and commit destructive
	// deletes past an unverified integrity gate.
	if err := fkRows.Err(); err != nil {
		fkRows.Close()
		return report, fmt.Errorf("foreign_key_check iteration: %w", err)
	}
	fkRows.Close()
	if violations > 0 {
		return report, fmt.Errorf("consolidation left %d foreign-key violation(s); rolling back", violations)
	}
	report.FKClean = true

	marker, _ := json.Marshal(map[string]any{"groups": report.Groups, "absorbed": report.AbsorbedCount})
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES('mac_owner_consolidation_v1', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, string(marker)); err != nil {
		return report, fmt.Errorf("record consolidation marker: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE _mac_consolidate`); err != nil {
		return report, fmt.Errorf("drop consolidation map: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}
