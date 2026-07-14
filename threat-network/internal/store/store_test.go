package store

import (
	"strings"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationsApplyAndIdempotent(t *testing.T) {
	db := newTestDB(t)

	tables := []string{"schema_migrations", "reporters", "nonces", "ingest_receipts",
		"signals", "signal_aggregates", "feed_items", "reporter_counters", "allowlist_domains"}
	for _, tbl := range tables {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %s: %v", tbl, err)
		}
	}

	// Re-running migrate is a no-op.
	if err := db.migrate(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			want++
		}
	}
	if count != want {
		t.Fatalf("expected %d migrations recorded, got %d", want, count)
	}
	indexRows, err := db.Query(`PRAGMA index_info('idx_device_corpus_version_facts_source')`)
	if err != nil {
		t.Fatal(err)
	}
	var indexColumns []string
	for indexRows.Next() {
		var sequence, columnID int
		var column string
		if err = indexRows.Scan(&sequence, &columnID, &column); err != nil {
			indexRows.Close()
			t.Fatal(err)
		}
		indexColumns = append(indexColumns, column)
	}
	if err = indexRows.Err(); err != nil {
		indexRows.Close()
		t.Fatal(err)
	}
	if err = indexRows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(indexColumns) != 1 || indexColumns[0] != "source_id" {
		t.Fatalf("version-fact source index columns = %v, want [source_id]", indexColumns)
	}
}

func TestReporterLifecycle(t *testing.T) {
	db := newTestDB(t)
	if err := db.CreateReporter("r1", "hash1", `["known_bad_domain_hit"]`, "0.1.0"); err != nil {
		t.Fatal(err)
	}
	r, err := db.GetReporter("r1")
	if err != nil {
		t.Fatal(err)
	}
	if r.SecretHash != "hash1" || r.Status != "active" {
		t.Fatalf("unexpected reporter: %+v", r)
	}
	if _, err := db.GetReporter("nope"); err != ErrReporterNotFound {
		t.Fatalf("expected ErrReporterNotFound, got %v", err)
	}
	if err := db.DenylistReporter("r1", "abuse"); err != nil {
		t.Fatal(err)
	}
	r, _ = db.GetReporter("r1")
	if r.Status != "denylisted" {
		t.Fatalf("expected denylisted, got %s", r.Status)
	}
	deny, _ := db.DenylistedReporterIDs()
	if !deny["r1"] {
		t.Fatal("expected r1 in denylist set")
	}
}

func TestNonceReplay(t *testing.T) {
	db := newTestDB(t)
	fresh, err := db.InsertNonceIfAbsent("r1", "n1")
	if err != nil || !fresh {
		t.Fatalf("expected fresh nonce, got fresh=%v err=%v", fresh, err)
	}
	fresh, err = db.InsertNonceIfAbsent("r1", "n1")
	if err != nil || fresh {
		t.Fatalf("expected replay (fresh=false), got fresh=%v err=%v", fresh, err)
	}
	// Different reporter, same nonce string → allowed.
	fresh, _ = db.InsertNonceIfAbsent("r2", "n1")
	if !fresh {
		t.Fatal("expected per-reporter nonce isolation")
	}
}

func TestSignalUpsertDedup(t *testing.T) {
	db := newTestDB(t)
	row := SignalRow{
		ReporterID: "r1", Kind: "known_bad_domain_hit", IndicatorKey: "bad.example",
		Domain: "bad.example", EtldPlusOne: "bad.example", TimeBucket: "2026-07-03T14:00:00Z",
		LocalConfidence: 0.8, LocalReasons: `["known_bad"]`, ObservationCount: 3,
		DistinctAssetCount: 2, BlockedCount: 1,
	}
	created, err := db.UpsertSignal(row)
	if err != nil || !created {
		t.Fatalf("expected created, got created=%v err=%v", created, err)
	}
	// Same key, higher confidence, more observations → merged into one row.
	row.LocalConfidence = 0.95
	row.ObservationCount = 5
	created, err = db.UpsertSignal(row)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected merge (created=false) on duplicate key")
	}
	var n int
	var conf float64
	var obs int
	db.QueryRow(`SELECT COUNT(*), MAX(local_confidence), MAX(observation_count) FROM signals`).Scan(&n, &conf, &obs)
	if n != 1 {
		t.Fatalf("expected 1 row after dedup, got %d", n)
	}
	if conf != 0.95 {
		t.Fatalf("expected max confidence 0.95, got %v", conf)
	}
	if obs != 8 {
		t.Fatalf("expected summed observations 8, got %d", obs)
	}
}

func TestCounters(t *testing.T) {
	db := newTestDB(t)
	day := "2026-07-03"
	if err := db.AddCounters("r1", day, 1, 10, 3, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCounters("r1", day, 1, 5, 1, 2); err != nil {
		t.Fatal(err)
	}
	c, _ := db.GetCounters("r1", day)
	if c.BatchesAccepted != 2 || c.SignalsAccepted != 15 || c.DistinctIndicators != 4 || c.AllowlistFlags != 2 {
		t.Fatalf("unexpected counters: %+v", c)
	}
}

func TestAllowlistLoad(t *testing.T) {
	db := newTestDB(t)
	n, err := db.LoadAllowlist(strings.NewReader("# comment\nGoogle.com\n\nexample.net\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 loaded, got %d", n)
	}
	hit, _ := db.IsAllowlisted("google.com") // case-insensitive
	if !hit {
		t.Fatal("expected google.com allowlisted")
	}
	hit, _ = db.IsAllowlisted("badhost.example")
	if hit {
		t.Fatal("did not expect badhost.example allowlisted")
	}
}

func TestSeedDefaultAllowlist(t *testing.T) {
	db := newTestDB(t)
	n, err := db.SeedDefaultAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("expected embedded allowlist to load many domains, got %d", n)
	}
	hit, _ := db.IsAllowlisted("google.com")
	if !hit {
		t.Fatal("expected google.com in default allowlist")
	}
}

func TestRetentionPurge(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)

	// Backdate rows by writing directly with old received_at/seen_at. Retention is
	// anchored on the immutable first_received_at, so set it alongside received_at.
	old := now.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)

	db.Exec(`INSERT INTO signals (reporter_id, kind, indicator_key, time_bucket, local_confidence, received_at, first_received_at)
        VALUES ('r1','known_bad_domain_hit','a.example','2026-05-01T00:00:00Z',0.9,?,?)`, old, old)
	db.Exec(`INSERT INTO signals (reporter_id, kind, indicator_key, time_bucket, local_confidence, received_at, first_received_at)
        VALUES ('r1','known_bad_domain_hit','b.example','2026-07-03T00:00:00Z',0.9,?,?)`, recent, recent)
	db.Exec(`INSERT INTO nonces (reporter_id, nonce, seen_at) VALUES ('r1','old',?)`,
		now.Add(-48*time.Hour).Format(time.RFC3339))
	db.Exec(`INSERT INTO nonces (reporter_id, nonce, seen_at) VALUES ('r1','new',?)`, recent)

	res, err := db.Purge(now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Signals != 1 {
		t.Fatalf("expected 1 signal purged, got %d", res.Signals)
	}
	if res.Nonces != 1 {
		t.Fatalf("expected 1 nonce purged, got %d", res.Nonces)
	}
	var sigCount int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&sigCount)
	if sigCount != 1 {
		t.Fatalf("expected 1 signal remaining, got %d", sigCount)
	}
}

// TestRetentionAnchoredToFirstReceived is the finding #4 regression: a re-sent
// hour-bucket signal keeps bumping received_at on merge, so anchoring retention
// to received_at let a raw row persist past 30 days indefinitely. Retention is
// anchored to the immutable first_received_at, which UpsertSignal stamps once at
// insert and never overwrites on merge. A row first seen >30d ago must be purged
// even after a recent merge bump refreshed received_at.
func TestRetentionAnchoredToFirstReceived(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)

	// A row first seen 40 days ago, but whose received_at was merge-bumped to just
	// an hour ago (simulating a re-send right before every purge window).
	firstSeen := now.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	bumped := now.Add(-1 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO signals
        (reporter_id, kind, indicator_key, time_bucket, local_confidence, received_at, first_received_at)
        VALUES ('r1','known_bad_domain_hit','stale.badzone.example','2026-05-24T00:00:00Z',0.9,?,?)`,
		bumped, firstSeen); err != nil {
		t.Fatal(err)
	}

	// Sanity: received_at is recent (would survive a received_at-anchored purge).
	var ra string
	db.QueryRow(`SELECT received_at FROM signals WHERE indicator_key='stale.badzone.example'`).Scan(&ra)
	if ra != bumped {
		t.Fatalf("precondition: received_at should be the bumped-recent value, got %s", ra)
	}

	// Purge at now-30d: anchored on first_received_at (40d old) → must delete.
	n, err := db.PurgeSignals(now.Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("row first seen >30d ago must purge despite a recent received_at bump, purged %d", n)
	}
	var remaining int
	db.QueryRow(`SELECT COUNT(*) FROM signals`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("stale row must be gone, %d remain", remaining)
	}
}

// TestUpsertSignalPreservesFirstReceived verifies the anchor is immutable across
// a merge: UpsertSignal must not overwrite first_received_at when it merges a
// re-sent (reporter_id, kind, indicator_key, time_bucket) row.
func TestUpsertSignalPreservesFirstReceived(t *testing.T) {
	db := newTestDB(t)

	row := SignalRow{
		ReporterID: "r1", Kind: "known_bad_domain_hit", IndicatorKey: "anchor.badzone.example",
		Domain: "anchor.badzone.example", EtldPlusOne: "badzone.example",
		TimeBucket: "2026-07-03T14:00:00Z", LocalConfidence: 0.9,
		LocalReasons: `["known_bad"]`, ObservationCount: 1, DistinctAssetCount: 1,
	}
	if _, err := db.UpsertSignal(row); err != nil {
		t.Fatal(err)
	}
	var firstAfterInsert, recvAfterInsert string
	db.QueryRow(`SELECT first_received_at, received_at FROM signals WHERE indicator_key='anchor.badzone.example'`).
		Scan(&firstAfterInsert, &recvAfterInsert)
	if firstAfterInsert == "" {
		t.Fatal("first_received_at must be stamped on insert")
	}

	// Force a later wall-clock so a merge bump is observable, then re-send.
	time.Sleep(1100 * time.Millisecond)
	if _, err := db.UpsertSignal(row); err != nil {
		t.Fatal(err)
	}
	var firstAfterMerge, recvAfterMerge string
	db.QueryRow(`SELECT first_received_at, received_at FROM signals WHERE indicator_key='anchor.badzone.example'`).
		Scan(&firstAfterMerge, &recvAfterMerge)
	if firstAfterMerge != firstAfterInsert {
		t.Fatalf("first_received_at must be immutable across merge: %s → %s", firstAfterInsert, firstAfterMerge)
	}
	if recvAfterMerge == recvAfterInsert {
		t.Fatal("received_at should be bumped on merge (it is the last-merged timestamp)")
	}
}

func TestReceiptIdempotent(t *testing.T) {
	db := newTestDB(t)
	r := Receipt{BatchID: "b1", ReporterID: "r1", SignalCount: 3, AcceptedCount: 3, RejectedCount: 0}
	ok, err := db.InsertReceipt(r)
	if err != nil || !ok {
		t.Fatalf("expected fresh receipt, got ok=%v err=%v", ok, err)
	}
	ok, _ = db.InsertReceipt(r)
	if ok {
		t.Fatal("expected duplicate receipt insert to report ok=false")
	}
	got, found, _ := db.GetReceipt("r1", "b1")
	if !found || got.AcceptedCount != 3 {
		t.Fatalf("unexpected receipt: %+v found=%v", got, found)
	}
}
