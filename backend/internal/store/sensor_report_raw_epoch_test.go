package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func normalizedReportTime(t *testing.T, db *DB, sensorID string, upstream, receipt time.Time) time.Time {
	t.Helper()
	got, err := db.NormalizeSensorReportTimes(context.Background(), sensorID, []time.Time{upstream}, receipt, time.Hour)
	if err != nil {
		t.Fatalf("normalize %s at %s: %v", upstream, receipt, err)
	}
	return got[sensorUpstreamTimeKey(upstream)]
}

func TestSensorReportRawEpochPersistsAcrossReopenAndExpires(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "raw-epoch.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	raw := base.Add(30 * time.Minute)
	if got := normalizedReportTime(t, db, "sensor-reopen", raw, base); !got.Equal(raw) {
		t.Fatalf("first raw classification = %s, want %s", got, raw)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var receiptBefore time.Time
	if err := db.QueryRow(`SELECT last_receipt FROM sensor_report_time_receipts
		WHERE sensor_id='sensor-reopen'`).Scan(&receiptBefore); err != nil {
		t.Fatal(err)
	}
	if !receiptBefore.Equal(base) {
		t.Fatalf("reopened receipt watermark = %s, want %s", receiptBefore, base)
	}
	if got := normalizedReportTime(t, db, "sensor-reopen", raw, base.Add(time.Hour)); !got.Equal(raw) {
		t.Fatalf("raw classification changed across reopen: got %s want %s", got, raw)
	}

	// Advance relative to the accepted raw timestamp, not merely its earlier
	// receipt, so the timestamp itself is outside the 90-day plausibility bound.
	afterRetention := raw.Add(sensorReportTimeRetention + time.Minute)
	current := afterRetention
	if got := normalizedReportTime(t, db, "sensor-reopen", current, afterRetention); !got.Equal(current) {
		t.Fatalf("current post-retention timestamp = %s, want raw %s", got, current)
	}
	if got := normalizedReportTime(t, db, "sensor-reopen", raw, afterRetention); got.Equal(raw) {
		t.Fatalf("expired raw epoch still classified %s as raw", raw)
	}
	var staleEpochs, reclassified int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-reopen' AND raw_min <= ? AND raw_max >= ?`, raw, raw).Scan(&staleEpochs); err != nil {
		t.Fatal(err)
	}
	if staleEpochs != 0 {
		t.Fatalf("expired raw classification left %d covering epochs", staleEpochs)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id='sensor-reopen' AND upstream_time=?`, sensorUpstreamTimeKey(raw)).Scan(&reclassified); err != nil {
		t.Fatal(err)
	}
	if reclassified != 1 {
		t.Fatalf("expired raw timestamp produced %d durable reclassifications, want one", reclassified)
	}
	var receiptRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_receipts
		WHERE sensor_id='sensor-reopen'`).Scan(&receiptRows); err != nil {
		t.Fatal(err)
	}
	if receiptRows != 1 {
		t.Fatalf("receipt retention left %d rows, want one current watermark", receiptRows)
	}
}

func TestSensorReportRawEpochIsSensorScoped(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	plausible := now.Add(30 * time.Minute)
	future := now.Add(80 * time.Minute)
	if got := normalizedReportTime(t, db, "sensor-a", plausible, now); !got.Equal(plausible) {
		t.Fatal("sensor-a fixture did not stay raw")
	}
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-b", []time.Time{future}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exactFuture := first[sensorUpstreamTimeKey(future)]
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-b", []time.Time{plausible, future}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := second[sensorUpstreamTimeKey(plausible)]; got.Equal(plausible) ||
		exactFuture.Sub(got) != 50*time.Minute {
		t.Fatalf("sensor-a raw envelope leaked into sensor-b: plausible=%s future=%s", got, exactFuture)
	}
}

func TestSensorReportRawEpochHighFrequencyStateIsBounded(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 2880; i++ {
		now := base.Add(time.Duration(i) * 30 * time.Second)
		if got := normalizedReportTime(t, db, "sensor-high-frequency", now, now); !got.Equal(now) {
			t.Fatalf("correct-clock report %d changed: got %s want %s", i, got, now)
		}
	}
	var epochs, receipts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-high-frequency'`).Scan(&epochs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_receipts
		WHERE sensor_id='sensor-high-frequency'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if epochs != 1 || receipts != 1 {
		t.Fatalf("high-frequency raw state grew: epochs=%d receipts=%d, want 1/1", epochs, receipts)
	}
}

func TestSensorReportRawEpochRotatesBeyondSevenDaysWithoutLinearGrowth(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i <= 15*48; i++ {
		now := base.Add(time.Duration(i) * 30 * time.Minute)
		if got := normalizedReportTime(t, db, "sensor-rotation", now, now); !got.Equal(now) {
			t.Fatalf("rotation fixture changed %s to %s", now, got)
		}
	}
	rows, err := db.Query(`SELECT raw_min, raw_max FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-rotation' ORDER BY raw_min`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var from, until time.Time
		if err := rows.Scan(&from, &until); err != nil {
			t.Fatal(err)
		}
		count++
		if until.Sub(from) > sensorReportRawEpochSpan {
			t.Fatalf("raw epoch span = %s, exceeds %s", until.Sub(from), sensorReportRawEpochSpan)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 2 || count > 4 {
		t.Fatalf("15 days of correct-clock reports created %d epochs, want compact rotation", count)
	}
}

func TestSensorReportBackwardNTPStartsNewEpochWithoutRevivingOld(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	for _, delta := range []time.Duration{0, 2 * time.Hour} {
		now := base.Add(delta)
		if got := normalizedReportTime(t, db, "sensor-ntp-epochs", now, now); !got.Equal(now) {
			t.Fatal("forward raw fixture changed")
		}
	}
	var oldID int64
	var oldUpdated time.Time
	if err := db.QueryRow(`SELECT epoch_id, updated_at FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-ntp-epochs' ORDER BY epoch_id LIMIT 1`).Scan(&oldID, &oldUpdated); err != nil {
		t.Fatal(err)
	}
	receipt := base.Add(3 * time.Hour)
	partiallyCorrected := base.Add(-6 * time.Hour)
	if got := normalizedReportTime(t, db, "sensor-ntp-epochs", partiallyCorrected, receipt); !got.Equal(partiallyCorrected) {
		t.Fatalf("plausible backward NTP correction = %s, want raw %s", got, partiallyCorrected)
	}
	var epochs int
	var oldUpdatedAfter time.Time
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-ntp-epochs'`).Scan(&epochs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT updated_at FROM sensor_report_time_raw_epochs
		WHERE epoch_id=?`, oldID).Scan(&oldUpdatedAfter); err != nil {
		t.Fatal(err)
	}
	if epochs != 2 || !oldUpdatedAfter.Equal(oldUpdated) {
		t.Fatalf("backward NTP revived old epoch: epochs=%d old_updated=%s->%s",
			epochs, oldUpdated, oldUpdatedAfter)
	}
}

func TestSensorReportRawEpochRotationHasHardCap(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < sensorReportRawEpochLimit+10; i++ {
		receipt := base.Add(time.Duration(i) * (sensorReportRawEpochSpan + time.Hour))
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := recordSensorReportRawAcceptanceTx(context.Background(), tx, "sensor-cap", []time.Time{receipt},
			receipt, receipt.Add(time.Hour)); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var epochs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-cap'`).Scan(&epochs); err != nil {
		t.Fatal(err)
	}
	if epochs != sensorReportRawEpochLimit {
		t.Fatalf("raw epoch cap = %d, want %d", epochs, sensorReportRawEpochLimit)
	}
}

func TestSensorReportRawAndMixedConcurrentFirstClassificationWins(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	plausible := now.Add(30 * time.Minute)
	future := now.Add(80 * time.Minute)
	start := make(chan struct{})
	type outcome struct {
		values map[string]time.Time
		err    error
	}
	out := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, values := range [][]time.Time{{plausible}, {plausible, future}} {
		values := values
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-linearizable", values, now, time.Hour)
			out <- outcome{values: got, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(out)
	var plausibleResults []time.Time
	var concurrentFuture time.Time
	for got := range out {
		if got.err != nil {
			t.Fatal(got.err)
		}
		plausibleResults = append(plausibleResults, got.values[sensorUpstreamTimeKey(plausible)])
		if value := got.values[sensorUpstreamTimeKey(future)]; !value.IsZero() {
			concurrentFuture = value
		}
	}
	if len(plausibleResults) != 2 || !plausibleResults[0].Equal(plausibleResults[1]) {
		t.Fatalf("concurrent first classifications disagreed: %+v", plausibleResults)
	}
	replay, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-linearizable", []time.Time{plausible, future}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := replay[sensorUpstreamTimeKey(plausible)]; !got.Equal(plausibleResults[0]) {
		t.Fatalf("durable replay = %s, concurrent winner = %s", got, plausibleResults[0])
	}
	if !replay[sensorUpstreamTimeKey(future)].Equal(concurrentFuture) {
		t.Fatalf("concurrent future mapping changed on replay: first=%s replay=%s",
			concurrentFuture, replay[sensorUpstreamTimeKey(future)])
	}
	var rawHigh time.Time
	err = db.QueryRow(`SELECT raw_max FROM sensor_report_time_raw_epochs
		WHERE sensor_id='sensor-linearizable' ORDER BY updated_at DESC LIMIT 1`).Scan(&rawHigh)
	if err == nil && concurrentFuture.Before(rawHigh) {
		t.Fatalf("concurrent future result %s precedes raw pin %s", concurrentFuture, rawHigh)
	}
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
}

func TestSensorReportReceiptWatermarkDoesNotRegressOnCoveredRaw(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	first := base.Add(10 * time.Minute)
	if got := normalizedReportTime(t, db, "sensor-receipt", first, base); !got.Equal(first) {
		t.Fatal("first raw timestamp changed")
	}
	covered := base.Add(40 * time.Minute)
	if got := normalizedReportTime(t, db, "sensor-receipt", covered, base.Add(20*time.Minute)); !got.Equal(covered) {
		t.Fatal("covered raw timestamp changed")
	}
	// This request captured its receipt earlier but acquires the writer after the
	// covered path. Its effective receipt must remain at the durable high watermark.
	olderCapture := base.Add(5 * time.Minute)
	if got := normalizedReportTime(t, db, "sensor-receipt", base.Add(50*time.Minute), olderCapture); !got.Equal(base.Add(50 * time.Minute)) {
		t.Fatalf("server rollback changed covered raw classification: %s", got)
	}
	var watermark time.Time
	if err := db.QueryRow(`SELECT last_receipt FROM sensor_report_time_receipts
		WHERE sensor_id='sensor-receipt'`).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	if !watermark.Equal(base.Add(20 * time.Minute)) {
		t.Fatalf("receipt watermark regressed to %s", watermark)
	}
}

func TestNormalizeSensorReportTimesBoundsImplausiblyOldClock(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	old := now.Add(-sensorReportPastSkew - time.Minute)
	got := normalizedReportTime(t, db, "sensor-old-clock", old, now)
	floor := now.Add(-sensorReportPastSkew)
	if got.Before(floor) || got.After(now.Add(time.Hour)) || got.Equal(old) {
		t.Fatalf("implausibly old timestamp normalized outside bounds: raw=%s got=%s floor=%s", old, got, floor)
	}
	if replay := normalizedReportTime(t, db, "sensor-old-clock", old, now.Add(time.Hour)); !replay.Equal(got) {
		t.Fatalf("old-clock exact replay changed: first=%s replay=%s", got, replay)
	}
}

func TestSensorReportRetentionCleanupIsSensorScoped(t *testing.T) {
	db := newCorrelationDB(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	bRaw := base.Add(30 * time.Minute)
	bFuture := base.Add(2 * time.Hour)

	if got := normalizedReportTime(t, db, "sensor-b", bRaw, base); !got.Equal(bRaw) {
		t.Fatalf("sensor-b raw fixture = %s, want %s", got, bRaw)
	}
	bFutureFirst := normalizedReportTime(t, db, "sensor-b", bFuture, base)

	// A temporary forward Core clock jump retained for one sensor must not use
	// that sensor's watermark to expire another sensor's still-live replay state.
	aJump := base.Add(2 * sensorReportTimeRetention)
	if got := normalizedReportTime(t, db, "sensor-a", aJump, aJump); !got.Equal(aJump) {
		t.Fatalf("sensor-a jump fixture = %s, want %s", got, aJump)
	}

	for table, want := range map[string]int{
		"sensor_report_time_normalizations": 1,
		"sensor_report_time_raw_epochs":     1,
		"sensor_report_time_receipts":       1,
	} {
		var got int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE sensor_id = 'sensor-b'`).Scan(&got); err != nil {
			t.Fatalf("count sensor-b rows in %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("sensor-a cleanup changed sensor-b %s rows: got %d want %d", table, got, want)
		}
	}
	if got := normalizedReportTime(t, db, "sensor-b", bFuture, base.Add(5*time.Minute)); !got.Equal(bFutureFirst) {
		t.Fatalf("cross-sensor cleanup changed exact replay: first=%s replay=%s", bFutureFirst, got)
	}
}
