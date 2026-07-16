package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNormalizeSensorReportTimesHonorsCanceledContext(t *testing.T) {
	db := newCorrelationDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := db.NormalizeSensorReportTimes(ctx, "sensor-canceled", []time.Time{
		time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
	}, time.Date(2026, 7, 15, 12, 1, 0, 0, time.UTC), time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled normalization error = %v, want context.Canceled", err)
	}

	var rows int
	if err := db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM sensor_report_time_receipts WHERE sensor_id = 'sensor-canceled') +
		(SELECT COUNT(*) FROM sensor_report_time_raw_epochs WHERE sensor_id = 'sensor-canceled') +
		(SELECT COUNT(*) FROM sensor_report_time_normalizations WHERE sensor_id = 'sensor-canceled')`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("canceled normalization persisted %d state row(s)", rows)
	}
}

func TestNormalizeSensorReportTimesReplayStableAndMixedEpochSafe(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	current := now.Add(-10 * time.Minute)
	extremeOld := time.Date(9999, 12, 31, 23, 57, 0, 0, time.UTC)
	extremeNew := extremeOld.Add(time.Minute)

	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-time-test", []time.Time{
		current, extremeOld, extremeNew,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := first[sensorUpstreamTimeKey(current)]; !got.Equal(current) {
		t.Fatalf("plausible post-NTP timestamp shifted: got %s want %s", got, current)
	}
	oldNormalized := first[sensorUpstreamTimeKey(extremeOld)]
	newNormalized := first[sensorUpstreamTimeKey(extremeNew)]
	if delta := newNormalized.Sub(oldNormalized); delta != time.Minute {
		t.Fatalf("future cohort order lost: old=%s new=%s delta=%s", oldNormalized, newNormalized, delta)
	}
	if newNormalized.After(now.Add(time.Hour)) {
		t.Fatalf("extreme timestamp remained future-dated: %s", newNormalized)
	}

	replayedAt := now.Add(20 * time.Minute)
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-time-test", []time.Time{
		extremeOld, extremeNew,
	}, replayedAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := second[sensorUpstreamTimeKey(extremeOld)]; !got.Equal(oldNormalized) {
		t.Fatalf("old replay normalization changed: got %s want %s", got, oldNormalized)
	}
	if got := second[sensorUpstreamTimeKey(extremeNew)]; !got.Equal(newNormalized) {
		t.Fatalf("new replay normalization changed: got %s want %s", got, newNormalized)
	}
}

func TestNormalizeSensorReportTimesScopesMappingByAuthenticatedSensor(t *testing.T) {
	db := newCorrelationDB(t)
	upstream := time.Date(9999, 12, 31, 23, 58, 0, 0, time.UTC)
	firstNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	secondNow := firstNow.Add(time.Hour)

	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-a", []time.Time{upstream}, firstNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-b", []time.Time{upstream}, secondNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := sensorUpstreamTimeKey(upstream)
	if !first[key].Equal(firstNow) || !second[key].Equal(secondNow) {
		t.Fatalf("sensor-scoped mappings = %s/%s, want %s/%s", first[key], second[key], firstNow, secondNow)
	}
}

func TestNormalizeSensorReportTimesExactReplayWinsAfterSkewWindowMoves(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	upstream := now.Add(2 * time.Hour)
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-threshold", []time.Time{upstream}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := sensorUpstreamTimeKey(upstream)
	firstNormalized := first[key]
	if !firstNormalized.Equal(now) {
		t.Fatalf("first normalization = %s, want %s", firstNormalized, now)
	}

	// The exact same raw time is now inside the one-hour plausibility window.
	// Persisted replay identity must still win over returning the raw future time.
	replayedAt := now.Add(61 * time.Minute)
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-threshold", []time.Time{upstream}, replayedAt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := second[key]; !got.Equal(firstNormalized) {
		t.Fatalf("threshold-crossing replay changed: got %s want %s", got, firstNormalized)
	}
}

func TestNormalizeSensorReportTimesMixedCutoffCohortUsesOneDurableOffset(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	justInside := now.Add(59 * time.Minute)
	justOutside := now.Add(61 * time.Minute)

	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-mixed-cutoff", []time.Time{
		justOutside, justInside,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	insideNormalized := first[sensorUpstreamTimeKey(justInside)]
	outsideNormalized := first[sensorUpstreamTimeKey(justOutside)]
	if delta := outsideNormalized.Sub(insideNormalized); delta != 2*time.Minute {
		t.Fatalf("mixed-cutoff cohort lost ordering: inside=%s outside=%s delta=%s", insideNormalized, outsideNormalized, delta)
	}
	if outsideNormalized.After(now.Add(time.Hour)) {
		t.Fatalf("mixed-cutoff cohort remained implausibly future-dated: %s", outsideNormalized)
	}

	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ? AND upstream_time IN (?, ?)`, "sensor-mixed-cutoff",
		sensorUpstreamTimeKey(justInside), sensorUpstreamTimeKey(justOutside)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 2 {
		t.Fatalf("persisted mixed-cutoff mappings = %d, want 2", persisted)
	}

	replay, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-mixed-cutoff", []time.Time{
		justInside, justOutside,
	}, now.Add(3*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := replay[sensorUpstreamTimeKey(justInside)]; !got.Equal(insideNormalized) {
		t.Fatalf("inside exact replay changed: got %s want %s", got, insideNormalized)
	}
	if got := replay[sensorUpstreamTimeKey(justOutside)]; !got.Equal(outsideNormalized) {
		t.Fatalf("outside exact replay changed: got %s want %s", got, outsideNormalized)
	}
}

func TestNormalizeSensorReportTimesWideMixedCutoffCohortCannotInvert(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	plausible := now.Add(30 * time.Minute)
	future := now.Add(80 * time.Minute)

	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-wide-mixed-cutoff", []time.Time{
		plausible, future,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	plausibleNormalized := got[sensorUpstreamTimeKey(plausible)]
	futureNormalized := got[sensorUpstreamTimeKey(future)]
	if delta := futureNormalized.Sub(plausibleNormalized); delta != 50*time.Minute {
		t.Fatalf("wide mixed-cutoff cohort inverted or lost its offset: plausible=%s future=%s delta=%s",
			plausibleNormalized, futureNormalized, delta)
	}
	if futureNormalized.After(now.Add(time.Hour)) {
		t.Fatalf("wide mixed-cutoff future remained beyond cutoff: %s", futureNormalized)
	}
	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ? AND upstream_time IN (?, ?)`, "sensor-wide-mixed-cutoff",
		sensorUpstreamTimeKey(plausible), sensorUpstreamTimeKey(future)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 2 {
		t.Fatalf("persisted wide mixed-cutoff mappings = %d, want 2", persisted)
	}
	replay, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-wide-mixed-cutoff", []time.Time{
		future, plausible,
	}, now.Add(4*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !replay[sensorUpstreamTimeKey(plausible)].Equal(plausibleNormalized) ||
		!replay[sensorUpstreamTimeKey(future)].Equal(futureNormalized) {
		t.Fatalf("wide mixed-cutoff replay changed: first=%+v replay=%+v", got, replay)
	}
}

func TestNormalizeSensorReportTimesPartialReplayDoesNotChangePriorRawPlausibleTime(t *testing.T) {
	db := newCorrelationDB(t)
	firstNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	plausible := firstNow.Add(30 * time.Minute)
	future := firstNow.Add(80 * time.Minute)
	sensorID := "sensor-partial-raw-replay"

	first, err := db.NormalizeSensorReportTimes(context.Background(), sensorID, []time.Time{plausible}, firstNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := first[sensorUpstreamTimeKey(plausible)]; !got.Equal(plausible) {
		t.Fatalf("standalone plausible timestamp = %s, want raw %s", got, plausible)
	}
	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ?`, sensorID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("ordinary standalone plausible path persisted %d mappings, want 0", persisted)
	}

	secondNow := firstNow.Add(5 * time.Minute)
	second, err := db.NormalizeSensorReportTimes(context.Background(), sensorID, []time.Time{future}, secondNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	futureNormalized := second[sensorUpstreamTimeKey(future)]
	if futureNormalized.After(secondNow.Add(time.Hour)) {
		t.Fatalf("future timestamp remained beyond cutoff: %s", futureNormalized)
	}
	var rawHigh time.Time
	if err := db.QueryRow(`SELECT raw_max FROM sensor_report_time_raw_epochs
		WHERE sensor_id = ? ORDER BY updated_at DESC LIMIT 1`, sensorID).Scan(&rawHigh); err != nil {
		t.Fatal(err)
	}
	if futureNormalized.Before(rawHigh) {
		t.Fatalf("future cohort normalized before accepted-raw high watermark: future=%s raw_max=%s",
			futureNormalized, rawHigh)
	}

	replay, err := db.NormalizeSensorReportTimes(context.Background(), sensorID, []time.Time{plausible, future}, secondNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := replay[sensorUpstreamTimeKey(plausible)]; !got.Equal(plausible) {
		t.Fatalf("partial replay changed prior raw plausible time: got %s want %s", got, plausible)
	}
	if got := replay[sensorUpstreamTimeKey(future)]; !got.Equal(futureNormalized) {
		t.Fatalf("partial replay changed exact future mapping: got %s want %s", got, futureNormalized)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ?`, sensorID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 1 {
		t.Fatalf("partial replay persisted ambiguous plausible key: mappings=%d, want only future key", persisted)
	}
}

func TestNormalizeSensorReportTimesFutureFirstPromotesUnseenPlausiblePredecessor(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	plausible := now.Add(30 * time.Minute)
	exactFuture := now.Add(80 * time.Minute)

	seed, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-exact-pin", []time.Time{exactFuture}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exactNormalized := seed[sensorUpstreamTimeKey(exactFuture)]
	if !exactNormalized.Equal(now) {
		t.Fatalf("seed exact normalization = %s, want %s", exactNormalized, now)
	}

	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-exact-pin", []time.Time{
		plausible, exactFuture,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if normalized := got[sensorUpstreamTimeKey(exactFuture)]; !normalized.Equal(exactNormalized) {
		t.Fatalf("exact pin moved: got %s want %s", normalized, exactNormalized)
	}
	plausibleNormalized := got[sensorUpstreamTimeKey(plausible)]
	if delta := exactNormalized.Sub(plausibleNormalized); delta != 50*time.Minute {
		t.Fatalf("future-first predecessor did not share exact offset: plausible=%s exact=%s delta=%s",
			plausibleNormalized, exactNormalized, delta)
	}
	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations
		WHERE sensor_id = ? AND upstream_time = ?`, "sensor-exact-pin",
		sensorUpstreamTimeKey(plausible)).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 1 {
		t.Fatalf("persisted promoted predecessor mappings = %d, want 1", persisted)
	}
}

func TestNormalizeSensorReportTimesFutureFirstPinsNewValues(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	before := now.Add(30 * time.Minute)
	exactMiddle := now.Add(80 * time.Minute)
	after := now.Add(90 * time.Minute)

	seed, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-exact-middle", []time.Time{exactMiddle}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exactNormalized := seed[sensorUpstreamTimeKey(exactMiddle)]

	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-exact-middle", []time.Time{
		after, exactMiddle, before,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	beforeNormalized := got[sensorUpstreamTimeKey(before)]
	middleNormalized := got[sensorUpstreamTimeKey(exactMiddle)]
	afterNormalized := got[sensorUpstreamTimeKey(after)]
	if !middleNormalized.Equal(exactNormalized) {
		t.Fatalf("middle exact pin moved: got %s want %s", middleNormalized, exactNormalized)
	}
	if middleNormalized.Sub(beforeNormalized) != 50*time.Minute ||
		afterNormalized.Sub(middleNormalized) != 10*time.Minute {
		t.Fatalf("future-first values did not retain exact-pin offset: before=%s middle=%s after=%s",
			beforeNormalized, middleNormalized, afterNormalized)
	}
	if afterNormalized.After(now.Add(time.Hour)) {
		t.Fatalf("new value after exact pin exceeded cutoff: %s", afterNormalized)
	}
}

func TestNormalizeSensorReportTimesSeparateRequestsRespectRetainedExactPins(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	predecessor := now.Add(30 * time.Minute)
	future := now.Add(80 * time.Minute)
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-retained-pin", []time.Time{future}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	futureNormalized := first[sensorUpstreamTimeKey(future)]
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-retained-pin", []time.Time{predecessor, future}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	predecessorNormalized := second[sensorUpstreamTimeKey(predecessor)]
	if !second[sensorUpstreamTimeKey(future)].Equal(futureNormalized) {
		t.Fatal("seed future mapping moved while creating plausible predecessor pin")
	}

	// This earlier value arrives in a separate request that omits both stored
	// keys. Returning it raw would place it after the retained, receipt-plausible
	// predecessor and permanently invert their upstream order.
	plausible := now.Add(20 * time.Minute)
	third, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-retained-pin", []time.Time{plausible}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	plausibleNormalized := third[sensorUpstreamTimeKey(plausible)]
	if plausibleNormalized.After(predecessorNormalized) {
		t.Fatalf("separate request crossed retained exact pin: plausible=%s predecessor=%s",
			plausibleNormalized, predecessorNormalized)
	}
	var persisted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_report_time_normalizations WHERE sensor_id=?`, "sensor-retained-pin").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 3 {
		t.Fatalf("persisted mappings = %d, want 3", persisted)
	}
}

func TestNormalizeSensorReportTimesDistantFutureClustersRemainMonotonic(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	near := now.Add(2 * time.Hour)
	farNew := time.Date(9999, 12, 31, 23, 59, 0, 0, time.UTC)
	farOld := farNew.Add(-time.Minute)

	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-multi-future-cluster", []time.Time{
		farNew, near, farOld,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	nearNormalized := got[sensorUpstreamTimeKey(near)]
	farOldNormalized := got[sensorUpstreamTimeKey(farOld)]
	farNewNormalized := got[sensorUpstreamTimeKey(farNew)]
	if farOldNormalized.Before(nearNormalized) || farNewNormalized.Before(farOldNormalized) {
		t.Fatalf("distant future clusters inverted: near=%s far-old=%s far-new=%s",
			nearNormalized, farOldNormalized, farNewNormalized)
	}
	if delta := farNewNormalized.Sub(farOldNormalized); delta != time.Minute {
		t.Fatalf("far future cohort delta = %s, want 1m", delta)
	}
	if farNewNormalized.After(now.Add(time.Hour)) {
		t.Fatalf("distant future cluster exceeded cutoff: %s", farNewNormalized)
	}
}

func TestNormalizeSensorReportTimesUnseenForwardEpochKeyWinsAfterThresholdCrossing(t *testing.T) {
	db := newCorrelationDB(t)
	firstNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	// Start just outside the skew window. A short delivery delay can move an
	// unseen follow-on key just inside it while receipt time and sensor time still
	// advance at approximately the same rate.
	anchorUpstream := firstNow.Add(70 * time.Minute)
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-unseen-threshold", []time.Time{anchorUpstream}, firstNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchorNormalized := first[sensorUpstreamTimeKey(anchorUpstream)]
	if !anchorNormalized.Equal(firstNow) {
		t.Fatalf("anchor normalization = %s, want %s", anchorNormalized, firstNow)
	}

	// Server wall time has advanced enough that this previously-unseen value is
	// now within the ordinary one-hour skew allowance. It is nevertheless a
	// short, forward continuation of a durable future-clock epoch and must retain
	// that epoch's offset.
	secondNow := firstNow.Add(16 * time.Minute)
	continuation := anchorUpstream.Add(5 * time.Minute)
	// A corrected clock jumps backward from the future anchor toward receipt
	// time. Even a small positive wall-clock skew must remain raw rather than
	// being pulled into the stale epoch.
	corrected := secondNow.Add(30 * time.Second)
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-unseen-threshold", []time.Time{
		continuation, corrected,
	}, secondNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wantContinuation := anchorNormalized.Add(5 * time.Minute)
	if got := second[sensorUpstreamTimeKey(continuation)]; !got.Equal(wantContinuation) {
		t.Fatalf("unseen threshold-crossing continuation = %s, want durable epoch value %s", got, wantContinuation)
	}
	if got := second[sensorUpstreamTimeKey(corrected)]; !got.Equal(corrected) {
		t.Fatalf("NTP-corrected timestamp was dragged into stale epoch: got %s want raw %s", got, corrected)
	}

	// The newly classified key is durable too: a later exact replay cannot move.
	third, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-unseen-threshold", []time.Time{continuation}, secondNow.Add(2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := third[sensorUpstreamTimeKey(continuation)]; !got.Equal(wantContinuation) {
		t.Fatalf("durable continuation replay changed: got %s want %s", got, wantContinuation)
	}
}

func TestNormalizeSensorReportTimesPartialNTPCorrectionDoesNotContinueStaleEpoch(t *testing.T) {
	db := newCorrelationDB(t)
	firstNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	anchorUpstream := firstNow.Add(2 * time.Hour)
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-partial-correction", []time.Time{anchorUpstream}, firstNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := first[sensorUpstreamTimeKey(anchorUpstream)]; !got.Equal(firstNow) {
		t.Fatalf("anchor normalization = %s, want %s", got, firstNow)
	}

	// Sixty-six receipt-time minutes later the sensor timestamp has advanced only
	// three minutes: NTP removed 63 minutes of the bad offset, but the corrected
	// value remains numerically after the old anchor and is now inside the allowed
	// skew window. Ordering alone would misclassify it as an old-epoch continuation.
	secondNow := firstNow.Add(66 * time.Minute)
	partiallyCorrected := anchorUpstream.Add(3 * time.Minute)
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-partial-correction", []time.Time{partiallyCorrected}, secondNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := second[sensorUpstreamTimeKey(partiallyCorrected)]; !got.Equal(partiallyCorrected) {
		t.Fatalf("partial NTP correction was dragged into stale epoch: got %s want raw %s", got, partiallyCorrected)
	}
}

func TestNormalizeSensorReportTimesDoesNotContinueOvertakenFutureEpoch(t *testing.T) {
	db := newCorrelationDB(t)
	firstNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	anchor := firstNow.Add(2 * time.Hour)
	if _, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-overtaken-epoch", []time.Time{anchor}, firstNow, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Once server wall time has overtaken the durable upstream anchor, a nearby
	// unseen value is ambiguous with a corrected/current clock. Fail closed by
	// accepting the now-plausible raw value.
	now := anchor.Add(time.Minute)
	corrected := now.Add(30 * time.Second)
	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-overtaken-epoch", []time.Time{corrected}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if normalized := got[sensorUpstreamTimeKey(corrected)]; !normalized.Equal(corrected) {
		t.Fatalf("overtaken epoch captured corrected timestamp: got %s want %s", normalized, corrected)
	}
}

func TestNormalizeSensorReportTimesOutOfOrderRequestsShareEpoch(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	older := time.Date(9999, 12, 31, 23, 57, 0, 0, time.UTC)
	newer := older.Add(time.Minute)
	first, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-out-of-order", []time.Time{newer}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-out-of-order", []time.Time{older}, now.Add(10*time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newNormalized := first[sensorUpstreamTimeKey(newer)]
	oldNormalized := second[sensorUpstreamTimeKey(older)]
	if delta := newNormalized.Sub(oldNormalized); delta != time.Minute {
		t.Fatalf("out-of-order requests lost upstream ordering: old=%s new=%s delta=%s", oldNormalized, newNormalized, delta)
	}
}

func TestNormalizeSensorReportTimesSeparatesDistantFutureEpochs(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	near := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	far := time.Date(9999, 12, 31, 23, 59, 0, 0, time.UTC)
	got, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-mixed-epochs", []time.Time{near, far}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, upstream := range []time.Time{near, far} {
		normalized := got[sensorUpstreamTimeKey(upstream)]
		if normalized.Before(now.Add(-time.Minute)) || normalized.After(now.Add(time.Hour)) {
			t.Fatalf("distant epoch %s normalized implausibly to %s", upstream, normalized)
		}
	}
}

func TestNormalizeSensorReportTimesConcurrentNearbyValuesRemainOrdered(t *testing.T) {
	db := newCorrelationDB(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	older := time.Date(9999, 12, 31, 23, 57, 0, 0, time.UTC)
	newer := older.Add(time.Minute)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, upstream := range []time.Time{older, newer} {
		upstream := upstream
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-concurrent", []time.Time{upstream}, now, time.Hour)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err := db.NormalizeSensorReportTimes(context.Background(), "sensor-concurrent", []time.Time{older, newer}, now.Add(time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldNormalized := result[sensorUpstreamTimeKey(older)]
	newNormalized := result[sensorUpstreamTimeKey(newer)]
	if delta := newNormalized.Sub(oldNormalized); delta != time.Minute {
		t.Fatalf("concurrent epoch order = old %s new %s delta %s", oldNormalized, newNormalized, delta)
	}
}
