package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	sensorReportTimeRetention = 90 * 24 * time.Hour
	// Receipt-plausible raw timestamps are retained as compact, bounded epochs.
	// Seven-day rotation prevents one lifetime min/max range from swallowing NTP
	// generations; the hard cap bounds storage even under repeated clock jumps.
	sensorReportRawEpochSpan  = 7 * 24 * time.Hour
	sensorReportRawEpochLimit = 32
	sensorReportRawEpochDrift = 15 * time.Minute
	// Sensors retry retained observations after connectivity outages, so a raw
	// timestamp remains plausible for the same 90-day horizon as the durable
	// normalization and identity history that can consume it. Older values are
	// treated as broken-clock evidence instead of silently accepted at their raw
	// epoch.
	sensorReportPastSkew = sensorReportTimeRetention
	// A stable broken clock advances normally even though its epoch is wrong.
	// Nearby values reuse one durable offset; a large NTP jump starts a new epoch
	// instead of letting an unrelated year-9999 value drag a 2030 value centuries
	// backward through time.Duration saturation.
	sensorReportEpochGap  = 30 * 24 * time.Hour
	sensorReportEpochSpan = 30 * 24 * time.Hour
	// A timestamp that has become plausible only because server wall time moved
	// forward is ambiguous: it could be delayed evidence from the broken epoch,
	// or the first value after NTP corrected the sensor. Continue a durable epoch
	// only for a short, forward-moving sequence while the durable upstream anchor
	// itself is still ahead of server wall time. Fifteen minutes covers three
	// default sensor scan intervals; a wider/custom interval safely falls back to
	// the raw plausible time instead of risking a stale-clock correction.
	sensorReportEpochContinuation = 15 * time.Minute
)

const sensorReportTimeNormalizationsDDL = `
CREATE TABLE IF NOT EXISTS sensor_report_time_normalizations (
    sensor_id       TEXT NOT NULL,
    upstream_time   TEXT NOT NULL,
    normalized_time TIMESTAMP NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    PRIMARY KEY (sensor_id, upstream_time)
);
CREATE INDEX IF NOT EXISTS idx_sensor_report_time_normalizations_created
    ON sensor_report_time_normalizations(created_at);
CREATE INDEX IF NOT EXISTS idx_sensor_report_time_normalizations_sensor_created
    ON sensor_report_time_normalizations(sensor_id, created_at);

CREATE TABLE IF NOT EXISTS sensor_report_time_raw_epochs (
    epoch_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id     TEXT NOT NULL,
    raw_min       TIMESTAMP NOT NULL,
    raw_max       TIMESTAMP NOT NULL,
    last_raw      TIMESTAMP NOT NULL,
    last_receipt  TIMESTAMP NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL,
    CHECK (raw_max >= raw_min),
    CHECK (last_raw >= raw_min AND last_raw <= raw_max)
);
CREATE INDEX IF NOT EXISTS idx_sensor_report_time_raw_epochs_lookup
    ON sensor_report_time_raw_epochs(sensor_id, raw_min, raw_max);
CREATE INDEX IF NOT EXISTS idx_sensor_report_time_raw_epochs_updated
    ON sensor_report_time_raw_epochs(updated_at);
CREATE TABLE IF NOT EXISTS sensor_report_time_receipts (
    sensor_id    TEXT PRIMARY KEY,
    last_receipt TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sensor_report_time_receipts_updated
    ON sensor_report_time_receipts(updated_at);
`

func (db *DB) ensureSensorReportTimeSchema() error {
	if _, err := db.Exec(sensorReportTimeNormalizationsDDL); err != nil {
		return fmt.Errorf("ensure sensor report timestamp schema: %w", err)
	}
	return nil
}

func sensorUpstreamTimeKey(ts time.Time) string {
	return ts.UTC().Format(time.RFC3339Nano)
}

type sensorReportTimeMapping struct {
	upstream   time.Time
	normalized time.Time
	createdAt  time.Time
}

func shiftReportTime(anchor sensorReportTimeMapping, upstream time.Time) time.Time {
	if upstream.Before(anchor.upstream) {
		return anchor.normalized.Add(-anchor.upstream.Sub(upstream))
	}
	return anchor.normalized.Add(upstream.Sub(anchor.upstream))
}

// durablePlausibleEpochAnchor returns an anchor only when an unseen timestamp
// has enough evidence to be a forward continuation of an already-persisted
// broken-clock epoch. In particular, it refuses backward/equal values (the
// shape of an NTP correction), anchors that wall time has already overtaken,
// gaps larger than a few normal reports, and values whose upstream progression
// no longer tracks elapsed receipt time. That last check distinguishes a short
// delayed continuation from a partial NTP correction that still happens to be
// numerically after the old anchor. Exact persisted keys are handled before
// this function and remain stable regardless of these conservative rules.
func durablePlausibleEpochAnchor(existing []sensorReportTimeMapping, upstream, now time.Time,
	maxFutureSkew time.Duration) *sensorReportTimeMapping {
	if !upstream.After(now) {
		return nil
	}
	best := -1
	bestGap := sensorReportEpochContinuation + 1
	for i := range existing {
		candidate := existing[i]
		// A future epoch's durable anchor must still be future relative to this
		// receipt, and the sequence must advance rather than jump backward as it
		// would after the sensor corrects its clock.
		if !candidate.upstream.After(now) || !upstream.After(candidate.upstream) {
			continue
		}
		gap := upstream.Sub(candidate.upstream)
		if gap > sensorReportEpochContinuation || gap >= bestGap {
			continue
		}
		// Once a previously-future raw value becomes plausible, its ordering alone
		// cannot prove that the old offset still applies: an NTP step/slew may leave
		// the corrected value slightly after the old anchor. Compare sensor-clock
		// advancement with server receipt advancement and fail closed to the raw,
		// now-plausible time when those diverge materially.
		receiptGap := now.Sub(candidate.createdAt)
		if candidate.createdAt.IsZero() || receiptGap < 0 {
			continue
		}
		drift := receiptGap - gap
		if drift < 0 {
			drift = -drift
		}
		if drift > sensorReportEpochContinuation {
			continue
		}
		// Only mappings that demonstrably carry a future-clock correction may
		// classify an otherwise plausible unseen value. This excludes ordinary
		// exact mappings should the table gain other uses later.
		if !candidate.upstream.After(candidate.normalized.Add(maxFutureSkew)) {
			continue
		}
		best = i
		bestGap = gap
	}
	if best < 0 {
		return nil
	}
	anchor := existing[best]
	return &anchor
}

// planSensorReportTimeMappings assigns durable server times to one request's
// timestamps that require normalization. Nearby values share an offset. Distant
// unanchored epochs are placed after the preceding request-local epoch when the
// cutoff budget permits, preventing independently anchored-at-now clusters from
// reversing order. Existing durable anchors remain preferred; only an actual
// request-local inversion or the existing future cutoff can adjust a new value
// away from that offset. The rare case where a cluster cannot fit between the
// prior output and cutoff is rank-compressed into that interval: ordering and the
// future bound take precedence over an impossible request to preserve the full
// inter-event delta. Already-persisted exact mappings are never changed here.
func planSensorReportTimeMappings(upstream []time.Time, existing []sensorReportTimeMapping,
	now, cutoff time.Time) []sensorReportTimeMapping {
	if len(upstream) == 0 {
		return nil
	}
	ordered := append([]time.Time(nil), upstream...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Before(ordered[j]) })
	anchors := append([]sensorReportTimeMapping(nil), existing...)
	planned := make([]sensorReportTimeMapping, 0, len(ordered))
	var previous time.Time

	for start := 0; start < len(ordered); {
		end := start + 1
		for end < len(ordered) {
			adjacent := ordered[end].Sub(ordered[end-1])
			span := ordered[end].Sub(ordered[start])
			if adjacent > sensorReportEpochGap || span > sensorReportEpochSpan {
				break
			}
			end++
		}
		cluster := ordered[start:end]
		clusterStart, clusterEnd := cluster[0], cluster[len(cluster)-1]

		var anchor *sensorReportTimeMapping
		bestDistance := time.Duration(1<<63 - 1)
		for i := range anchors {
			candidate := anchors[i]
			distance := time.Duration(0)
			switch {
			case candidate.upstream.Before(clusterStart):
				distance = clusterStart.Sub(candidate.upstream)
			case candidate.upstream.After(clusterEnd):
				distance = candidate.upstream.Sub(clusterEnd)
			}
			if distance <= sensorReportEpochGap && distance < bestDistance {
				copy := candidate
				anchor = &copy
				bestDistance = distance
			}
		}

		mapped := make([]time.Time, len(cluster))
		if anchor == nil {
			clusterAnchor := sensorReportTimeMapping{upstream: clusterEnd, normalized: now}
			for i, ts := range cluster {
				mapped[i] = shiftReportTime(clusterAnchor, ts)
			}
		} else {
			for i, ts := range cluster {
				mapped[i] = shiftReportTime(*anchor, ts)
			}
			// A fast/broken clock must not project fresh evidence beyond the same
			// future-skew budget accepted for ordinary timestamps. Shift the whole
			// cluster together so its relative ordering remains intact.
			if latest := mapped[len(mapped)-1]; latest.After(cutoff) {
				shift := latest.Sub(cutoff)
				for i := range mapped {
					mapped[i] = mapped[i].Add(-shift)
				}
			}
		}

		if !previous.IsZero() && mapped[0].Before(previous) {
			shift := previous.Sub(mapped[0])
			if mapped[len(mapped)-1].Add(shift).After(cutoff) {
				available := cutoff.Sub(previous)
				if available < 0 {
					available = 0
				}
				if len(mapped) == 1 {
					mapped[0] = previous
				} else {
					step := available / time.Duration(len(mapped)-1)
					for i := range mapped {
						mapped[i] = previous.Add(step * time.Duration(i))
					}
					mapped[len(mapped)-1] = cutoff
				}
			} else {
				for i := range mapped {
					mapped[i] = mapped[i].Add(shift)
				}
			}
		}

		for i, ts := range cluster {
			mapping := sensorReportTimeMapping{upstream: ts, normalized: mapped[i], createdAt: now}
			planned = append(planned, mapping)
			anchors = append(anchors, mapping)
		}
		previous = mapped[len(mapped)-1]
		start = end
	}
	return planned
}

// constrainSensorReportTimePlan keeps immutable exact mappings and retained raw
// epoch endpoints as ordering pins. New planned values before, between, and after
// those pins are shifted as a group when their delta fits. If a pinned interval
// is narrower than the planned span, only the new values are rank-compressed
// inside it. Pins are inputs to this function and are never returned or mutated.
func constrainSensorReportTimePlan(planned, pins []sensorReportTimeMapping,
	floor, cutoff time.Time) ([]sensorReportTimeMapping, error) {
	if len(planned) == 0 {
		return planned, nil
	}
	pins = append([]sensorReportTimeMapping(nil), pins...)
	sort.Slice(pins, func(i, j int) bool { return pins[i].upstream.Before(pins[j].upstream) })

	adjust := func(segment []sensorReportTimeMapping, lower, upper time.Time) error {
		if len(segment) == 0 {
			return nil
		}
		if lower.After(upper) {
			return fmt.Errorf("sensor report timestamp constraints are contradictory: lower %s after upper %s", lower, upper)
		}
		first := segment[0].normalized
		last := segment[len(segment)-1].normalized
		shift := time.Duration(0)
		if first.Before(lower) {
			shift = lower.Sub(first)
		}
		if last.Add(shift).After(upper) {
			shift = upper.Sub(last)
		}
		if !first.Add(shift).Before(lower) {
			for i := range segment {
				segment[i].normalized = segment[i].normalized.Add(shift)
			}
			return nil
		}
		if len(segment) == 1 {
			segment[0].normalized = lower
			return nil
		}
		available := upper.Sub(lower)
		step := available / time.Duration(len(segment)-1)
		for i := range segment {
			segment[i].normalized = lower.Add(step * time.Duration(i))
		}
		segment[len(segment)-1].normalized = upper
		return nil
	}

	start := 0
	lower := floor
	for i := range pins {
		end := start
		for end < len(planned) && planned[end].upstream.Before(pins[i].upstream) {
			end++
		}
		if err := adjust(planned[start:end], lower, pins[i].normalized); err != nil {
			return nil, err
		}
		lower = pins[i].normalized
		if lower.Before(floor) {
			lower = floor
		}
		start = end
	}
	if err := adjust(planned[start:], lower, cutoff); err != nil {
		return nil, err
	}
	return planned, nil
}

type sensorReportRawEpoch struct {
	epochID                 int64
	rawMin, rawMax, lastRaw time.Time
	lastReceipt             time.Time
	createdAt, updatedAt    time.Time
}

func (epoch sensorReportRawEpoch) covers(ts time.Time) bool {
	return !ts.Before(epoch.rawMin) && !ts.After(epoch.rawMax)
}

func loadSensorReportRawEpochsTx(ctx context.Context, tx *sql.Tx, sensorID string) ([]sensorReportRawEpoch, error) {
	rows, err := tx.QueryContext(ctx, `SELECT epoch_id, raw_min, raw_max, last_raw, last_receipt,
		created_at, updated_at FROM sensor_report_time_raw_epochs
		WHERE sensor_id = ? ORDER BY raw_min, epoch_id`, sensorID)
	if err != nil {
		return nil, fmt.Errorf("load sensor raw timestamp epochs: %w", err)
	}
	defer rows.Close()
	var epochs []sensorReportRawEpoch
	for rows.Next() {
		var epoch sensorReportRawEpoch
		if err := rows.Scan(&epoch.epochID, &epoch.rawMin, &epoch.rawMax, &epoch.lastRaw,
			&epoch.lastReceipt, &epoch.createdAt, &epoch.updatedAt); err != nil {
			return nil, fmt.Errorf("scan sensor raw timestamp epoch: %w", err)
		}
		epoch.rawMin = epoch.rawMin.UTC()
		epoch.rawMax = epoch.rawMax.UTC()
		epoch.lastRaw = epoch.lastRaw.UTC()
		epoch.lastReceipt = epoch.lastReceipt.UTC()
		epochs = append(epochs, epoch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sensor raw timestamp epochs: %w", err)
	}
	return epochs, nil
}

func sensorReportRawPins(exact []sensorReportTimeMapping, epochs []sensorReportRawEpoch) []sensorReportTimeMapping {
	byUpstream := make(map[string]sensorReportTimeMapping, len(exact)+2*len(epochs))
	for _, epoch := range epochs {
		for _, ts := range []time.Time{epoch.rawMin, epoch.rawMax} {
			byUpstream[sensorUpstreamTimeKey(ts)] = sensorReportTimeMapping{
				upstream: ts, normalized: ts, createdAt: epoch.updatedAt,
			}
		}
	}
	// Exact normalized keys have first-classification precedence over an envelope
	// that may conservatively span across their upstream value.
	for _, mapping := range exact {
		byUpstream[sensorUpstreamTimeKey(mapping.upstream)] = mapping
	}
	pins := make([]sensorReportTimeMapping, 0, len(byUpstream))
	for _, mapping := range byUpstream {
		pins = append(pins, mapping)
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].upstream.Before(pins[j].upstream) })
	return pins
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func absReportDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

// recordSensorReportRawAcceptanceTx extends only a forward, receipt-tracking
// epoch. Backward jumps, excessive clock drift, and seven-day span rotation
// create a new epoch. The hard per-sensor cap bounds even adversarial clock
// generation churn.
func recordSensorReportRawAcceptanceTx(ctx context.Context, tx *sql.Tx, sensorID string, accepted []time.Time,
	receipt, cutoff time.Time) error {
	if len(accepted) == 0 {
		return nil
	}
	accepted = append([]time.Time(nil), accepted...)
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Before(accepted[j]) })
	for _, raw := range accepted {
		raw = raw.UTC()
		var covered int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM sensor_report_time_raw_epochs
			WHERE sensor_id = ? AND raw_min <= ? AND ? <= raw_max LIMIT 1`,
			sensorID, raw, raw).Scan(&covered); err == nil {
			continue
		} else if err != sql.ErrNoRows {
			return fmt.Errorf("check sensor raw timestamp coverage: %w", err)
		}

		var latest sensorReportRawEpoch
		err := tx.QueryRowContext(ctx, `SELECT epoch_id, raw_min, raw_max, last_raw, last_receipt,
			created_at, updated_at FROM sensor_report_time_raw_epochs
			WHERE sensor_id = ? ORDER BY updated_at DESC, epoch_id DESC LIMIT 1`, sensorID).
			Scan(&latest.epochID, &latest.rawMin, &latest.rawMax, &latest.lastRaw,
				&latest.lastReceipt, &latest.createdAt, &latest.updatedAt)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("load latest sensor raw timestamp epoch: %w", err)
		}
		canExtend := err == nil && !raw.Before(latest.lastRaw) && !receipt.Before(latest.lastReceipt)
		if canExtend {
			upstreamGap := raw.Sub(latest.lastRaw)
			receiptGap := receipt.Sub(latest.lastReceipt)
			canExtend = absReportDuration(upstreamGap-receiptGap) <= sensorReportRawEpochDrift
		}
		newMax := cutoff
		if err == nil {
			newMax = laterTime(latest.rawMax, cutoff)
			canExtend = canExtend && newMax.Sub(latest.rawMin) <= sensorReportRawEpochSpan
		}
		if canExtend {
			if _, err := tx.ExecContext(ctx, `UPDATE sensor_report_time_raw_epochs SET
				raw_max = ?, last_raw = ?, last_receipt = ?, updated_at = ?
				WHERE epoch_id = ?`, newMax, raw, receipt, receipt, latest.epochID); err != nil {
				return fmt.Errorf("extend sensor raw timestamp epoch: %w", err)
			}
			continue
		}

		initialMax := cutoff
		if spanMax := raw.Add(sensorReportRawEpochSpan); initialMax.After(spanMax) {
			initialMax = spanMax
		}
		if initialMax.Before(raw) {
			return fmt.Errorf("raw timestamp %s exceeds acceptance cutoff %s", raw, cutoff)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_report_time_raw_epochs
			(sensor_id, raw_min, raw_max, last_raw, last_receipt, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, sensorID, raw, initialMax, raw, receipt, receipt, receipt); err != nil {
			return fmt.Errorf("create sensor raw timestamp epoch: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_report_time_raw_epochs
		WHERE sensor_id = ? AND epoch_id NOT IN (
			SELECT epoch_id FROM sensor_report_time_raw_epochs
			WHERE sensor_id = ? ORDER BY updated_at DESC, epoch_id DESC LIMIT ?
		)`, sensorID, sensorID, sensorReportRawEpochLimit); err != nil {
		return fmt.Errorf("cap sensor raw timestamp epochs: %w", err)
	}
	return nil
}

func sensorReportEffectiveReceiptTx(ctx context.Context, tx *sql.Tx, sensorID string, receipt time.Time) (time.Time, error) {
	effective := receipt.UTC()
	for _, query := range []string{
		`SELECT last_receipt FROM sensor_report_time_receipts
		 WHERE sensor_id = ?`,
		`SELECT created_at FROM sensor_report_time_normalizations
		 WHERE sensor_id = ? ORDER BY created_at DESC LIMIT 1`,
		`SELECT last_receipt FROM sensor_report_time_raw_epochs
		 WHERE sensor_id = ? ORDER BY last_receipt DESC LIMIT 1`,
	} {
		var durable time.Time
		err := tx.QueryRowContext(ctx, query, sensorID).Scan(&durable)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("read sensor report receipt watermark: %w", err)
		}
		effective = laterTime(effective, durable.UTC())
	}
	return effective, nil
}

// NormalizeSensorReportTimes returns a stable server-side time for every non-zero
// upstream timestamp. All classifications are writer-serialized: a retained exact
// normalization wins first, then a retained raw epoch, so the first durable
// classification remains stable across retries and concurrent delivery. Newly
// plausible values inside the 90-day past/future-skew window remain raw unless they
// continue a known broken-clock epoch or would invert an immutable exact/raw pin.
// Implausibly old or future values are clustered into bounded sensor-clock epochs
// and anchored to a prior mapping for the authenticated sensor when possible. Raw
// epochs, exact mappings, and monotonic receipt watermarks expire after 90 days.
func (db *DB) NormalizeSensorReportTimes(ctx context.Context, sensorID string, upstream []time.Time, now time.Time, maxFutureSkew time.Duration) (map[string]time.Time, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sensorID = strings.TrimSpace(sensorID)
	if sensorID == "" {
		return nil, fmt.Errorf("sensor ID is required for report timestamp normalization")
	}
	now = now.UTC()
	unique := make(map[string]time.Time, len(upstream))
	for _, raw := range upstream {
		if raw.IsZero() {
			continue
		}
		ts := raw.UTC()
		unique[sensorUpstreamTimeKey(ts)] = ts
	}
	result := make(map[string]time.Time, len(unique))
	if len(unique) == 0 {
		return result, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin sensor report timestamp normalization: %w", err)
	}
	defer tx.Rollback()

	// Every classification, including the common raw path, passes through this
	// writer-serialization point. Whichever concurrent request classifies an
	// upstream time first creates durable exact/raw state that the next request
	// must honor.
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_report_time_normalizations WHERE 0`); err != nil {
		return nil, fmt.Errorf("serialize sensor report timestamp classification: %w", err)
	}
	effectiveNow, err := sensorReportEffectiveReceiptTx(ctx, tx, sensorID, now)
	if err != nil {
		return nil, err
	}
	floor := effectiveNow.Add(-sensorReportPastSkew)
	cutoff := effectiveNow.Add(maxFutureSkew)
	retentionCutoff := effectiveNow.Add(-sensorReportTimeRetention)
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_report_time_normalizations
		WHERE sensor_id = ? AND created_at < ?`, sensorID, retentionCutoff); err != nil {
		return nil, fmt.Errorf("expire sensor report timestamp normalizations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_report_time_raw_epochs
		WHERE sensor_id = ? AND updated_at < ?`, sensorID, retentionCutoff); err != nil {
		return nil, fmt.Errorf("expire sensor raw timestamp epochs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_report_time_receipts
		WHERE sensor_id = ? AND updated_at < ?`, sensorID, retentionCutoff); err != nil {
		return nil, fmt.Errorf("expire sensor report receipt watermarks: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_report_time_receipts
		(sensor_id, last_receipt, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(sensor_id) DO UPDATE SET
			last_receipt = CASE WHEN excluded.last_receipt > last_receipt THEN excluded.last_receipt ELSE last_receipt END,
			updated_at = CASE WHEN excluded.updated_at > updated_at THEN excluded.updated_at ELSE updated_at END`,
		sensorID, effectiveNow, effectiveNow); err != nil {
		return nil, fmt.Errorf("advance sensor report receipt watermark: %w", err)
	}

	existingByKey := make(map[string]sensorReportTimeMapping)
	var existing []sensorReportTimeMapping
	rows, err := tx.QueryContext(ctx, `SELECT upstream_time, normalized_time, created_at
		FROM sensor_report_time_normalizations WHERE sensor_id = ?`, sensorID)
	if err != nil {
		return nil, fmt.Errorf("load sensor report timestamp normalizations: %w", err)
	}
	for rows.Next() {
		var key string
		var normalized, createdAt time.Time
		if err := rows.Scan(&key, &normalized, &createdAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan sensor report timestamp normalization: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, key)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("parse stored sensor report timestamp: %w", err)
		}
		mapping := sensorReportTimeMapping{
			upstream: parsed.UTC(), normalized: normalized.UTC(), createdAt: createdAt.UTC(),
		}
		existingByKey[key] = mapping
		existing = append(existing, mapping)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate sensor report timestamp normalizations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close sensor report timestamp mappings: %w", err)
	}
	rawEpochs, err := loadSensorReportRawEpochsTx(ctx, tx, sensorID)
	if err != nil {
		return nil, err
	}

	missingNormalized := make([]time.Time, 0)
	type plausibleCandidate struct {
		upstream     time.Time
		mapped       time.Time
		continuation bool
		promoted     bool
	}
	plausible := make([]plausibleCandidate, 0)
	requestExact := make([]sensorReportTimeMapping, 0)
	for key, ts := range unique {
		if mapping, ok := existingByKey[key]; ok {
			result[key] = mapping.normalized
			requestExact = append(requestExact, mapping)
			continue
		}
		coveredRaw := false
		for _, epoch := range rawEpochs {
			if epoch.covers(ts) {
				coveredRaw = true
				break
			}
		}
		if coveredRaw {
			result[key] = ts
		} else if !ts.Before(floor) && !ts.After(cutoff) {
			candidate := plausibleCandidate{upstream: ts, mapped: ts}
			if anchor := durablePlausibleEpochAnchor(existing, ts, effectiveNow, maxFutureSkew); anchor != nil {
				candidate.mapped = shiftReportTime(*anchor, ts)
				candidate.continuation = true
			}
			plausible = append(plausible, candidate)
		} else {
			missingNormalized = append(missingNormalized, ts)
		}
	}
	sort.Slice(plausible, func(i, j int) bool { return plausible[i].upstream.Before(plausible[j].upstream) })

	// Exact request members, retained mappings that were receipt-plausible when
	// first classified, and raw-envelope endpoints are immutable ordering pins.
	// Including plausible mappings omitted from this request preserves ordering
	// across separate deliveries. Deliberately exclude omitted mappings whose raw
	// clock was already implausible at creation: a later plausible timestamp that
	// moves backward across one is an NTP correction and must remain raw rather
	// than being dragged into the stale clock epoch.
	retainedExact := append([]sensorReportTimeMapping(nil), requestExact...)
	for _, mapping := range existing {
		if mapping.createdAt.IsZero() ||
			mapping.upstream.Before(mapping.createdAt.Add(-sensorReportPastSkew)) ||
			mapping.upstream.After(mapping.createdAt.Add(maxFutureSkew)) {
			continue
		}
		retainedExact = append(retainedExact, mapping)
	}
	pins := sensorReportRawPins(retainedExact, rawEpochs)
	normalizedUpstream := append([]time.Time(nil), missingNormalized...)
	var planned []sensorReportTimeMapping
	for {
		planned = planSensorReportTimeMappings(normalizedUpstream, existing, effectiveNow, cutoff)
		planned, err = constrainSensorReportTimePlan(planned, pins, floor, cutoff)
		if err != nil {
			return nil, err
		}
		spine := make([]sensorReportTimeMapping, 0, len(pins)+len(planned))
		spine = append(spine, pins...)
		spine = append(spine, planned...)
		sort.Slice(spine, func(i, j int) bool { return spine[i].upstream.Before(spine[j].upstream) })
		promotedAny := false
		for i := range plausible {
			if plausible[i].promoted {
				continue
			}
			var lower, upper time.Time
			for j := range spine {
				switch {
				case spine[j].upstream.Before(plausible[i].upstream):
					lower = spine[j].normalized
				case spine[j].upstream.After(plausible[i].upstream):
					upper = spine[j].normalized
				}
				if !upper.IsZero() {
					break
				}
			}
			if (!lower.IsZero() && plausible[i].mapped.Before(lower)) ||
				(!upper.IsZero() && plausible[i].mapped.After(upper)) {
				plausible[i].promoted = true
				normalizedUpstream = append(normalizedUpstream, plausible[i].upstream)
				promotedAny = true
			}
		}
		if !promotedAny {
			break
		}
	}

	// Persist positively classified continuations and collect new raw acceptance
	// for one compact epoch update before commit.
	acceptedRaw := make([]time.Time, 0, len(plausible))
	for _, candidate := range plausible {
		if candidate.promoted {
			continue
		}
		key := sensorUpstreamTimeKey(candidate.upstream)
		if !candidate.continuation {
			result[key] = candidate.mapped
			acceptedRaw = append(acceptedRaw, candidate.upstream)
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sensor_report_time_normalizations
			(sensor_id, upstream_time, normalized_time, created_at) VALUES (?, ?, ?, ?)`,
			sensorID, key, candidate.mapped, effectiveNow); err != nil {
			return nil, fmt.Errorf("persist plausible sensor-clock continuation: %w", err)
		}
		var normalized time.Time
		if err := tx.QueryRowContext(ctx, `SELECT normalized_time FROM sensor_report_time_normalizations
			WHERE sensor_id = ? AND upstream_time = ?`, sensorID, key).Scan(&normalized); err != nil {
			return nil, fmt.Errorf("read plausible sensor-clock continuation: %w", err)
		}
		result[key] = normalized.UTC()
	}
	if err := recordSensorReportRawAcceptanceTx(ctx, tx, sensorID, acceptedRaw, effectiveNow, cutoff); err != nil {
		return nil, err
	}

	for _, mapping := range planned {
		key := sensorUpstreamTimeKey(mapping.upstream)
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sensor_report_time_normalizations
			(sensor_id, upstream_time, normalized_time, created_at) VALUES (?, ?, ?, ?)`,
			sensorID, key, mapping.normalized, effectiveNow); err != nil {
			return nil, fmt.Errorf("persist sensor report timestamp normalization: %w", err)
		}
		var normalized time.Time
		if err := tx.QueryRowContext(ctx, `SELECT normalized_time FROM sensor_report_time_normalizations
			WHERE sensor_id = ? AND upstream_time = ?`, sensorID, key).Scan(&normalized); err != nil {
			return nil, fmt.Errorf("read sensor report timestamp normalization: %w", err)
		}
		result[key] = normalized.UTC()
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit sensor report timestamp normalization: %w", err)
	}
	return result, nil
}
