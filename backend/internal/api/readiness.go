package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/store"
)

// probeTimeout bounds the cheap per-probe queries (SELECT 1, schema head) so a wedged
// or locked database fails the probe with a 503 well within the compose healthcheck's
// own timeout, rather than hanging the probe.
const probeTimeout = 3 * time.Second

// deepCheckTTL bounds how often the expensive integrity + foreign-key scan runs. The
// readiness probe fires on the compose healthcheck interval (~30s); running a full
// PRAGMA integrity_check that often would needlessly hammer the DB, so its result is
// cached for this long and refreshed off the hot path.
const deepCheckTTL = 5 * time.Minute

// deepCheckMaxDuration caps a single background deep check so it cannot run forever on
// a huge or contended database.
const deepCheckMaxDuration = 30 * time.Second

// deepCheckResult is the cached outcome of the expensive integrity + foreign-key scan.
// A zero-value `at` means "never run yet".
type deepCheckResult struct {
	healthy bool
	reason  string
	at      time.Time
}

// ReadinessMonitor answers GET /readyz — a REAL readiness probe (unlike /healthz,
// which is pure liveness). Cheap checks run on every probe: the store must answer a
// trivial query and the recorded schema migration head must equal the binary's
// expected latest, so a behind/half-migrated/swapped DB reads NOT ready. The expensive
// integrity + foreign-key scan is cached and refreshed in the background so the probe
// stays cheap enough to run on the healthcheck interval.
type ReadinessMonitor struct {
	db *store.DB

	mu         sync.Mutex
	deep       deepCheckResult
	refreshing bool
	// firstDone is closed once the FIRST deep check has stored a result. Probes that
	// arrive before then wait on it (bounded by the probe context) instead of ever
	// reporting ready ahead of the initial integrity scan — see deepStatus.
	firstDone chan struct{}
}

// NewReadinessMonitor builds a readiness monitor over the given store.
func NewReadinessMonitor(db *store.DB) *ReadinessMonitor {
	return &ReadinessMonitor{db: db, firstDone: make(chan struct{})}
}

// handleReadyz is the HTTP handler for GET /readyz. It returns 200 only when every
// check passes and 503 with a short reason otherwise.
func (m *ReadinessMonitor) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if m == nil || m.db == nil {
		writeReadyz(w, http.StatusServiceUnavailable, "database not configured", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	// Cheap, every-probe checks first.
	if err := m.db.VerifyReadable(ctx); err != nil {
		writeReadyz(w, http.StatusServiceUnavailable, "database unreachable",
			map[string]any{"error": err.Error()})
		return
	}

	head, err := m.db.SchemaHead(ctx)
	if err != nil {
		writeReadyz(w, http.StatusServiceUnavailable, "schema head query failed",
			map[string]any{"error": err.Error()})
		return
	}
	if head != store.ExpectedSchemaMigration {
		// A blank head means migrations were never recorded (un-migrated DB); any
		// other value means the DB is behind or ahead of what this binary ships.
		writeReadyz(w, http.StatusServiceUnavailable, "schema not at expected migration",
			map[string]any{"db_head": head, "expected": store.ExpectedSchemaMigration})
		return
	}

	// Cached deep check (integrity + foreign keys), refreshed off the hot path.
	deep := m.deepStatus(ctx)
	if !deep.healthy {
		writeReadyz(w, http.StatusServiceUnavailable, deep.reason,
			map[string]any{"check": "integrity"})
		return
	}

	writeReadyz(w, http.StatusOK, "ready", map[string]any{
		"schema_migration": head,
		"integrity":        deep.reason,
	})
}

// deepStatus returns the cached deep-check result, kicking off a single background
// refresh when the cache is empty or older than deepCheckTTL. Once a result exists the
// probe never blocks on the expensive scan — it returns whatever was last known.
//
// Before the FIRST result exists, however, the probe MUST NOT report ready: a
// corrupt-but-readable DB (schema head fine, integrity broken) would otherwise
// false-green exactly once at startup, and once is enough for compose to mark the
// container healthy and start dependents. So the first probe(s) wait — bounded by the
// probe context — for the initial scan. On a fresh/small DB the scan completes in
// milliseconds and the very first probe still answers 200; on a huge DB the probe
// times out NOT ready, which the compose start_period absorbs until the scan lands.
func (m *ReadinessMonitor) deepStatus(ctx context.Context) deepCheckResult {
	now := time.Now().UTC()

	m.mu.Lock()
	cached := m.deep
	stale := cached.at.IsZero() || now.Sub(cached.at) > deepCheckTTL
	if stale && !m.refreshing {
		m.refreshing = true
		go m.refreshDeep()
	}
	m.mu.Unlock()

	if !cached.at.IsZero() {
		return cached
	}

	// No result yet — wait for the initial scan rather than guessing healthy.
	select {
	case <-m.firstDone:
		m.mu.Lock()
		cached = m.deep
		m.mu.Unlock()
		return cached
	case <-ctx.Done():
		return deepCheckResult{healthy: false, reason: "initial integrity check still running"}
	}
}

// refreshDeep runs the expensive deep check once and stores the result. It clears the
// refreshing flag on exit so a later staleness can trigger another refresh, and closes
// firstDone after the first result so startup probes waiting in deepStatus unblock.
func (m *ReadinessMonitor) refreshDeep() {
	ctx, cancel := context.WithTimeout(context.Background(), deepCheckMaxDuration)
	defer cancel()

	res := m.runDeepCheck(ctx)
	res.at = time.Now().UTC()

	m.mu.Lock()
	first := m.deep.at.IsZero()
	m.deep = res
	m.refreshing = false
	m.mu.Unlock()

	// Only one refresh runs at a time (refreshing flag), and `first` is true exactly
	// once because every stored result carries a non-zero at — so no double close.
	if first && m.firstDone != nil {
		close(m.firstDone)
	}
}

// runDeepCheck performs the referential-integrity (foreign_key_check) and structural
// (integrity_check) scans, returning the first failure it finds. foreign_key_check runs
// first because it is the cheaper of the two.
func (m *ReadinessMonitor) runDeepCheck(ctx context.Context) deepCheckResult {
	violations, err := m.db.ForeignKeyViolations(ctx)
	if err != nil {
		return deepCheckResult{reason: "foreign_key_check failed: " + err.Error()}
	}
	if len(violations) > 0 {
		return deepCheckResult{
			reason: fmt.Sprintf("%d foreign key violation(s): %s",
				len(violations), summarizeViolations(violations)),
		}
	}

	ok, detail, err := m.db.IntegrityCheck(ctx)
	if err != nil {
		return deepCheckResult{reason: "integrity_check failed: " + err.Error()}
	}
	if !ok {
		return deepCheckResult{reason: "integrity_check: " + detail}
	}

	return deepCheckResult{healthy: true, reason: "ok"}
}

// summarizeViolations keeps the readiness reason bounded regardless of how many FK
// violations exist, so a badly corrupted DB does not emit a giant response body.
func summarizeViolations(violations []string) string {
	const max = 5
	if len(violations) <= max {
		return strings.Join(violations, ", ")
	}
	return fmt.Sprintf("%s, … (+%d more)", strings.Join(violations[:max], ", "), len(violations)-max)
}

// writeReadyz emits the readiness JSON body. wget --spider (the compose healthcheck)
// only inspects the status code, but a JSON body keeps the endpoint useful for humans
// and curl-based debugging.
func writeReadyz(w http.ResponseWriter, status int, reason string, extra map[string]any) {
	body := map[string]any{
		"ready":  status == http.StatusOK,
		"status": http.StatusText(status),
		"reason": reason,
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}
