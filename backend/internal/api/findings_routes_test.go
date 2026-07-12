package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/auth"
	"github.com/vedetta-network/vedetta/backend/internal/discovery"
	"github.com/vedetta-network/vedetta/backend/internal/dnsintel"
	"github.com/vedetta-network/vedetta/backend/internal/models"
	"github.com/vedetta-network/vedetta/backend/internal/store"
	"github.com/vedetta-network/vedetta/backend/internal/threatintel"
)

type staticFeedHealth []threatintel.FeedHealth

func (f staticFeedHealth) Status() []threatintel.FeedHealth {
	return append([]threatintel.FeedHealth(nil), f...)
}

func setupFindingRouter(t *testing.T) (*Server, *store.DB, http.Handler) {
	t.Helper()
	srv, db := setupTestServer(t)
	tdb, err := threatintel.NewThreatIntelDB(db.DB)
	if err != nil {
		t.Fatalf("threat DB: %v", err)
	}
	if _, err := tdb.BulkImport([]threatintel.Indicator{{
		Value: "c2.badzone.example", Type: "domain", Source: "urlhaus",
		Confidence: 0.92, Tags: []string{"c2"}, TTLHours: 168,
	}}); err != nil {
		t.Fatalf("seed threat indicator: %v", err)
	}
	now := time.Now().UTC()
	srv.Enricher = dnsintel.NewEnricher(tdb)
	srv.FeedHealth = staticFeedHealth{{
		Name: "urlhaus", State: "healthy", LastAttempt: &now, LastSuccess: &now, ItemCount: 1,
	}}
	return srv, db, NewRouter(srv)
}

func requestJSON(t *testing.T, router http.Handler, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestFindingRoutesVerticalSliceAndLifecycle(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	now := time.Now().UTC()
	ingest := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", "", models.Event{
		EventID: "finding-route-event", Timestamp: now, EventType: "dns_query",
		SourceIP: "192.0.2.10", Domain: "c2.badzone.example", QueryType: "A", Blocked: false,
	})
	if ingest.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", ingest.Code, ingest.Body.String())
	}

	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	list := requestJSON(t, router, http.MethodGet, "/api/v1/findings?status=active&disposition=active", admin, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list findings: %d %s", list.Code, list.Body.String())
	}
	var page struct {
		Findings []models.Finding `json:"findings"`
		Total    int              `json:"total"`
	}
	if err := json.NewDecoder(list.Body).Decode(&page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if page.Total != 1 || len(page.Findings) != 1 {
		t.Fatalf("unexpected findings page: %+v", page)
	}
	finding := page.Findings[0]
	if finding.CurrentPriority != models.PriorityCritical || finding.ObservedCount != 1 || finding.Outcome != "observed" {
		t.Fatalf("finding did not preserve priority/outcome: %+v", finding)
	}

	detail := requestJSON(t, router, http.MethodGet, "/api/v1/findings/"+finding.FindingID, admin, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("finding detail: %d %s", detail.Code, detail.Body.String())
	}
	var detailBody struct {
		Evidence         []models.DetectionEvidence    `json:"evidence"`
		StatusHistory    []models.FindingStatusHistory `json:"status_history"`
		SupportingEvents []models.Event                `json:"supporting_events"`
	}
	if err := json.NewDecoder(detail.Body).Decode(&detailBody); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if len(detailBody.Evidence) == 0 || len(detailBody.StatusHistory) != 1 || len(detailBody.SupportingEvents) != 1 {
		t.Fatalf("incomplete finding detail: %+v", detailBody)
	}

	badResolve := requestJSON(t, router, http.MethodPatch, "/api/v1/findings/"+finding.FindingID+"/status", admin,
		map[string]any{"status": "resolved", "reason": ""})
	if badResolve.Code != http.StatusBadRequest {
		t.Fatalf("resolution without reason = %d, want 400", badResolve.Code)
	}
	resolved := requestJSON(t, router, http.MethodPatch, "/api/v1/findings/"+finding.FindingID+"/status", admin,
		map[string]any{"status": "resolved", "reason": "Synthetic fixture reviewed"})
	if resolved.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", resolved.Code, resolved.Body.String())
	}

	stats := requestJSON(t, router, http.MethodGet, "/api/v1/findings/stats", admin, nil)
	if stats.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", stats.Code, stats.Body.String())
	}
	var gotStats store.FindingStats
	_ = json.NewDecoder(stats.Body).Decode(&gotStats)
	if gotStats.RecentlyResolved != 1 || gotStats.OpenByPriority[models.PriorityCritical] != 0 || gotStats.CalculatedAt.IsZero() {
		t.Fatalf("unexpected stats after resolution: %+v", gotStats)
	}

	raw, err := db.QueryEvents(store.EventQueryParams{Domain: "c2.badzone.example"})
	if err != nil || raw.Total != 1 || raw.Events[0].Acknowledged {
		t.Fatalf("lifecycle mutated or lost raw event: total=%d err=%v events=%+v", raw.Total, err, raw.Events)
	}
}

func TestFindingDispositionPagesAreDisjointBeforePagination(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	now := time.Now().UTC()
	for index, sourceIP := range []string{"192.0.2.41", "192.0.2.42"} {
		response := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", "", models.Event{
			EventID: fmt.Sprintf("finding-disposition-event-%d", index), Timestamp: now.Add(time.Duration(index) * time.Second),
			EventType: "dns_query", SourceIP: sourceIP, Domain: "c2.badzone.example", QueryType: "A",
		})
		if response.Code != http.StatusAccepted {
			t.Fatalf("ingest %d: %d %s", index, response.Code, response.Body.String())
		}
	}

	var suppressedID string
	if err := db.QueryRow(`SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1`).Scan(&suppressedID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE findings SET disposition='suppressed' WHERE finding_id=?`, suppressedID); err != nil {
		t.Fatal(err)
	}
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	readPage := func(path string) struct {
		Findings []models.Finding `json:"findings"`
		Total    int              `json:"total"`
	} {
		t.Helper()
		response := requestJSON(t, router, http.MethodGet, path, admin, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, response.Code, response.Body.String())
		}
		var page struct {
			Findings []models.Finding `json:"findings"`
			Total    int              `json:"total"`
		}
		if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
			t.Fatal(err)
		}
		return page
	}

	actionable := readPage("/api/v1/findings?status=active&disposition=active&page=1&limit=1")
	suppressed := readPage("/api/v1/findings?status=active&disposition=suppressed&page=1&limit=1")
	if actionable.Total != 1 || suppressed.Total != 1 || len(actionable.Findings) != 1 || len(suppressed.Findings) != 1 {
		t.Fatalf("disposition pages actionable=%+v suppressed=%+v", actionable, suppressed)
	}
	if actionable.Findings[0].FindingID == suppressed.Findings[0].FindingID || suppressed.Findings[0].FindingID != suppressedID {
		t.Fatalf("disposition pages overlap: actionable=%s suppressed=%s", actionable.Findings[0].FindingID, suppressed.Findings[0].FindingID)
	}
}

func TestFindingsRouteCapsExpandedPrefixAtSafeBetaBound(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	response := requestJSON(t, router, http.MethodGet,
		fmt.Sprintf("/api/v1/findings?status=active&page=1&limit=%d", store.MaxFindingQueryLimit+1000), admin, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expanded findings prefix: %d %s", response.Code, response.Body.String())
	}
	var page store.FindingQueryResult
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Limit != store.MaxFindingQueryLimit || page.Page != 1 {
		t.Fatalf("route prefix = %+v, want page 1 limit %d", page, store.MaxFindingQueryLimit)
	}
}

func TestFindingSuppressionRoutesAreAdminOnlyImmediateAndReversible(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	now := time.Now().UTC()
	seed := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", "", models.Event{
		EventID: "suppression-route-1", Timestamp: now, EventType: "dns_query",
		SourceIP: "192.0.2.55", Domain: "c2.badzone.example", QueryType: "A",
	})
	if seed.Code != http.StatusAccepted {
		t.Fatalf("seed: %d %s", seed.Code, seed.Body.String())
	}
	page, err := db.QueryFindings(t.Context(), store.FindingQueryParams{ActiveOnly: true})
	if err != nil || len(page.Findings) != 1 {
		t.Fatalf("finding fixture: page=%+v err=%v", page, err)
	}
	findingID := page.Findings[0].FindingID
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")

	path := "/api/v1/findings/" + findingID + "/suppress"
	if w := requestJSON(t, router, http.MethodPost, path, read, map[string]any{"reason": "Expected lab traffic"}); w.Code != http.StatusForbidden {
		t.Fatalf("read token suppression = %d, want 403", w.Code)
	}
	if w := requestJSON(t, router, http.MethodPost, path, admin, map[string]any{"reason": ""}); w.Code != http.StatusBadRequest {
		t.Fatalf("empty suppression reason = %d, want 400: %s", w.Code, w.Body.String())
	}
	suppressed := requestJSON(t, router, http.MethodPost, path, admin, map[string]any{"reason": "Expected lab traffic"})
	if suppressed.Code != http.StatusCreated {
		t.Fatalf("suppress = %d: %s", suppressed.Code, suppressed.Body.String())
	}
	var suppressBody struct {
		Finding models.Finding                `json:"finding"`
		Rule    models.FindingSuppressionRule `json:"rule"`
	}
	if err := json.NewDecoder(suppressed.Body).Decode(&suppressBody); err != nil {
		t.Fatal(err)
	}
	if suppressBody.Finding.Disposition != models.DispositionSuppressed || suppressBody.Rule.RuleID == "" || !suppressBody.Rule.Active {
		t.Fatalf("suppression response = %+v", suppressBody)
	}

	// The typed policy applies to a future equivalent occurrence without erasing
	// or resolving the existing finding.
	next := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", admin, models.Event{
		EventID: "suppression-route-2", Timestamp: now.Add(time.Minute), EventType: "dns_query",
		SourceIP: "192.0.2.55", Domain: "c2.badzone.example", QueryType: "A",
	})
	if next.Code != http.StatusAccepted {
		t.Fatalf("future matching event = %d: %s", next.Code, next.Body.String())
	}
	finding, err := db.GetFinding(t.Context(), findingID)
	if err != nil || finding.Disposition != models.DispositionSuppressed || finding.OccurrenceCount != 2 || finding.Status != models.FindingStatusOpen {
		t.Fatalf("future suppression finding=%+v err=%v", finding, err)
	}
	otherSource := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", admin, models.Event{
		EventID: "suppression-route-other-source", Timestamp: now.Add(2 * time.Minute), EventType: "dns_query",
		SourceIP: "192.0.2.56", Domain: "c2.badzone.example", QueryType: "A",
	})
	if otherSource.Code != http.StatusAccepted {
		t.Fatalf("other source event = %d: %s", otherSource.Code, otherSource.Body.String())
	}
	actionable, err := db.QueryFindings(t.Context(), store.FindingQueryParams{
		ActiveOnly: true, Disposition: models.DispositionActive,
	})
	if err != nil || actionable.Total != 1 || len(actionable.Findings) != 1 || actionable.Findings[0].FindingID == findingID {
		t.Fatalf("fallback-scoped suppression hid another source: page=%+v err=%v", actionable, err)
	}

	list := requestJSON(t, router, http.MethodGet, "/api/v1/finding-suppressions", read, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), suppressBody.Rule.RuleID) {
		t.Fatalf("list rules = %d: %s", list.Code, list.Body.String())
	}
	deletePath := "/api/v1/finding-suppressions/" + suppressBody.Rule.RuleID
	if w := requestJSON(t, router, http.MethodDelete, deletePath, read, nil); w.Code != http.StatusForbidden {
		t.Fatalf("read token unsuppress = %d, want 403", w.Code)
	}
	unsuppressed := requestJSON(t, router, http.MethodDelete, deletePath, admin, nil)
	if unsuppressed.Code != http.StatusOK {
		t.Fatalf("unsuppress = %d: %s", unsuppressed.Code, unsuppressed.Body.String())
	}
	finding, _ = db.GetFinding(t.Context(), findingID)
	if finding.Disposition != models.DispositionActive || finding.SuppressionRuleID != "" || finding.OccurrenceCount != 2 {
		t.Fatalf("unsuppressed finding = %+v", finding)
	}
}

func TestDetectionHealthUsesWorstActorAndRequiresSources(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	if w := requestJSON(t, router, http.MethodGet, "/api/v1/health/detection", "", nil); w.Code != http.StatusOK {
		t.Fatalf("health without source: %d %s", w.Code, w.Body.String())
	} else {
		var body map[string]any
		_ = json.NewDecoder(w.Body).Decode(&body)
		if body["state"] != "initializing" {
			t.Fatalf("no collection sources must initialize, got %v", body["state"])
		}
	}

	if err := db.MarkCollectionSuccess(t.Context(), "collector", "push", "Collector", 3, time.Now().UTC()); err != nil {
		t.Fatalf("mark healthy: %v", err)
	}
	if _, err := db.InsertEvents([]models.Event{{
		EventID: "health-last-event", Timestamp: time.Now().UTC(), EventType: "dns_query", SourceHash: "fixture", Metadata: `{}`,
	}}); err != nil {
		t.Fatalf("insert health event: %v", err)
	}
	healthy := requestJSON(t, router, http.MethodGet, "/api/v1/health/detection", "", nil)
	var healthyBody map[string]any
	_ = json.NewDecoder(healthy.Body).Decode(&healthyBody)
	if healthyBody["state"] != "healthy" || healthyBody["last_event_at"] == nil {
		t.Fatalf("healthy actors aggregated as %v: %s", healthyBody["state"], healthy.Body.String())
	}

	if err := db.MarkCollectionError(t.Context(), "collector", "push", "Collector", "synthetic failure", time.Now().UTC()); err != nil {
		t.Fatalf("mark error: %v", err)
	}
	failed := requestJSON(t, router, http.MethodGet, "/api/v1/health/detection", "", nil)
	var failedBody map[string]any
	_ = json.NewDecoder(failed.Body).Decode(&failedBody)
	if failedBody["state"] != "error" {
		t.Fatalf("child error must dominate aggregate: %s", failed.Body.String())
	}
}

func TestDetectionHealthSensorHeartbeatDoesNotMaskProcessingError(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	now := time.Now().UTC()
	if err := db.RegisterSensor(models.Sensor{
		SensorID: "sensor-health", Hostname: "health-probe", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test", LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkCollectionError(t.Context(), "sensor:sensor-health", "sensor",
		"Sensor sensor-health", "synthetic commit failure", now); err != nil {
		t.Fatal(err)
	}

	w := requestJSON(t, router, http.MethodGet, "/api/v1/health/detection", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		State   string                 `json:"state"`
		Sources []detectionHealthActor `json:"sources"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.State != "error" {
		t.Fatalf("fresh heartbeat masked processing error: %s", w.Body.String())
	}
	for _, source := range body.Sources {
		if source.ID == "sensor:sensor-health" {
			if source.State != "error" || source.Error != "synthetic commit failure" {
				t.Fatalf("merged sensor health = %+v", source)
			}
			return
		}
	}
	t.Fatal("sensor health actor missing")
}

func TestDetectionHealthSensorHeartbeatWithoutBatchIsInitializing(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	now := time.Now().UTC()
	if err := db.RegisterSensor(models.Sensor{
		SensorID: "sensor-no-capture-proof", Hostname: "quiet-probe", OS: "linux", Arch: "amd64",
		CIDR: "192.0.2.0/24", Version: "test", LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	w := requestJSON(t, router, http.MethodGet, "/api/v1/health/detection", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		State   string                 `json:"state"`
		Sources []detectionHealthActor `json:"sources"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.State != "initializing" {
		t.Fatalf("work heartbeat falsely proved capture health: %s", w.Body.String())
	}
	for _, source := range body.Sources {
		if source.ID == "sensor:sensor-no-capture-proof" {
			if source.State != "initializing" || source.LastAttempt == nil || source.LastSuccess != nil {
				t.Fatalf("unproven capture actor = %+v", source)
			}
			return
		}
	}
	t.Fatal("sensor health actor missing")
}

func TestFindingDeviceNavigationFollowsMergeAndUndo(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	observedAt := time.Now().UTC().Add(-time.Minute)
	for _, host := range []discovery.DiscoveredHost{
		{IPAddress: "192.0.2.21", MACAddress: "00:00:5E:00:53:21", Hostname: "camera-one.example"},
		{IPAddress: "192.0.2.22", MACAddress: "00:00:5E:00:53:22", Hostname: "camera-two.example"},
	} {
		if _, err := db.ObserveDevice(store.DeviceObservation{Host: host, Segment: "iot", ObservedAt: observedAt}); err != nil {
			t.Fatalf("observe device: %v", err)
		}
	}
	source, _ := db.GetDeviceByIP("192.0.2.21")
	target, _ := db.GetDeviceByIP("192.0.2.22")
	if source == nil || target == nil {
		t.Fatal("device fixtures missing")
	}

	event := models.Event{EventID: "merge-nav-event", Timestamp: time.Now().UTC(), EventType: "dns_query",
		SourceIP: "192.0.2.21", Domain: "c2.badzone.example", QueryType: "A", NetworkSegment: "iot"}
	if w := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", "", event); w.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
	page, err := db.QueryFindings(t.Context(), store.FindingQueryParams{ActiveOnly: true})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].DeviceID != source.DeviceID {
		t.Fatalf("finding did not resolve source device: page=%+v err=%v", page, err)
	}
	rule, err := db.SuppressFinding(t.Context(), page.Findings[0].FindingID, "same asset/domain noise", "test")
	if err != nil {
		t.Fatalf("suppress source finding: %v", err)
	}
	action, err := db.MergeDevices(t.Context(), source.DeviceID, target.DeviceID, "same synthetic camera", "test")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	recurrence := event
	recurrence.EventID = "merge-nav-event-recurrence"
	recurrence.Timestamp = event.Timestamp.Add(time.Minute)
	if w := requestJSON(t, router, http.MethodPost, "/api/v1/ingest", "", recurrence); w.Code != http.StatusAccepted {
		t.Fatalf("post-merge recurrence: %d %s", w.Code, w.Body.String())
	}
	suppressed, err := db.GetFinding(t.Context(), page.Findings[0].FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if suppressed.Disposition != models.DispositionSuppressed || suppressed.SuppressionRuleID != rule.RuleID || suppressed.OccurrenceCount != 2 {
		t.Fatalf("merge broke canonical suppression: %+v rule=%+v", suppressed, rule)
	}

	list := requestJSON(t, router, http.MethodGet, "/api/v1/findings?status=active", "", nil)
	var response struct {
		Findings []models.Finding `json:"findings"`
	}
	_ = json.NewDecoder(list.Body).Decode(&response)
	if len(response.Findings) != 1 || response.Findings[0].CanonicalDeviceID != target.DeviceID {
		t.Fatalf("canonical navigation after merge: %s", list.Body.String())
	}
	if _, err := db.UndoDeviceMerge(t.Context(), action.ActionID, "fixture was incorrect", "test"); err != nil {
		t.Fatalf("undo merge: %v", err)
	}
	list = requestJSON(t, router, http.MethodGet, "/api/v1/findings?status=active", "", nil)
	_ = json.NewDecoder(list.Body).Decode(&response)
	if len(response.Findings) != 1 || response.Findings[0].CanonicalDeviceID != source.DeviceID {
		t.Fatalf("canonical navigation after undo: %s", list.Body.String())
	}
}

func TestIdentityActionsAreAdminOnlyAndRawValueIsNotStored(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	if _, err := db.ObserveDevice(store.DeviceObservation{Host: discovery.DiscoveredHost{
		IPAddress: "192.0.2.31", MACAddress: "00:00:5E:00:53:31",
	}, Segment: "default", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("observe device: %v", err)
	}
	device, _ := db.GetDeviceByIP("192.0.2.31")
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")
	body := map[string]any{
		"evidence": map[string]any{"type": "hostname", "value": "synthetic-camera.example", "sensitive": true},
		"reason":   "Confirmed from the device label",
	}
	if w := requestJSON(t, router, http.MethodPost, "/api/v1/devices/"+device.DeviceID+"/confirm", read, body); w.Code != http.StatusForbidden {
		t.Fatalf("read token identity write = %d, want 403", w.Code)
	}
	confirmed := requestJSON(t, router, http.MethodPost, "/api/v1/devices/"+device.DeviceID+"/confirm", admin, body)
	if confirmed.Code != http.StatusCreated {
		t.Fatalf("confirm identity: %d %s", confirmed.Code, confirmed.Body.String())
	}
	var rawValue, display string
	if err := db.QueryRow(`SELECT value_hmac, value_display FROM device_identity_evidence
		WHERE device_id = ? AND evidence_type = 'hostname'`, device.DeviceID).Scan(&rawValue, &display); err != nil {
		t.Fatalf("load identity evidence: %v", err)
	}
	if rawValue == "synthetic-camera.example" || display != "" || len(rawValue) != 64 {
		t.Fatalf("raw stable identity persisted: hash=%q display=%q", rawValue, display)
	}
}

func TestAuthSessionReportsCapabilities(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	bootstrap := requestJSON(t, router, http.MethodGet, "/api/v1/auth/session", "", nil)
	var body struct {
		Scope    string `json:"scope"`
		CanAdmin bool   `json:"can_admin"`
	}
	_ = json.NewDecoder(bootstrap.Body).Decode(&body)
	if bootstrap.Code != http.StatusOK || body.Scope != "bootstrap" || body.CanAdmin {
		t.Fatalf("bootstrap session: %d %s", bootstrap.Code, bootstrap.Body.String())
	}

	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")
	for _, test := range []struct {
		token string
		scope string
		admin bool
	}{{admin, "admin", true}, {read, "read", false}} {
		w := requestJSON(t, router, http.MethodGet, "/api/v1/auth/session", test.token, nil)
		body = struct {
			Scope    string `json:"scope"`
			CanAdmin bool   `json:"can_admin"`
		}{}
		_ = json.NewDecoder(w.Body).Decode(&body)
		if w.Code != http.StatusOK || body.Scope != test.scope || body.CanAdmin != test.admin {
			t.Fatalf("session for %s: %d %s", test.scope, w.Code, w.Body.String())
		}
	}
}

func TestDeviceMergeAuditCanBeRediscoveredAndUndone(t *testing.T) {
	_, db, router := setupFindingRouter(t)
	when := time.Now().UTC()
	for _, host := range []discovery.DiscoveredHost{
		{IPAddress: "192.0.2.41", MACAddress: "00:00:5E:00:53:41", Hostname: "duplicate-a.example"},
		{IPAddress: "192.0.2.42", MACAddress: "00:00:5E:00:53:42", Hostname: "duplicate-b.example"},
	} {
		if _, err := db.ObserveDevice(store.DeviceObservation{Host: host, Segment: "iot", ObservedAt: when}); err != nil {
			t.Fatal(err)
		}
	}
	source, _ := db.GetDeviceByIP("192.0.2.41")
	target, _ := db.GetDeviceByIP("192.0.2.42")
	admin := createTestToken(t, db, auth.ScopeAdmin, "")
	read := createTestToken(t, db, auth.ScopeRead, "")
	merged := requestJSON(t, router, http.MethodPost, "/api/v1/devices/merge", admin, map[string]any{
		"source_device_id": source.DeviceID, "target_device_id": target.DeviceID, "reason": "synthetic duplicate",
	})
	if merged.Code != http.StatusCreated {
		t.Fatalf("merge: %d %s", merged.Code, merged.Body.String())
	}
	var mergeBody struct {
		Action models.ActiveDeviceMerge `json:"action"`
	}
	_ = json.NewDecoder(merged.Body).Decode(&mergeBody)
	if mergeBody.Action.ActionID == "" {
		t.Fatalf("missing merge audit action: %s", merged.Body.String())
	}

	listed := requestJSON(t, router, http.MethodGet, "/api/v1/device-merges", read, nil)
	var listBody struct {
		Actions []models.ActiveDeviceMerge `json:"actions"`
	}
	_ = json.NewDecoder(listed.Body).Decode(&listBody)
	if listed.Code != http.StatusOK || len(listBody.Actions) != 1 || listBody.Actions[0].ActionID != mergeBody.Action.ActionID {
		t.Fatalf("reloadable merge audit: %d %s", listed.Code, listed.Body.String())
	}

	path := "/api/v1/device-merges/" + mergeBody.Action.ActionID + "/split"
	if w := requestJSON(t, router, http.MethodPost, path, read, map[string]any{"reason": "wrong"}); w.Code != http.StatusForbidden {
		t.Fatalf("read token split = %d, want 403", w.Code)
	}
	if w := requestJSON(t, router, http.MethodPost, path, admin, map[string]any{"reason": "not actually the same"}); w.Code != http.StatusCreated {
		t.Fatalf("split: %d %s", w.Code, w.Body.String())
	}
	listed = requestJSON(t, router, http.MethodGet, "/api/v1/device-merges", read, nil)
	_ = json.NewDecoder(listed.Body).Decode(&listBody)
	if len(listBody.Actions) != 0 {
		t.Fatalf("undone merge still active: %s", listed.Body.String())
	}
}
