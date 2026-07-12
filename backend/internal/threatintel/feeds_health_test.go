package threatintel

import (
	"errors"
	"testing"
	"time"
)

func TestFeedSchedulerStatusTracksFreshnessCountAndFailure(t *testing.T) {
	db := testThreatDB(t)
	fs := NewFeedScheduler(db)

	initial := feedStatusByName(fs.Status(), "urlhaus")
	if initial.State != "initializing" || initial.LastAttempt != nil {
		t.Fatalf("unexpected initial status: %+v", initial)
	}

	err := fs.runFeed("urlhaus", func() (int, error) {
		_, err := db.BulkImport([]Indicator{{
			Value:      "badzone.example",
			Type:       "domain",
			Source:     "urlhaus",
			Confidence: 0.85,
			TTLHours:   168,
		}})
		return 1, err
	})
	if err != nil {
		t.Fatalf("successful refresh: %v", err)
	}

	healthy := feedStatusByName(fs.Status(), "urlhaus")
	if healthy.State != "healthy" || healthy.ItemCount != 1 || healthy.LastSuccess == nil {
		t.Fatalf("unexpected healthy status: %+v", healthy)
	}

	wantErr := errors.New("upstream unavailable")
	if err := fs.runFeed("urlhaus", func() (int, error) { return 0, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("failed refresh error = %v, want %v", err, wantErr)
	}
	failed := feedStatusByName(fs.Status(), "urlhaus")
	if failed.State != "error" || failed.LastError == "" || failed.LastSuccess == nil {
		t.Fatalf("unexpected failed status: %+v", failed)
	}
}

func TestFeedSchedulerItemCountUsesCurrentRefreshNotAccumulatedDBRows(t *testing.T) {
	db := testThreatDB(t)
	if _, err := db.BulkImport([]Indicator{
		{Value: "old-one.example", Type: "domain", Source: "urlhaus", Confidence: 0.85},
		{Value: "old-two.example", Type: "domain", Source: "urlhaus", Confidence: 0.85},
	}); err != nil {
		t.Fatal(err)
	}

	fs := NewFeedScheduler(db)
	if err := fs.runFeed("urlhaus", func() (int, error) { return 1, nil }); err != nil {
		t.Fatal(err)
	}
	status := feedStatusByName(fs.Status(), "urlhaus")
	if status.ItemCount != 1 {
		t.Fatalf("item_count = %d, want current refresh count 1", status.ItemCount)
	}
}

func TestFeedSchedulerStatusMarksMissedRefreshesStale(t *testing.T) {
	fs := NewFeedScheduler(testThreatDB(t))
	old := time.Now().UTC().Add(-11 * time.Minute)

	fs.healthMu.Lock()
	status := fs.health["urlhaus"]
	status.LastAttempt = &old
	status.LastSuccess = &old
	fs.health["urlhaus"] = status
	fs.healthMu.Unlock()

	if got := feedStatusByName(fs.Status(), "urlhaus"); got.State != "stale" {
		t.Fatalf("state = %q, want stale (%+v)", got.State, got)
	}
}

func TestFeedSchedulerRefreshesCommunityAndReportsHealth(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := validCommunityPayload(now,
		communityItem(now, "community-1", "domain_indicator", "domain", "c2.badzone.example", 0.9),
	)
	server := communityServer(t, payload)
	defer server.Close()

	db := testThreatDB(t)
	fs := NewFeedSchedulerWithCommunity(db, server.URL)
	fs.client = server.Client()
	if err := fs.runFeed(communityFeedSource, fs.fetchCommunity); err != nil {
		t.Fatal(err)
	}
	status := feedStatusByName(fs.Status(), communityFeedSource)
	if status.State != "healthy" || status.ItemCount != 1 || status.LastSuccess == nil {
		t.Fatalf("community health = %+v", status)
	}
}

func TestFeedSchedulerOfflineModeOmitsCommunityAndUnsupportedJA3(t *testing.T) {
	fs := NewFeedSchedulerConfigured(testThreatDB(t), DefaultCommunityFeedURL, false)
	for _, status := range fs.Status() {
		if status.Name == communityFeedSource || status.Name == "sslbl" {
			t.Fatalf("disabled or unobservable source remained health-gating: %+v", status)
		}
	}
}

func feedStatusByName(statuses []FeedHealth, name string) FeedHealth {
	for _, status := range statuses {
		if status.Name == name {
			return status
		}
	}
	return FeedHealth{}
}
