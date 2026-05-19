package dnsintel

import (
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

func TestEnrichDoesNotPromoteSubthresholdDGA(t *testing.T) {
	result := ScoreDGA("a1b2c3d4.example.com")
	if result.Score <= 0.3 || result.IsDGA {
		t.Fatalf("test fixture should be mild only, got score=%.2f isDGA=%v", result.Score, result.IsDGA)
	}

	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "a1b2c3d4.example.com",
		QueryType:  "A",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore != 0 {
		t.Fatalf("expected subthreshold DGA heuristic to stay out of threat view, got %.2f", event.AnomalyScore)
	}
	if len(event.Tags) != 0 {
		t.Fatalf("expected no tags, got %v", event.Tags)
	}
}

func TestEnrichDoesNotPromoteSubthresholdTunnelSignal(t *testing.T) {
	result := ScoreTunnel("aaaaaaaaaaaaaaaa.example.com")
	if result.Score <= 0.3 || result.IsTunnel {
		t.Fatalf("test fixture should be mild only, got score=%.2f isTunnel=%v signals=%v", result.Score, result.IsTunnel, result.Signals)
	}

	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "aaaaaaaaaaaaaaaa.example.com",
		QueryType:  "TXT",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore != 0 {
		t.Fatalf("expected subthreshold tunnel heuristic to stay out of threat view, got %.2f", event.AnomalyScore)
	}
	if len(event.Tags) != 0 {
		t.Fatalf("expected no tags, got %v", event.Tags)
	}
}

func TestEnrichPromotesStrongDGA(t *testing.T) {
	event := models.Event{
		EventType:  "dns_query",
		SourceHash: "source-a",
		Domain:     "r7t2x9k4m1n8.biz",
		QueryType:  "A",
		Timestamp:  time.Now().UTC(),
	}

	NewEnricher(nil).Enrich(&event)

	if event.AnomalyScore == 0 {
		t.Fatal("expected strong DGA to raise anomaly score")
	}
	if !hasTag(event.Tags, "dga_candidate") {
		t.Fatalf("expected dga_candidate tag, got %v", event.Tags)
	}
	if event.ThreatDesc == "" {
		t.Fatal("expected threat description")
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
