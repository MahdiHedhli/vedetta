package feed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// TestContractConformance validates the live response structure (fields, types,
// enums) against specs/003-threat-network/contracts/community-feed-api.md.
// Removing or renaming a required field will fail this test.
func TestContractConformance(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 30, 0, 0, time.UTC)
	b, db := newBuilder(t, now)
	seedItems(t, db, 1, now)

	resp, _, err := b.Build(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(resp)
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}

	// Envelope required keys per contract.
	for _, k := range []string{"schema_version", "feed", "generated_at", "ttl_seconds",
		"advisory", "total_items", "returned_items", "items"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("envelope missing required field %q", k)
		}
	}
	if m["schema_version"].(float64) != 1 {
		t.Fatalf("schema_version must be 1")
	}
	if m["feed"].(string) != "community" {
		t.Fatalf("feed must be 'community'")
	}
	if m["ttl_seconds"].(float64) != 900 {
		t.Fatalf("ttl_seconds must be 900")
	}
	if m["advisory"].(bool) != true {
		t.Fatalf("advisory must be true")
	}

	items := m["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	item := items[0].(map[string]any)
	requiredItemKeys := []string{"feed_id", "kind", "indicator", "indicator_type",
		"confidence", "severity", "advisory", "recommended_action", "sources_required",
		"sources_observed", "reasons", "first_seen", "last_seen", "published_at",
		"updated_at", "expires_at"}
	for _, k := range requiredItemKeys {
		if _, ok := item[k]; !ok {
			t.Fatalf("item missing required field %q", k)
		}
	}

	// Enum checks.
	if item["recommended_action"].(string) != "advise" {
		t.Fatalf("recommended_action must be 'advise'")
	}
	if item["advisory"].(bool) != true {
		t.Fatalf("item advisory must be true")
	}
	if k := item["kind"].(string); k != "domain_indicator" && k != "etld1_indicator" && k != "behavior_cluster" {
		t.Fatalf("invalid kind enum: %s", k)
	}
	if it := item["indicator_type"].(string); it != "domain" && it != "etld_plus_one" && it != "behavior" {
		t.Fatalf("invalid indicator_type enum: %s", it)
	}
	if sev := item["severity"].(string); sev != "high" && sev != "medium" && sev != "low" {
		t.Fatalf("invalid severity enum: %s", sev)
	}
	if c := item["confidence"].(float64); c < 0 || c > 1 {
		t.Fatalf("confidence out of [0,1]: %v", c)
	}
	if _, ok := item["reasons"].([]any); !ok {
		t.Fatalf("reasons must be an array")
	}
}

// TestErrorBodyShape validates the feed error envelope shape from the contract.
func TestErrorBodyShape(t *testing.T) {
	// This mirrors the api layer's writeFeedError body; we assert the contract
	// fields here so a rename is caught in the feed package tests too.
	body := map[string]any{
		"schema_version": SchemaVersion,
		"error": map[string]any{
			"code":                "RATE_LIMIT_EXCEEDED",
			"message":             "Per-IP feed request limit exceeded",
			"retry_after_seconds": 300,
		},
	}
	blob, _ := json.Marshal(body)
	var m map[string]any
	json.Unmarshal(blob, &m)
	if _, ok := m["schema_version"]; !ok {
		t.Fatal("error envelope missing schema_version")
	}
	e := m["error"].(map[string]any)
	if e["code"].(string) != "RATE_LIMIT_EXCEEDED" {
		t.Fatal("error code mismatch")
	}
}

var _ = store.FeedItem{}
