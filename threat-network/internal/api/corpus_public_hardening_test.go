package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestCorpusPublicRoutesRejectQueriesAndRateLimit(t *testing.T) {
	s, public, _ := newCorpusAPIServers(t)
	resp, err := http.Get(public.URL + "/api/v1/device-corpus/manifest?cache_bust=1")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("query-bearing manifest status=%d", resp.StatusCode)
	}

	s.corpusLimit = NewRateLimiter(0.001, 1)
	resp, err = http.Get(public.URL + "/api/v1/device-corpus/manifest")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first corpus request status=%d", resp.StatusCode)
	}
	resp, err = http.Get(public.URL + "/api/v1/device-corpus/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited corpus request status=%d", resp.StatusCode)
	}
}

func TestConditionalCorpusSnapshotDoesNotMaterializeStoredBody(t *testing.T) {
	s, public, _ := newCorpusAPIServers(t)
	raw := []byte(`{"schema_version":1,"corpus_revision":1,"generated_at":"2026-07-13T16:00:00Z","profiles":[],"unreviewed":"private"}`)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	if _, err := s.DB.Exec(`INSERT INTO device_corpus_releases
        (corpus_revision, schema_version, snapshot_sha256, snapshot_json,
         profile_count, variant_count, created_at)
        VALUES (1, 1, ?, ?, 0, 0, '2026-07-13T16:00:00Z')`, hash, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE device_corpus_state SET current_revision = 1,
        current_snapshot_sha256 = ?, updated_at = '2026-07-13T16:00:00Z'
        WHERE singleton = 1`, hash); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, public.URL+"/api/v1/device-corpus/snapshot", nil)
	req.Header.Set("If-None-Match", `"`+hash+`"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional snapshot status=%d", resp.StatusCode)
	}

	resp, err = http.Get(public.URL + "/api/v1/device-corpus/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("invalid stored snapshot unexpectedly served: %d", resp.StatusCode)
	}
}
