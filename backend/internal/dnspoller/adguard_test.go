package dnspoller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdGuardHTTPClientBoundsAndAuth(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/control/querylog" {
			http.NotFound(w, r)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "synthetic-user" || password != "synthetic-password" {
			t.Errorf("unexpected basic auth: ok=%v user=%q", ok, user)
		}
		if olderThan := r.URL.Query().Get("older_than"); olderThan != "" {
			t.Errorf("unexpected continuation cursor %q", olderThan)
		}
		if r.URL.Query().Get("limit") != "2" {
			t.Errorf("first-page limit = %q", r.URL.Query().Get("limit"))
		}
		fmt.Fprint(w, `{"data":[
			{"time":"2026-07-12T12:00:00Z","client":"192.0.2.30","reason":"NotFilteredNotFound","question":{"name":"one.example","type":"A","class":"IN"}},
			{"time":"2026-07-12T12:00:01Z","client":"192.0.2.31","reason":"FilteredBlackList","question":{"name":"two.example","type":"AAAA","class":"IN"}}
		],"oldest":"2026-07-12T12:00:00Z"}`)
	}))
	defer server.Close()

	queries, err := NewAdGuardHTTPClient(server.URL, "synthetic-user", "synthetic-password").FetchQueries(context.Background(), 2)
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	if len(queries) != 2 || queries[0].IsBlocked() || !queries[1].IsBlocked() {
		t.Fatalf("queries decoded incorrectly: %+v", queries)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want one bounded page", requests.Load())
	}
}

func TestAdGuardCurrentRuleObjectResponseAndLegacyString(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/querylog" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"data":[
			{"time":"2026-07-12T12:00:00.123456789Z","elapsedMs":"1.75","client":"192.0.2.30","reason":"FilteredInvalid","rules":[{"filter_list_id":17,"text":"||c2.badzone.example^"}],"question":{"name":"c2.badzone.example","type":"A","class":"IN"}},
			{"time":"2026-07-12T12:00:01Z","client":"192.0.2.31","reason":"FilteredBlackList","rules":["legacy synthetic rule"],"question":{"name":"legacy.example","type":"AAAA","class":"IN"}}
		]}`)
	}))
	defer server.Close()

	queries, err := NewAdGuardHTTPClient(server.URL, "", "").FetchQueries(context.Background(), 10)
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	if len(queries) != 2 {
		t.Fatalf("queries = %d, want 2", len(queries))
	}
	if queries[0].ElapsedMs != "1.75" || !queries[0].IsBlocked() {
		t.Fatalf("current query fields not decoded: %+v", queries[0])
	}
	if got := queries[0].Rules; len(got) != 1 || got[0].FilterListID != 17 || got[0].Text != "||c2.badzone.example^" {
		t.Fatalf("object rules = %+v", got)
	}
	if got := queries[1].Rules; len(got) != 1 || got[0].FilterListID != 0 || got[0].Text != "legacy synthetic rule" {
		t.Fatalf("legacy rules = %+v", got)
	}
	event := (&AdGuardPoller{}).adguardQueryToEvent(queries[0])
	if event == nil {
		t.Fatal("current query did not produce an event")
	}
	var metadata struct {
		Rules []AdGuardRule `json:"adguard_rules"`
	}
	if err := json.Unmarshal([]byte(event.Metadata), &metadata); err != nil {
		t.Fatalf("decode event metadata: %v", err)
	}
	if len(metadata.Rules) != 1 || metadata.Rules[0].FilterListID != 17 || metadata.Rules[0].Text != "||c2.badzone.example^" {
		t.Fatalf("event rule evidence = %+v", metadata.Rules)
	}
}

func TestAdGuardPaginatesWithOlderThanCursor(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch request {
		case 1:
			if got := r.URL.Query().Get("limit"); got != strconv.Itoa(adGuardPageSize) {
				t.Errorf("first limit = %q", got)
			}
			if got := r.URL.Query().Get("older_than"); got != "" {
				t.Errorf("unexpected first cursor %q", got)
			}
			rows := make([]map[string]any, adGuardPageSize)
			for index := range rows {
				rows[index] = map[string]any{
					"time":     time.Date(2026, 7, 12, 12, 0, 0, index, time.UTC),
					"client":   "198.51.100.20",
					"question": map[string]string{"name": fmt.Sprintf("page-one-%d.example", index), "type": "A", "class": "IN"},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": rows, "oldest": "2026-07-12T11:59:00Z"})
		case 2:
			if got := r.URL.Query().Get("older_than"); got != "2026-07-12T11:59:00Z" {
				t.Errorf("second cursor = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
				"time": "2026-07-12T11:58:59Z", "client": "198.51.100.21",
				"question": map[string]string{"name": "page-two.example", "type": "A", "class": "IN"},
			}}})
		default:
			t.Errorf("unexpected request %d", request)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		}
	}))
	defer server.Close()

	queries, err := NewAdGuardHTTPClient(server.URL, "", "").FetchQueries(context.Background(), 150)
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	if len(queries) != adGuardPageSize+1 || requests.Load() != 2 {
		t.Fatalf("queries=%d requests=%d", len(queries), requests.Load())
	}
}

func TestAdGuardHTTPClientRejectsIgnoredLimit(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rows := make([]map[string]any, 3)
		for i := range rows {
			rows[i] = map[string]any{
				"time": "2026-07-12T12:00:00Z", "client": "198.51.100.20",
				"question": map[string]string{"name": "bounded.example", "type": "A", "class": "IN"},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
	}))
	defer server.Close()

	_, err := NewAdGuardHTTPClient(server.URL, "", "").FetchQueries(context.Background(), 2)
	if err == nil {
		t.Fatal("expected oversized AdGuard response to fail")
	}
}

func TestAdGuardFullTerminalPageWithEmptyOldestIsComplete(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[
			{"time":"2026-07-12T12:00:00Z","client":"198.51.100.20","question":{"name":"one.example","type":"A"}},
			{"time":"2026-07-12T11:59:59Z","client":"198.51.100.20","question":{"name":"two.example","type":"A"}}
		],"oldest":""}`)
	}))
	defer server.Close()

	batch, err := NewAdGuardHTTPClient(server.URL, "", "").fetchQueryBatch(context.Background(), 2, "")
	if err != nil {
		t.Fatalf("terminal full page: %v", err)
	}
	if !batch.Complete || len(batch.Queries) != 2 || batch.NextCursor != "" {
		t.Fatalf("terminal batch = %+v", batch)
	}
}

func TestAdGuardHTTPClientContinuesRetainedLogAcrossBoundedBatches(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("older_than") == "" {
			fmt.Fprint(w, `{"data":[
				{"time":"2026-07-12T12:00:00Z","client":"198.51.100.20","question":{"name":"one.example","type":"A"}},
				{"time":"2026-07-12T11:59:59Z","client":"198.51.100.20","question":{"name":"two.example","type":"A"}}
			],"oldest":"2026-07-12T11:59:59Z"}`)
			return
		}
		if got := r.URL.Query().Get("older_than"); got != "2026-07-12T11:59:59Z" {
			t.Errorf("continuation cursor = %q", got)
		}
		fmt.Fprint(w, `{"data":[{"time":"2026-07-12T11:59:58Z","client":"198.51.100.20","question":{"name":"older.example","type":"A"}}]}`)
	}))
	defer server.Close()

	client := NewAdGuardHTTPClient(server.URL, "", "")
	first, err := client.fetchQueryBatch(context.Background(), 2, "")
	if err != nil {
		t.Fatalf("first bounded batch: %v", err)
	}
	if first.Complete || first.NextCursor != "2026-07-12T11:59:59Z" || len(first.Queries) != 2 {
		t.Fatalf("first batch = %+v", first)
	}
	second, err := client.fetchQueryBatch(context.Background(), 2, first.NextCursor)
	if err != nil {
		t.Fatalf("continued bounded batch: %v", err)
	}
	if !second.Complete || len(second.Queries) != 1 || second.Queries[0].Question.Name != "older.example" {
		t.Fatalf("second batch = %+v", second)
	}
}

func TestAdGuardBackfillDoesNotAdvanceWatermarkUntilComplete(t *testing.T) {
	t.Parallel()
	watermark := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
	newest := watermark.Add(10 * time.Minute)
	poller := &AdGuardPoller{lastPollTime: watermark}

	poller.commitAdGuardBatch(false, newest, "2026-07-12T11:05:00Z")
	if !poller.lastPollTime.Equal(watermark) {
		t.Fatalf("incomplete backfill advanced watermark to %s", poller.lastPollTime)
	}
	if poller.backfillCursor == "" || !poller.backfillMaxTime.Equal(newest) {
		t.Fatalf("continuation state = cursor %q max %s", poller.backfillCursor, poller.backfillMaxTime)
	}

	poller.commitAdGuardBatch(true, newest, "")
	if !poller.lastPollTime.Equal(newest) || poller.backfillCursor != "" || !poller.backfillMaxTime.IsZero() {
		t.Fatalf("completed state = watermark %s cursor %q max %s", poller.lastPollTime, poller.backfillCursor, poller.backfillMaxTime)
	}
}

func TestAdGuardBatchReachesPriorWatermark(t *testing.T) {
	t.Parallel()
	watermark := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	if !adGuardBatchReachesWatermark([]AdGuardQuery{{Time: watermark}}, time.Time{}) {
		t.Fatal("fresh-install bootstrap did not establish the newest bounded prefix")
	}
	if adGuardBatchReachesWatermark([]AdGuardQuery{{Time: watermark.Add(time.Second)}}, watermark) {
		t.Fatal("newer-only batch incorrectly completed backfill")
	}
	if !adGuardBatchReachesWatermark([]AdGuardQuery{{Time: watermark}}, watermark) {
		t.Fatal("overlap row did not complete backfill")
	}
}
