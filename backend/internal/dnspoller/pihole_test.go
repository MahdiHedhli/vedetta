package dnspoller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPiHoleV6SessionAuthAndQueries(t *testing.T) {
	t.Parallel()
	var authRequests atomic.Int32
	var queryRequests atomic.Int32
	var logoutRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			authRequests.Add(1)
			if r.Method == http.MethodDelete {
				logoutRequests.Add(1)
				if got := r.Header.Get("X-FTL-SID"); got != "synthetic-sid" {
					t.Errorf("logout X-FTL-SID = %q", got)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method != http.MethodPost {
				t.Errorf("unexpected auth method %s", r.Method)
				http.Error(w, "bad method", http.StatusMethodNotAllowed)
				return
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode auth body: %v", err)
				http.Error(w, "bad auth body", http.StatusBadRequest)
				return
			}
			if payload["password"] != "synthetic-app-password" {
				t.Errorf("password = %q", payload["password"])
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"session":{"valid":true,"sid":"synthetic-sid","validity":1800}}`)
		case "/api/queries":
			queryRequests.Add(1)
			if got := r.Header.Get("X-FTL-SID"); got != "synthetic-sid" {
				t.Errorf("X-FTL-SID = %q", got)
			}
			if got := r.URL.Query().Get("length"); got != strconv.Itoa(piHoleV6PageSize) {
				t.Errorf("length = %q", got)
			}
			if r.URL.Query().Get("from") == "" || r.URL.Query().Get("until") == "" {
				t.Errorf("missing v6 time bounds: %s", r.URL.RawQuery)
			}
			if r.URL.Query().Has("to") {
				t.Errorf("v6 request used legacy to parameter: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"queries":[
				{"id":7001,"time":1752336000.125,"type":"A","domain":"c2.badzone.example","cname":null,"status":"EXTERNAL_BLOCKED_EDE15","client":{"ip":"192.0.2.25","name":"camera.example"},"dnssec":"INSECURE","reply":{"type":"NXDOMAIN","time":1.25}},
				{"id":7002,"time":1752336000.125,"type":"A","domain":"c2.badzone.example","cname":null,"status":"FORWARDED","client":{"ip":"192.0.2.25","name":"camera.example"},"dnssec":"SECURE","reply":{"type":"IP","time":2.5}},
				{"id":7003,"time":1752336000.5,"type":"AAAA","domain":"pending.example","cname":null,"status":"IN_PROGRESS","client":{"ip":"192.0.2.25"},"dnssec":"UNKNOWN","reply":{"type":"UNKNOWN","time":-1}}
			],"cursor":7002}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewPiHoleClient(server.URL, "synthetic-app-password")
	from := time.Unix(1752335940, 0).UTC()
	to := from.Add(time.Minute)
	first, err := client.FetchQueries(context.Background(), from, to)
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	second, err := client.FetchQueries(context.Background(), from, to)
	if err != nil {
		t.Fatalf("second FetchQueries: %v", err)
	}
	if authRequests.Load() != 1 { // one documented POST login, then SID reuse
		t.Fatalf("auth requests = %d, want 1", authRequests.Load())
	}
	if queryRequests.Load() != 2 {
		t.Fatalf("query requests = %d, want 2", queryRequests.Load())
	}
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("query lengths = %d, %d", len(first), len(second))
	}
	if !first[0].IsBlocked() || first[0].Status != 18 || first[0].StatusName != "EXTERNAL_BLOCKED_EDE15" {
		t.Errorf("blocked v6 query decoded incorrectly: %+v", first[0])
	}
	if first[1].IsBlocked() || first[1].Status != 2 {
		t.Errorf("allowed v6 query decoded incorrectly: %+v", first[1])
	}
	if first[0].QueryID != 7001 || first[0].ReplyName != "NXDOMAIN" || first[0].DNSSECName != "INSECURE" {
		t.Errorf("v6 evidence fields not preserved: %+v", first[0])
	}
	if piHoleEventID(first[0]) == piHoleEventID(first[1]) {
		t.Error("distinct Pi-hole v6 query IDs produced the same event ID")
	}
	if piHoleEventID(first[0]) != piHoleEventID(second[0]) {
		t.Error("replayed Pi-hole v6 query did not preserve its event ID")
	}
	progressed := first[0]
	progressed.Status = 2
	progressed.StatusName = "FORWARDED"
	progressed.ReplyType = 4
	progressed.ReplyName = "IP"
	if piHoleEventID(progressed) != piHoleEventID(first[0]) {
		t.Error("one Pi-hole v6 query changed event ID when its status finalized")
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if logoutRequests.Load() != 1 {
		t.Fatalf("logout requests = %d, want 1", logoutRequests.Load())
	}
}

func TestPiHoleV6WithoutPassword(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			t.Error("passwordless Pi-hole should not receive an auth request")
			http.Error(w, "unexpected auth", http.StatusInternalServerError)
		case "/api/queries":
			if got := r.Header.Get("X-FTL-SID"); got != "" {
				t.Errorf("unexpected SID %q", got)
			}
			fmt.Fprint(w, `{"queries":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	queries, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("FetchQueries without password: %v", err)
	}
	if len(queries) != 0 {
		t.Fatalf("queries = %d, want 0", len(queries))
	}
}

func TestPiHoleFallsBackToV5AndPreservesAuth(t *testing.T) {
	t.Parallel()
	var authAttempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			authAttempts.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("v6 fallback used %s, want POST", r.Method)
			}
			http.NotFound(w, r)
		case "/admin/api.php":
			if r.URL.Query().Get("auth") != "synthetic-v5-token" {
				t.Errorf("legacy auth token not forwarded")
			}
			if !r.URL.Query().Has("getAllQueries") {
				t.Errorf("missing getAllQueries: %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data":[[1752336000,"AAAA","blocked.badzone.example","198.51.100.40",11,2,2,3.5,"cname.badzone.example","synthetic-rule"]]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewPiHoleClient(server.URL, "synthetic-v5-token")
	queries, err := client.FetchQueries(context.Background(), time.Unix(1752335940, 0), time.Unix(1752336060, 0))
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	if len(queries) != 1 || !queries[0].IsBlocked() || queries[0].Status != 11 {
		t.Fatalf("v5 query decoded incorrectly: %+v", queries)
	}
	if queries[0].ReplyTime != 3.5 || queries[0].RegexID != "synthetic-rule" {
		t.Errorf("v5 fields not preserved: %+v", queries[0])
	}
	if authAttempts.Load() != 1 {
		t.Fatalf("v6 auth attempts = %d, want 1", authAttempts.Load())
	}

	// Once identified as v5, the client should not probe /api/auth every minute.
	if _, err := client.FetchQueries(context.Background(), time.Unix(1752335940, 0), time.Unix(1752336060, 0)); err != nil {
		t.Fatalf("second v5 fetch: %v", err)
	}
	if authAttempts.Load() != 1 {
		t.Fatalf("v6 auth attempts after cached fallback = %d, want 1", authAttempts.Load())
	}
}

func TestPiHoleV6RejectsOversizedQuerySet(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			fmt.Fprint(w, `{"session":{"valid":true,"sid":"","validity":-1}}`)
		case "/api/queries":
			rows := make([]map[string]any, piHoleV6PageSize+1)
			for i := range rows {
				rows[i] = map[string]any{
					"id": i + 1, "time": 1752336000, "type": "A",
					"domain": "bounded.example", "status": "FORWARDED",
					"client": map[string]string{"ip": "203.0.113.25"},
					"reply":  map[string]any{"type": "IP", "time": 1},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"queries": rows})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil || !strings.Contains(err.Error(), "page limit is") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestPiHoleV6IgnoresGlobalRecordsFilteredForShortWindow(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"queries": []map[string]any{{
				"id": 1, "time": 1752336000, "type": "A", "domain": "bounded.example", "status": "FORWARDED",
				"client": map[string]string{"ip": "203.0.113.25"}, "reply": map[string]any{"type": "IP", "time": 1},
			}},
			"cursor": 1, "recordsFiltered": piHoleV6MaxQueries + 1,
		})
	}))
	defer server.Close()

	queries, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("short time-window page failed because recordsFiltered was global: %v", err)
	}
	if len(queries) != 1 || queries[0].QueryID != 1 {
		t.Fatalf("queries = %+v", queries)
	}
}

func TestPiHoleV6EmptyWindowTerminatesDespiteGlobalRecordsFiltered(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		fmt.Fprint(w, `{"queries":[],"cursor":5000,"recordsFiltered":500000}`)
	}))
	defer server.Close()

	queries, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("empty time-window page: %v", err)
	}
	if len(queries) != 0 || requests.Load() != 1 {
		t.Fatalf("queries=%d requests=%d, want 0 and 1", len(queries), requests.Load())
	}
}

func TestPiHoleV6PaginatesWithCursor(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		request := requests.Add(1)
		if got := r.URL.Query().Get("length"); got != strconv.Itoa(piHoleV6PageSize) {
			t.Errorf("length = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request {
		case 1:
			if got := r.URL.Query().Get("cursor"); got != "" {
				t.Errorf("unexpected first cursor %q", got)
			}
			rows := make([]map[string]any, piHoleV6PageSize)
			for index := range rows {
				rows[index] = map[string]any{
					"id": index + 1, "time": 1752336000 + float64(index)/1000,
					"type": "A", "domain": fmt.Sprintf("page-one-%d.example", index), "status": "FORWARDED",
					"client": map[string]string{"ip": "203.0.113.25"},
					"reply":  map[string]any{"type": "IP", "time": 1},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"queries": rows, "cursor": 8000, "recordsFiltered": piHoleV6PageSize + 1,
			})
		case 2:
			if got := r.URL.Query().Get("cursor"); got != "8000" {
				t.Errorf("second cursor = %q", got)
			}
			if got := r.URL.Query().Get("start"); got != strconv.Itoa(piHoleV6PageSize) {
				t.Errorf("second start = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"queries": []map[string]any{{
					"id": 9001, "time": 1752335999.5, "type": "AAAA", "domain": "page-two.example", "status": "CACHE",
					"client": map[string]string{"ip": "203.0.113.26"},
					"reply":  map[string]any{"type": "IP", "time": 0.5},
				}},
				"cursor": 8000, "recordsFiltered": piHoleV6PageSize + 1,
			})
		default:
			t.Errorf("unexpected query request %d", request)
			_ = json.NewEncoder(w).Encode(map[string]any{"queries": []any{}})
		}
	}))
	defer server.Close()

	queries, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Unix(1752335940, 0), time.Unix(1752336060, 0))
	if err != nil {
		t.Fatalf("FetchQueries: %v", err)
	}
	if len(queries) != piHoleV6PageSize+1 || requests.Load() != 2 {
		t.Fatalf("queries=%d requests=%d", len(queries), requests.Load())
	}
	if queries[len(queries)-1].QueryID != 9001 {
		t.Fatalf("last query = %+v", queries[len(queries)-1])
	}
}

func TestPiHoleV6RejectsRepeatedPageInsteadOfLooping(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		request := requests.Add(1)
		if request == 1 {
			rows := make([]map[string]any, piHoleV6PageSize)
			for index := range rows {
				rows[index] = map[string]any{
					"id": index + 1, "time": 1752336000 + float64(index)/1000,
					"type": "A", "domain": fmt.Sprintf("progress-%d.example", index), "status": "FORWARDED",
					"client": map[string]string{"ip": "203.0.113.25"},
					"reply":  map[string]any{"type": "IP", "time": 1},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"queries": rows, "cursor": 9000, "recordsFiltered": 900000})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"queries": []map[string]any{{
			"id": 1, "time": 1752336000, "type": "A", "domain": "progress-0.example", "status": "FORWARDED",
			"client": map[string]string{"ip": "203.0.113.25"}, "reply": map[string]any{"type": "IP", "time": 1},
		}}, "cursor": 9000, "recordsFiltered": 900000})
	}))
	defer server.Close()

	_, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Unix(1752335940, 0), time.Unix(1752336060, 0))
	if err == nil || !strings.Contains(err.Error(), "repeated query ID") {
		t.Fatalf("zero-progress error = %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want bounded failure on second page", requests.Load())
	}
}

func TestPiHoleV6ActualRowBoundAndProbe(t *testing.T) {
	for _, test := range []struct {
		name     string
		overflow bool
	}{
		{name: "exactly max rows succeeds"},
		{name: "one row above max fails visibly", overflow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/queries" {
					http.NotFound(w, r)
					return
				}
				requests.Add(1)
				start, _ := strconv.Atoi(r.URL.Query().Get("start"))
				length, _ := strconv.Atoi(r.URL.Query().Get("length"))
				rowCount := length
				if start == piHoleV6MaxQueries {
					rowCount = 0
					if test.overflow {
						rowCount = 1
					}
				}
				rows := make([]map[string]any, rowCount)
				for index := range rows {
					id := start + index + 1
					rows[index] = map[string]any{
						"id": id, "time": 1752336000 + float64(id)/1000,
						"type": "A", "domain": fmt.Sprintf("bounded-%d.example", id), "status": "FORWARDED",
						"client": map[string]string{"ip": "203.0.113.25"},
						"reply":  map[string]any{"type": "IP", "time": 1},
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"queries": rows, "cursor": 20000, "recordsFiltered": 999999,
				})
			}))
			defer server.Close()

			queries, err := NewPiHoleClient(server.URL, "").FetchQueries(
				context.Background(), time.Unix(1752335940, 0), time.Unix(1752336060, 0))
			if test.overflow {
				if err == nil || !strings.Contains(err.Error(), "exceeds bounded maximum") {
					t.Fatalf("overflow error = %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("exact max query window: %v", err)
				}
				if len(queries) != piHoleV6MaxQueries {
					t.Fatalf("queries = %d, want %d", len(queries), piHoleV6MaxQueries)
				}
			}
			if requests.Load() != piHoleV6MaxQueries/piHoleV6PageSize+1 {
				t.Fatalf("requests = %d, want pages plus one-row probe", requests.Load())
			}
		})
	}
}

func TestPiHolePendingRowsHoldReplayWatermarkUntilFinalized(t *testing.T) {
	t.Parallel()
	const rowTime = 1752336000.25
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		request := requests.Add(1)
		statusOne, statusTwo := "IN_PROGRESS", "UNKNOWN"
		if request > 1 {
			statusOne, statusTwo = "FORWARDED", "CACHE"
			from, err := strconv.ParseFloat(r.URL.Query().Get("from"), 64)
			if err != nil || from > rowTime {
				t.Errorf("finalization poll starts at %q; pending row time is %.6f", r.URL.Query().Get("from"), rowTime)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"queries": []map[string]any{
			{"id": 7301, "time": rowTime, "type": "A", "domain": "pending-one.example", "status": statusOne, "client": map[string]string{"ip": "192.0.2.25"}, "reply": map[string]any{"type": "UNKNOWN", "time": -1}},
			{"id": 7302, "time": rowTime + 0.25, "type": "AAAA", "domain": "pending-two.example", "status": statusTwo, "client": map[string]string{"ip": "192.0.2.25"}, "reply": map[string]any{"type": "UNKNOWN", "time": -1}},
		}})
	}))
	defer server.Close()

	client := NewPiHoleClient(server.URL, "")
	initialFrom := time.Unix(1752335940, 0).UTC()
	initialTo := time.Unix(1752336060, 0).UTC()
	pending, err := client.FetchQueries(context.Background(), initialFrom, initialTo)
	if err != nil {
		t.Fatalf("pending FetchQueries: %v", err)
	}
	if len(pending) != 2 || !piHoleQueryPending(pending[0]) || !piHoleQueryPending(pending[1]) {
		t.Fatalf("mutable rows were not retained: %+v", pending)
	}
	if event := (&Poller{}).piHoleQueryToEvent(pending[0]); event != nil {
		t.Fatalf("pending row was persisted: %+v", event)
	}
	replayFrom := piHoleReplayWatermark(initialTo, pending)
	if replayFrom.After(piHoleQueryTime(pending[0])) {
		t.Fatalf("watermark %s skipped pending row at %s", replayFrom, piHoleQueryTime(pending[0]))
	}

	finalized, err := client.FetchQueries(context.Background(), replayFrom, initialTo.Add(time.Minute))
	if err != nil {
		t.Fatalf("finalized FetchQueries: %v", err)
	}
	if len(finalized) != 2 || piHoleQueryPending(finalized[0]) || piHoleQueryPending(finalized[1]) {
		t.Fatalf("finalized rows decoded incorrectly: %+v", finalized)
	}
	for index := range finalized {
		if piHoleEventID(finalized[index]) != piHoleEventID(pending[index]) {
			t.Fatalf("query %d changed stable ID across finalization", index)
		}
		if event := (&Poller{}).piHoleQueryToEvent(finalized[index]); event == nil {
			t.Fatalf("finalized query %d did not produce an event", index)
		}
	}
}

func TestPiHoleV6RejectsUnknownFinalStatusInsteadOfSilentlyDroppingIt(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/queries" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"queries":[{"id":7100,"time":1752336000.5,"type":"A","domain":"future-status.example","status":"NEW_FINAL_STATUS","client":{"ip":"192.0.2.25"},"reply":{"type":"IP","time":1}}]}`)
	}))
	defer server.Close()

	_, err := NewPiHoleClient(server.URL, "").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil || !strings.Contains(err.Error(), "unsupported query status") {
		t.Fatalf("unknown final status error = %v", err)
	}
}

func TestPiHoleBlockedStatuses(t *testing.T) {
	t.Parallel()
	blocked := map[int]bool{1: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 11: true, 15: true, 16: true, 18: true}
	for status := 0; status <= 18; status++ {
		query := PiHoleQuery{Status: status}
		if got := query.IsBlocked(); got != blocked[status] {
			t.Errorf("status %d blocked = %v, want %v", status, got, blocked[status])
		}
	}
}

func TestFormatPiHoleTimePreservesIntegerMicrosecondPrecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value time.Time
		want  string
	}{
		{
			name:  "epoch",
			value: time.Unix(0, 0),
			want:  "0.000000",
		},
		{
			name:  "current timestamp truncates sub-microsecond remainder",
			value: time.Unix(1752336000, 123456789),
			want:  "1752336000.123456",
		},
		{
			name:  "does not round across second boundary",
			value: time.Unix(1752336000, 999999999),
			want:  "1752336000.999999",
		},
		{
			name:  "does not depend on UnixNano range",
			value: time.Unix(253402300799, 999999999),
			want:  "253402300799.999999",
		},
		{
			name:  "negative half second",
			value: time.Unix(-1, 500000000),
			want:  "-0.500000",
		},
		{
			name:  "negative sub-microsecond floors to one microsecond",
			value: time.Unix(-1, 999999999),
			want:  "-0.000001",
		},
		{
			name:  "negative whole second",
			value: time.Unix(-2, 0),
			want:  "-2.000000",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := formatPiHoleTime(test.value); got != test.want {
				t.Fatalf("formatPiHoleTime(%s) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestPiHoleCredentialDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/credential", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, err := NewPiHoleClient(source.URL, "synthetic-app-password").FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil {
		t.Fatal("expected redirected auth endpoint to fail")
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("credential endpoint received %d redirected requests", redirectedRequests.Load())
	}
}

func TestPiHoleV5TransportErrorDoesNotLeakToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL + "/admin/api.php"
	server.Close()

	const markerValue = "synthetic-v5-sentinel-token"
	_, err := NewPiHoleClient(endpoint, markerValue).FetchQueries(
		context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil {
		t.Fatal("expected a transport error from the closed test server")
	}
	message := err.Error()
	if strings.Contains(message, markerValue) || strings.Contains(message, "auth=") {
		t.Fatalf("Pi-hole v5 token leaked in transport error: %q", message)
	}
}

func TestPiHoleV5HTTPErrorDoesNotLeakReflectedTokenOrURL(t *testing.T) {
	t.Parallel()
	const markerValue = "synthetic-v5-reflected-sentinel"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "upstream rejected %s containing auth=%s", r.URL.RequestURI(), markerValue)
	}))
	defer server.Close()

	client := NewPiHoleClient(server.URL+"/admin/api.php", markerValue)
	_, err := client.FetchQueries(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil {
		t.Fatal("expected non-200 v5 response to fail")
	}
	message := err.Error()
	if strings.Contains(message, markerValue) || strings.Contains(message, "auth=") || strings.Contains(message, "/admin/api.php") {
		t.Fatalf("Pi-hole v5 non-200 error leaked reflected request data: %q", message)
	}
	if !strings.Contains(message, "status 502") {
		t.Fatalf("sanitized error lost status: %q", message)
	}
}
