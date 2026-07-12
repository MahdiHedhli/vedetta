package corereader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client reads events from Core's HTTP events API. It authenticates with a Core
// bearer token and NEVER touches Core's SQLite file directly.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClient builds a Core client with a sane default HTTP timeout.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// EffectiveOptIn asks Core for the EFFECTIVE telemetry opt-in via
// GET /api/v1/settings/telemetry, using the same read token as event reads. The
// response shape is {"opt_in":bool,"source":"setting"|"env","effective":bool};
// the daemon acts on `effective`. Any transport/status/decode error is returned
// so the caller can FAIL CLOSED: the opt-in cannot be confirmed live, so the
// caller must suppress this tick (spool only, never drain/export) rather than
// trust a stale cached "on" that a fresh admin opt-out may have superseded
// (GHSA-c776).
func (c *Client) EffectiveOptIn(ctx context.Context) (bool, error) {
	reqURL := c.BaseURL + "/api/v1/settings/telemetry"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("core telemetry setting request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("core telemetry setting unexpected status: %s", resp.Status)
	}
	var body struct {
		Effective bool `json:"effective"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("decode core telemetry setting: %w", err)
	}
	return body.Effective, nil
}

// FetchPageResult is the outcome of reading one page of events.
type FetchPageResult struct {
	Events           []Event
	Received         int
	Total            int
	Page             int
	Limit            int
	SkippedMalformed int
}

// FetchPage reads one page of events from Core after the given cursor time,
// using the real events API params: from / limit / page / sort=timestamp /
// order=asc. Events at exactly the cursor time are filtered client-side by the
// caller via the cursor tie-breaker; the server `from` is inclusive.
func (c *Client) FetchPage(ctx context.Context, from time.Time, page, limit int) (*FetchPageResult, error) {
	q := url.Values{}
	if !from.IsZero() {
		q.Set("from", from.UTC().Format(time.RFC3339Nano))
	}
	q.Set("sort", "timestamp")
	q.Set("order", "asc")
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(limit))

	reqURL := c.BaseURL + "/api/v1/events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core events request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("core events auth failed: %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("core events unexpected status: %s", resp.Status)
	}

	// Decode leniently: a malformed individual event should be skipped and
	// counted, not crash the tick. We decode the page envelope, then re-validate
	// each event by round-tripping through json.RawMessage.
	var raw struct {
		Events []json.RawMessage `json:"events"`
		Total  int               `json:"total"`
		Page   int               `json:"page"`
		Limit  int               `json:"limit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode core events page: %w", err)
	}

	out := &FetchPageResult{Received: len(raw.Events), Total: raw.Total, Page: raw.Page, Limit: raw.Limit}
	for _, rm := range raw.Events {
		var ev Event
		if err := json.Unmarshal(rm, &ev); err != nil || ev.EventID == "" || ev.Timestamp.IsZero() {
			out.SkippedMalformed++
			continue
		}
		out.Events = append(out.Events, ev)
	}
	return out, nil
}
