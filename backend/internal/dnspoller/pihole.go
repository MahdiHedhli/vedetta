package dnspoller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PiHoleQuery represents a single DNS query from Pi-hole's API response.
// It is the compatibility model shared by the Pi-hole v6 REST API and the v5
// getAllQueries endpoint.
type PiHoleQuery struct {
	Timestamp   float64 `json:"0"` // Unix timestamp, including v6 sub-second precision
	QueryType   string  `json:"1"` // A, AAAA, CNAME, MX, TXT, etc.
	Domain      string  `json:"2"` // Queried domain
	ClientIP    string  `json:"3"` // Client IP address
	Status      int     `json:"4"` // Pi-hole database status code
	StatusName  string  `json:"-"` // Pi-hole v6 status name (for source evidence)
	DNSSEC      int     `json:"5"` // DNSSEC status
	DNSSECName  string  `json:"-"`
	ReplyType   int     `json:"6"` // Reply type
	ReplyName   string  `json:"-"`
	ReplyTime   float64 `json:"7"` // Reply time in ms
	CNAMETarget string  `json:"8"` // CNAME target if applicable
	RegexID     string  `json:"9"` // Regex ID if blocked by regex
	QueryID     int64   `json:"-"` // Stable v6 long-term query ID
	// Occurrence distinguishes byte-identical queries that Pi-hole reports in
	// the same timestamp. v6 QueryID is stronger; this remains the v5 fallback.
	Occurrence int `json:"-"`
}

// PiHoleResponse is the JSON response structure from getAllQueries.
type PiHoleResponse struct {
	Data [][]interface{} `json:"data"`
}

type piHoleV6Response struct {
	Queries []piHoleV6Query `json:"queries"`
	Cursor  int64           `json:"cursor"`
}

type piHoleV6Query struct {
	ID     int64   `json:"id"`
	Time   float64 `json:"time"`
	Type   string  `json:"type"`
	Domain string  `json:"domain"`
	CNAME  *string `json:"cname"`
	Status string  `json:"status"`
	Client struct {
		IP string `json:"ip"`
	} `json:"client"`
	DNSSEC string `json:"dnssec"`
	Reply  struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
}

type piHoleV6AuthResponse struct {
	Session struct {
		Valid    bool   `json:"valid"`
		SID      string `json:"sid"`
		Validity int    `json:"validity"`
	} `json:"session"`
}

type piHoleAPIMode uint8

const (
	piHoleModeAuto piHoleAPIMode = iota
	piHoleModeV6
	piHoleModeV5

	// Pi-hole v6 itself caps /api/queries at 10,000 rows. Fetch it in bounded
	// pages so ordinary bursts are not silently truncated while a peer still
	// cannot force an unbounded allocation on Core.
	piHoleV6PageSize   = 1000
	piHoleV6MaxQueries = 10000
	piHoleV5MaxQueries = 10000
)

var (
	errPiHoleV6Unavailable  = errors.New("pihole v6 API unavailable")
	errPiHoleV6Unauthorized = errors.New("pihole v6 session unauthorized")
)

// PiHoleClient wraps the Pi-hole API.
type PiHoleClient struct {
	baseURL    string
	credential string
	client     *http.Client

	mu       sync.Mutex
	mode     piHoleAPIMode
	sid      string
	noAuthV6 bool
}

// NewPiHoleClient creates a new Pi-hole API client.
func NewPiHoleClient(baseURL, token string) *PiHoleClient {
	return &PiHoleClient{
		baseURL:    strings.TrimSpace(baseURL),
		credential: token,
		client:     newPollerHTTPClient(),
	}
}

// FetchQueries retrieves DNS queries from Pi-hole for the given time range.
func (c *PiHoleClient) FetchQueries(ctx context.Context, from, to time.Time) ([]PiHoleQuery, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("pihole: missing baseURL")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mode != piHoleModeV5 && !isExplicitPiHoleV5URL(c.baseURL) {
		queries, err := c.fetchV6(ctx, from, to)
		if err == nil {
			c.mode = piHoleModeV6
			return queries, nil
		}
		if c.mode == piHoleModeV6 || !errors.Is(err, errPiHoleV6Unavailable) {
			return nil, err
		}
	}

	queries, err := c.fetchV5(ctx, from, to)
	if err != nil {
		return nil, err
	}
	c.mode = piHoleModeV5
	return queries, nil
}

// Close releases a Pi-hole v6 session so rapid Core restarts do not consume the
// server's bounded session slots until idle expiry. Legacy v5 has no session.
func (c *PiHoleClient) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != piHoleModeV6 || c.sid == "" {
		return nil
	}
	authURL, err := c.v6URL("/auth")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, authURL, nil)
	if err != nil {
		return fmt.Errorf("pihole v6: create logout request: %w", err)
	}
	req.Header.Set("X-FTL-SID", c.sid)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pihole v6: logout: %w", err)
	}
	defer resp.Body.Close()
	c.sid = ""
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		return nil
	}
	return fmt.Errorf("pihole v6: logout status %d: %s", resp.StatusCode, readBoundedErrorBody(resp.Body))
}

func (c *PiHoleClient) fetchV6(ctx context.Context, from, to time.Time) ([]PiHoleQuery, error) {
	if err := c.ensureV6Session(ctx); err != nil {
		return nil, err
	}
	queries, err := c.fetchV6WithSession(ctx, from, to)
	if !errors.Is(err, errPiHoleV6Unauthorized) {
		return queries, err
	}

	// Sessions expire and are invalidated when Pi-hole credentials change. Clear
	// the cached SID and perform exactly one bounded re-authentication attempt.
	c.sid = ""
	c.noAuthV6 = false
	if err := c.ensureV6Session(ctx); err != nil {
		return nil, err
	}
	queries, err = c.fetchV6WithSession(ctx, from, to)
	if errors.Is(err, errPiHoleV6Unauthorized) && c.credential == "" {
		return nil, fmt.Errorf("pihole v6: authentication required but VEDETTA_PIHOLE_TOKEN is empty")
	}
	return queries, err
}

func (c *PiHoleClient) ensureV6Session(ctx context.Context) error {
	if c.sid != "" || c.noAuthV6 {
		return nil
	}

	// Pi-hole documents POST /api/auth for session creation. An installation
	// without a password permits direct API access, so it needs no auth probe.
	// Avoid relying on an undocumented GET method that may return 405 and make a
	// healthy v6 installation look like legacy v5.
	if c.credential == "" {
		c.noAuthV6 = true
		return nil
	}

	authURL, err := c.v6URL("/auth")
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{"password": c.credential})
	if err != nil {
		return fmt.Errorf("pihole v6: encode auth request: %w", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("pihole v6: create auth request: %w", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := c.client.Do(postReq)
	if err != nil {
		return fmt.Errorf("pihole v6: authenticate: %w", err)
	}
	if postResp.StatusCode == http.StatusNotFound || postResp.StatusCode == http.StatusMethodNotAllowed {
		postResp.Body.Close()
		return errPiHoleV6Unavailable
	}
	if postResp.StatusCode != http.StatusOK {
		body := readBoundedErrorBody(postResp.Body)
		postResp.Body.Close()
		return fmt.Errorf("pihole v6: authentication status %d: %s", postResp.StatusCode, body)
	}
	auth, err := decodePiHoleV6Auth(postResp)
	if err != nil {
		return err
	}
	if !auth.Session.Valid {
		return fmt.Errorf("pihole v6: authentication returned an invalid session")
	}
	c.sid = auth.Session.SID
	c.noAuthV6 = auth.Session.SID == ""
	return nil
}

func decodePiHoleV6Auth(resp *http.Response) (piHoleV6AuthResponse, error) {
	defer resp.Body.Close()
	var auth piHoleV6AuthResponse
	body, err := readBoundedBody(resp.Body, pollerMaxResponseBytes)
	if err != nil {
		return auth, fmt.Errorf("pihole v6: read auth response: %w", err)
	}
	if err := json.Unmarshal(body, &auth); err != nil {
		return auth, fmt.Errorf("pihole v6: decode auth response: %w", err)
	}
	return auth, nil
}

func (c *PiHoleClient) fetchV6WithSession(ctx context.Context, from, to time.Time) ([]PiHoleQuery, error) {
	endpoint, err := c.v6URL("/queries")
	if err != nil {
		return nil, err
	}

	rows := make([]piHoleV6Query, 0, piHoleV6PageSize)
	seenQueryIDs := make(map[int64]struct{})
	// Pi-hole's cursor freezes the newest database ID for a stable snapshot;
	// subsequent pages reuse that cursor and advance the server-side start offset.
	var snapshotCursor int64
	for {
		page, err := c.fetchV6Page(ctx, endpoint, from, to, snapshotCursor, len(rows), piHoleV6PageSize)
		if err != nil {
			return nil, err
		}
		if snapshotCursor == 0 && len(rows) == 0 {
			snapshotCursor = page.Cursor
		} else if page.Cursor != 0 && page.Cursor != snapshotCursor {
			return nil, fmt.Errorf("pihole v6: query snapshot cursor changed during pagination")
		}
		if len(rows)+len(page.Queries) > piHoleV6MaxQueries {
			return nil, fmt.Errorf("pihole v6: query window exceeds bounded maximum of %d rows", piHoleV6MaxQueries)
		}
		for _, query := range page.Queries {
			if query.ID == 0 {
				continue
			}
			if _, duplicate := seenQueryIDs[query.ID]; duplicate {
				return nil, fmt.Errorf("pihole v6: pagination repeated query ID %d", query.ID)
			}
			seenQueryIDs[query.ID] = struct{}{}
		}
		rows = append(rows, page.Queries...)

		// Pi-hole's recordsFiltered is not a reliable count for this from/until
		// window (some FTL versions report a global query-history total). Page
		// fullness is the only completion signal that is scoped to this request.
		if len(page.Queries) < piHoleV6PageSize {
			break
		}
		if len(rows) == piHoleV6MaxQueries {
			// A full page at exactly the cap is ambiguous. Perform a one-row
			// bounded probe using the same frozen snapshot: an empty page means the
			// window contains exactly the cap, while any row makes overflow visible.
			probe, err := c.fetchV6Page(ctx, endpoint, from, to, snapshotCursor, len(rows), 1)
			if err != nil {
				return nil, err
			}
			if probe.Cursor != 0 && probe.Cursor != snapshotCursor {
				return nil, fmt.Errorf("pihole v6: query snapshot cursor changed during pagination")
			}
			if len(probe.Queries) > 0 {
				return nil, fmt.Errorf("pihole v6: query window exceeds bounded maximum of %d rows", piHoleV6MaxQueries)
			}
			break
		}
		if snapshotCursor == 0 {
			return nil, fmt.Errorf("pihole v6: incomplete query page missing cursor")
		}
	}

	queries := make([]PiHoleQuery, 0, len(rows))
	wellFormedRows := 0
	for _, row := range rows {
		if row.Time <= 0 || strings.TrimSpace(row.Domain) == "" || strings.TrimSpace(row.Client.IP) == "" {
			continue
		}
		wellFormedRows++
		statusName := strings.ToUpper(strings.TrimSpace(row.Status))
		statusCode := piHoleStatusCode(statusName)
		if statusName != "UNKNOWN" && statusCode == 0 {
			return nil, fmt.Errorf("pihole v6: unsupported query status %q", row.Status)
		}
		q := PiHoleQuery{
			Timestamp: row.Time, QueryID: row.ID,
			QueryType: row.Type, Domain: row.Domain, ClientIP: row.Client.IP,
			Status: statusCode, StatusName: statusName,
			DNSSEC: piHoleDNSSECCode(row.DNSSEC), DNSSECName: strings.ToUpper(strings.TrimSpace(row.DNSSEC)),
			ReplyType: piHoleReplyCode(row.Reply.Type), ReplyName: strings.ToUpper(strings.TrimSpace(row.Reply.Type)),
			ReplyTime: row.Reply.Time,
		}
		if row.CNAME != nil {
			q.CNAMETarget = *row.CNAME
		}
		// Retain mutable UNKNOWN/IN_PROGRESS rows for the poller's watermark.
		// They are not persisted, but keeping their timestamp eligible ensures the
		// same stable v6 QueryID is ingested after Pi-hole finalizes the record.
		queries = append(queries, q)
	}
	if len(rows) > 0 && wellFormedRows == 0 {
		return nil, fmt.Errorf("pihole v6: response contained no valid query rows")
	}
	assignPiHoleOccurrences(queries)
	return queries, nil
}

func (c *PiHoleClient) fetchV6Page(ctx context.Context, endpoint string, from, to time.Time, cursor int64, start, length int) (piHoleV6Response, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: parse queries URL: %w", err)
	}
	params := parsed.Query()
	params.Set("from", formatPiHoleTime(from))
	params.Set("until", formatPiHoleTime(to))
	if length <= 0 || length > piHoleV6PageSize {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: invalid query page length %d", length)
	}
	params.Set("length", fmt.Sprintf("%d", length))
	if cursor != 0 {
		params.Set("cursor", fmt.Sprintf("%d", cursor))
	}
	if start > 0 {
		params.Set("start", fmt.Sprintf("%d", start))
	}
	parsed.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: create queries request: %w", err)
	}
	if c.sid != "" {
		req.Header.Set("X-FTL-SID", c.sid)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: fetch queries: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return piHoleV6Response{}, errPiHoleV6Unauthorized
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return piHoleV6Response{}, errPiHoleV6Unavailable
	}
	if resp.StatusCode != http.StatusOK {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: status %d: %s", resp.StatusCode, readBoundedErrorBody(resp.Body))
	}
	body, err := readBoundedBody(resp.Body, pollerMaxResponseBytes)
	if err != nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: read queries response: %w", err)
	}
	var source piHoleV6Response
	if err := json.Unmarshal(body, &source); err != nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: decode queries response: %w", err)
	}
	if source.Queries == nil {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: response missing queries array")
	}
	if len(source.Queries) > length {
		return piHoleV6Response{}, fmt.Errorf("pihole v6: response contains %d queries, page limit is %d", len(source.Queries), length)
	}
	return source, nil
}

func (c *PiHoleClient) fetchV5(ctx context.Context, from, to time.Time) ([]PiHoleQuery, error) {
	endpoint, err := c.v5URL()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("getAllQueries", "")
	params.Set("from", fmt.Sprintf("%d", from.Unix()))
	params.Set("to", fmt.Sprintf("%d", to.Unix()))
	if c.credential != "" {
		params.Set("auth", c.credential)
	}
	fullURL := endpoint + "?" + params.Encode()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pihole: create request: %w", err)
	}

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pihole v5: fetch queries: %w", redactRequestError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The legacy endpoint carries its static token in ?auth=. Some proxies
		// reflect the request URI in error bodies, so never include a v5 response
		// body in an error that reaches activity/container logs.
		return nil, fmt.Errorf("pihole v5: status %d", resp.StatusCode)
	}

	body, err := readBoundedBody(resp.Body, pollerMaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("pihole v5: read response: %w", err)
	}
	var phr PiHoleResponse
	if err := json.Unmarshal(body, &phr); err != nil {
		return nil, fmt.Errorf("pihole v5: decode response: %w", err)
	}
	if phr.Data == nil {
		return nil, fmt.Errorf("pihole v5: response missing data array")
	}
	if len(phr.Data) > piHoleV5MaxQueries {
		return nil, fmt.Errorf("pihole v5: response contains %d queries, limit is %d", len(phr.Data), piHoleV5MaxQueries)
	}

	// Convert raw array data to PiHoleQuery objects
	queries := make([]PiHoleQuery, 0, len(phr.Data))
	wellFormedRows := 0
	for _, row := range phr.Data {
		if len(row) < 10 {
			continue // skip malformed rows
		}

		// Parse each field from the raw array
		q := PiHoleQuery{}

		// 0: timestamp (int64)
		if ts, ok := row[0].(float64); ok {
			q.Timestamp = ts
		}

		// 1: query_type (string)
		if qt, ok := row[1].(string); ok {
			q.QueryType = qt
		}

		// 2: domain (string)
		if d, ok := row[2].(string); ok {
			q.Domain = d
		}

		// 3: client_ip (string)
		if ip, ok := row[3].(string); ok {
			q.ClientIP = ip
		}

		// 4: status (int)
		if st, ok := row[4].(float64); ok {
			q.Status = int(st)
		}

		// 5: dnssec (int)
		if ds, ok := row[5].(float64); ok {
			q.DNSSEC = int(ds)
		}

		// 6: reply_type (int)
		if rt, ok := row[6].(float64); ok {
			q.ReplyType = int(rt)
		}

		// 7: reply_time (int)
		if replytime, ok := row[7].(float64); ok {
			q.ReplyTime = replytime
		}

		// 8: cname_target (string)
		if ct, ok := row[8].(string); ok {
			q.CNAMETarget = ct
		}

		// 9: regex_id (string)
		if rid, ok := row[9].(string); ok {
			q.RegexID = rid
		}

		if q.Timestamp <= 0 || strings.TrimSpace(q.Domain) == "" || strings.TrimSpace(q.ClientIP) == "" {
			continue
		}
		wellFormedRows++
		// Retain mutable UNKNOWN/IN_PROGRESS rows so the poller can hold its
		// replay watermark until the source either finalizes or removes them.
		queries = append(queries, q)
	}
	if len(phr.Data) > 0 && wellFormedRows == 0 {
		return nil, fmt.Errorf("pihole v5: response contained no valid query rows")
	}
	assignPiHoleOccurrences(queries)

	return queries, nil
}

func assignPiHoleOccurrences(queries []PiHoleQuery) {
	occurrences := make(map[string]int, len(queries))
	for index := range queries {
		baseID := piHoleEventID(queries[index])
		queries[index].Occurrence = occurrences[baseID]
		occurrences[baseID]++
	}
}

func formatPiHoleTime(value time.Time) string {
	seconds := value.Unix()
	microseconds := int64(value.Nanosecond()) / int64(time.Microsecond)
	if seconds >= 0 || microseconds == 0 {
		return fmt.Sprintf("%d.%06d", seconds, microseconds)
	}

	// Unix returns the floor for pre-epoch instants while Nanosecond returns a
	// positive offset within that second. Format the mathematical timestamp,
	// rather than producing (for example) -1.500000 for Unix -0.5 seconds.
	return fmt.Sprintf("-%d.%06d", -(seconds + 1), int64(time.Second/time.Microsecond)-microseconds)
}

func isExplicitPiHoleV5URL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.TrimRight(parsed.Path, "/"))
	return strings.HasSuffix(path, "/api.php")
}

func (c *PiHoleClient) v6URL(endpoint string) (string, error) {
	parsed, err := parsePiHoleBaseURL(c.baseURL)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(strings.ToLower(basePath), "/api") {
		basePath += "/api"
	}
	parsed.Path = basePath + endpoint
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (c *PiHoleClient) v5URL() (string, error) {
	parsed, err := parsePiHoleBaseURL(c.baseURL)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(parsed.Path, "/")
	lowerPath := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lowerPath, "/api.php"):
		// The caller supplied the complete legacy endpoint.
	case strings.HasSuffix(lowerPath, "/admin"):
		path += "/api.php"
	default:
		path += "/admin/api.php"
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func parsePiHoleBaseURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("pihole: parse base URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("pihole: base URL must be an absolute http(s) URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("pihole: credentials must not be embedded in the base URL")
	}
	return parsed, nil
}

func piHoleStatusCode(status string) int {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "UNKNOWN":
		return 0
	case "GRAVITY":
		return 1
	case "FORWARDED":
		return 2
	case "CACHE":
		return 3
	case "REGEX":
		return 4
	case "DENYLIST":
		return 5
	case "EXTERNAL_BLOCKED_IP":
		return 6
	case "EXTERNAL_BLOCKED_NULL":
		return 7
	case "EXTERNAL_BLOCKED_NXRA":
		return 8
	case "GRAVITY_CNAME":
		return 9
	case "REGEX_CNAME":
		return 10
	case "DENYLIST_CNAME":
		return 11
	case "RETRIED":
		return 12
	case "RETRIED_DNSSEC":
		return 13
	case "IN_PROGRESS":
		return 14
	case "DBBUSY":
		return 15
	case "SPECIAL_DOMAIN":
		return 16
	case "CACHE_STALE":
		return 17
	case "EXTERNAL_BLOCKED_EDE15":
		return 18
	default:
		return 0
	}
}

func piHoleDNSSECCode(status string) int {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SECURE":
		return 1
	case "INSECURE":
		return 2
	case "BOGUS":
		return 3
	case "ABANDONED":
		return 4
	case "TRUNCATED":
		return 5
	default:
		return 0
	}
}

func piHoleReplyCode(reply string) int {
	switch strings.ToUpper(strings.TrimSpace(reply)) {
	case "NODATA":
		return 1
	case "NXDOMAIN":
		return 2
	case "CNAME":
		return 3
	case "IP":
		return 4
	case "DOMAIN":
		return 5
	case "RRNAME":
		return 6
	case "SERVFAIL":
		return 7
	case "REFUSED":
		return 8
	case "NOTIMP":
		return 9
	case "OTHER":
		return 10
	case "DNSSEC":
		return 11
	case "NONE":
		return 12
	case "BLOB":
		return 13
	default:
		return 0
	}
}

// IsBlocked returns true if the Pi-hole status code indicates the query was blocked.
func (q *PiHoleQuery) IsBlocked() bool {
	// Pi-hole documents these as blocked across gravity, deny/regex, CNAME,
	// upstream blocking, database-busy, special-domain, and EDE 15 outcomes.
	switch q.Status {
	case 1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18:
		return true
	default:
		return false
	}
}
