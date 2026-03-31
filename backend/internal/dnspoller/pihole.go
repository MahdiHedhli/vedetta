package dnspoller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// PiHoleQuery represents a single DNS query from Pi-hole's API response.
// Format from getAllQueries: [timestamp, query_type, domain, client_ip, status, dnssec, reply_type, reply_time, cname_target, regex_id]
type PiHoleQuery struct {
	Timestamp    int64  `json:"0"` // Unix timestamp
	QueryType    string `json:"1"` // A, AAAA, CNAME, MX, TXT, etc.
	Domain       string `json:"2"` // Queried domain
	ClientIP     string `json:"3"` // Client IP address
	Status       int    `json:"4"` // Pi-hole status code (1=gravity, 2=forwarded, 3=cached, 4=regex, 5=denylist, 6=external)
	DNSSEC       int    `json:"5"` // DNSSEC status
	ReplyType    int    `json:"6"` // Reply type
	ReplyTime    int    `json:"7"` // Reply time in ms
	CNAMETarget  string `json:"8"` // CNAME target if applicable
	RegexID      string `json:"9"` // Regex ID if blocked by regex
}

// PiHoleResponse is the JSON response structure from getAllQueries.
type PiHoleResponse struct {
	Data [][]interface{} `json:"data"`
}

// PiHoleClient wraps the Pi-hole API.
type PiHoleClient struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewPiHoleClient creates a new Pi-hole API client.
func NewPiHoleClient(baseURL, token string) *PiHoleClient {
	return &PiHoleClient{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FetchQueries retrieves DNS queries from Pi-hole for the given time range.
func (c *PiHoleClient) FetchQueries(ctx context.Context, from, to time.Time) ([]PiHoleQuery, error) {
	if c.baseURL == "" || c.token == "" {
		return nil, fmt.Errorf("pihole: missing baseURL or token")
	}

	// Build query string
	params := url.Values{}
	params.Set("getAllQueries", "")
	params.Set("from", fmt.Sprintf("%d", from.Unix()))
	params.Set("to", fmt.Sprintf("%d", to.Unix()))
	params.Set("auth", c.token)

	fullURL := fmt.Sprintf("%s/admin/api.php?%s", c.baseURL, params.Encode())

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pihole: create request: %w", err)
	}

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pihole: fetch queries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pihole: status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var phr PiHoleResponse
	if err := json.NewDecoder(resp.Body).Decode(&phr); err != nil {
		return nil, fmt.Errorf("pihole: decode response: %w", err)
	}

	// Convert raw array data to PiHoleQuery objects
	var queries []PiHoleQuery
	for _, row := range phr.Data {
		if len(row) < 10 {
			continue // skip malformed rows
		}

		// Parse each field from the raw array
		q := PiHoleQuery{}

		// 0: timestamp (int64)
		if ts, ok := row[0].(float64); ok {
			q.Timestamp = int64(ts)
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
			q.ReplyTime = int(replytime)
		}

		// 8: cname_target (string)
		if ct, ok := row[8].(string); ok {
			q.CNAMETarget = ct
		}

		// 9: regex_id (string)
		if rid, ok := row[9].(string); ok {
			q.RegexID = rid
		}

		queries = append(queries, q)
	}

	return queries, nil
}

// IsBlocked returns true if the Pi-hole status code indicates the query was blocked.
func (q *PiHoleQuery) IsBlocked() bool {
	// Status codes: 1=gravity, 4=regex, 5=denylist, 6=external (all blocked)
	return q.Status == 1 || q.Status == 4 || q.Status == 5 || q.Status == 6
}
