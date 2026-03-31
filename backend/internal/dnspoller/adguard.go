package dnspoller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// AdGuardQuery represents a single DNS query from AdGuard Home's API response.
type AdGuardQuery struct {
	Answer         []AdGuardAnswer `json:"answer"`
	OriginalAnswer []AdGuardAnswer `json:"original_answer"`
	Upstream       string          `json:"upstream"`
	Time           time.Time       `json:"time"`
	ElapsedMs      string          `json:"elapsed_ms"`
	Client         string          `json:"client"`
	ClientID       string          `json:"client_id"`
	ClientInfo     AdGuardClient   `json:"client_info"`
	Rules          []string        `json:"rules"`
	Reason         string          `json:"reason"`
	FilterID       int             `json:"filterId"`
	Question       AdGuardQuestion `json:"question"`
}

// AdGuardAnswer represents a single answer in the response.
type AdGuardAnswer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// AdGuardClient represents client info from the response.
type AdGuardClient struct {
	Name string `json:"name"`
}

// AdGuardQuestion represents the query question.
type AdGuardQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// AdGuardResponse is the JSON response structure from /control/querylog.
type AdGuardResponse struct {
	Data   []AdGuardQuery `json:"data"`
	Oldest string         `json:"oldest"`
}

// AdGuardHTTPClient wraps the AdGuard Home API.
type AdGuardHTTPClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewAdGuardHTTPClient creates a new AdGuard Home API client.
func NewAdGuardHTTPClient(baseURL, username, password string) *AdGuardHTTPClient {
	return &AdGuardHTTPClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FetchQueries retrieves DNS queries from AdGuard Home.
func (c *AdGuardHTTPClient) FetchQueries(ctx context.Context, limit int) ([]AdGuardQuery, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("adguard: missing baseURL")
	}

	if limit <= 0 {
		limit = 100
	}

	// Build query parameters
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", "0")
	params.Set("search", "")
	params.Set("response_status", "all")

	fullURL := fmt.Sprintf("%s/control/querylog?%s", c.baseURL, params.Encode())

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("adguard: create request: %w", err)
	}

	// Add HTTP Basic Auth if credentials are provided
	if c.username != "" || c.password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("adguard: fetch queries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("adguard: status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var agr AdGuardResponse
	if err := json.NewDecoder(resp.Body).Decode(&agr); err != nil {
		return nil, fmt.Errorf("adguard: decode response: %w", err)
	}

	return agr.Data, nil
}

// IsBlocked returns true if the AdGuard query was blocked.
// Blocked reasons: FilteredBlackList, FilteredSafeBrowsing, FilteredParental,
// FilteredSafeSearch, FilteredBlockedService
func (q *AdGuardQuery) IsBlocked() bool {
	switch q.Reason {
	case "FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
		"FilteredSafeSearch", "FilteredBlockedService":
		return true
	default:
		return false
	}
}
