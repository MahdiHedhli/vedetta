package dnspoller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// AdGuard recommends older_than cursor pagination for query-log traversal.
	// Keep each response small while bounding the complete poll cycle so a peer
	// cannot force an unbounded allocation on Core.
	adGuardPageSize   = 100
	adGuardMaxQueries = 1000
)

// AdGuardRule is the current AdGuard Home ResultRule wire shape. Older AdGuard
// releases returned rule text as a bare string, so UnmarshalJSON accepts both
// representations while normalizing them into one evidence-preserving model.
type AdGuardRule struct {
	FilterListID int64  `json:"filter_list_id,omitempty"`
	Text         string `json:"text,omitempty"`
}

func (r *AdGuardRule) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		r.Text = text
		r.FilterListID = 0
		return nil
	}

	type ruleWire AdGuardRule
	var decoded ruleWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("adguard: decode result rule: %w", err)
	}
	*r = AdGuardRule(decoded)
	return nil
}

// AdGuardQuery represents a single DNS query from AdGuard Home's API response.
type AdGuardQuery struct {
	Answer          []AdGuardAnswer `json:"answer"`
	OriginalAnswer  []AdGuardAnswer `json:"original_answer"`
	Upstream        string          `json:"upstream"`
	Time            time.Time       `json:"time"`
	ElapsedMs       string          `json:"elapsedMs"`
	LegacyElapsedMs string          `json:"elapsed_ms,omitempty"` // Older adapter/API spelling.
	Client          string          `json:"client"`
	ClientID        string          `json:"client_id"`
	ClientInfo      AdGuardClient   `json:"client_info"`
	Rules           []AdGuardRule   `json:"rules"`
	Rule            string          `json:"rule"` // Deprecated single-rule text.
	Reason          string          `json:"reason"`
	FilterID        int             `json:"filterId"`
	Question        AdGuardQuestion `json:"question"`
	// Occurrence distinguishes otherwise-identical rows in one querylog snapshot.
	Occurrence int `json:"-"`
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

// adGuardQueryBatch is one bounded unit of query-log traversal. Complete means
// the retained log ended before the limit; otherwise NextCursor resumes at the
// next older row on a later poll. Keeping the continuation explicit lets Core
// drain a burst over several polls without allocating the entire retained log
// or mistaking normal history beyond the cycle limit for an outage.
type adGuardQueryBatch struct {
	Queries    []AdGuardQuery
	NextCursor string
	Complete   bool
}

// NewAdGuardHTTPClient creates a new AdGuard Home API client.
func NewAdGuardHTTPClient(baseURL, username, password string) *AdGuardHTTPClient {
	return &AdGuardHTTPClient{
		baseURL:    baseURL,
		username:   username,
		password:   password,
		httpClient: newPollerHTTPClient(),
	}
}

// FetchQueries retrieves DNS queries from AdGuard Home.
func (c *AdGuardHTTPClient) FetchQueries(ctx context.Context, limit int) ([]AdGuardQuery, error) {
	batch, err := c.fetchQueryBatch(ctx, limit, "")
	if err != nil {
		return nil, err
	}
	return batch.Queries, nil
}

func (c *AdGuardHTTPClient) fetchQueryBatch(ctx context.Context, limit int, startCursor string) (adGuardQueryBatch, error) {
	if c.baseURL == "" {
		return adGuardQueryBatch{}, fmt.Errorf("adguard: missing baseURL")
	}
	base, err := url.Parse(strings.TrimSpace(c.baseURL))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return adGuardQueryBatch{}, fmt.Errorf("adguard: base URL must be an absolute http(s) URL")
	}
	if base.User != nil {
		return adGuardQueryBatch{}, fmt.Errorf("adguard: credentials must not be embedded in the base URL")
	}

	if limit <= 0 {
		limit = 100
	}
	if limit > adGuardMaxQueries {
		return adGuardQueryBatch{}, fmt.Errorf("adguard: requested limit %d exceeds maximum %d", limit, adGuardMaxQueries)
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/control/querylog"
	base.RawPath = ""
	base.Fragment = ""

	queries := make([]AdGuardQuery, 0, min(limit, adGuardPageSize))
	olderThan := strings.TrimSpace(startCursor)
	seenCursors := make(map[string]struct{})
	if olderThan != "" {
		seenCursors[olderThan] = struct{}{}
	}
	complete := false
	for len(queries) < limit {
		pageLimit := min(adGuardPageSize, limit-len(queries))
		page, err := c.fetchQueryPage(ctx, base, pageLimit, olderThan)
		if err != nil {
			return adGuardQueryBatch{}, err
		}
		queries = append(queries, page.Data...)

		if len(page.Data) < pageLimit {
			complete = true
			break
		}
		if page.Oldest == "" {
			// AdGuard uses an empty oldest value as the terminal marker, including
			// when the retained row count is an exact multiple of the page size.
			complete = true
			break
		}
		if _, duplicate := seenCursors[page.Oldest]; duplicate {
			return adGuardQueryBatch{}, fmt.Errorf("adguard: query-log cursor did not advance")
		}
		seenCursors[page.Oldest] = struct{}{}
		olderThan = page.Oldest
	}

	occurrences := map[string]int{}
	for index := range queries {
		baseID := adGuardEventID(queries[index])
		queries[index].Occurrence = occurrences[baseID]
		occurrences[baseID]++
	}

	return adGuardQueryBatch{
		Queries:    queries,
		NextCursor: olderThan,
		Complete:   complete,
	}, nil
}

func (c *AdGuardHTTPClient) fetchQueryPage(ctx context.Context, base *url.URL, limit int, olderThan string) (AdGuardResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("search", "")
	params.Set("response_status", "all")
	if olderThan != "" {
		params.Set("older_than", olderThan)
	}
	pageURL := *base
	pageURL.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return AdGuardResponse{}, fmt.Errorf("adguard: create request: %w", err)
	}
	if c.username != "" || c.password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AdGuardResponse{}, fmt.Errorf("adguard: fetch queries: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return AdGuardResponse{}, fmt.Errorf("adguard: status %d: %s", resp.StatusCode, readBoundedErrorBody(resp.Body))
	}
	body, err := readBoundedBody(resp.Body, pollerMaxResponseBytes)
	if err != nil {
		return AdGuardResponse{}, fmt.Errorf("adguard: read response: %w", err)
	}
	var page AdGuardResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return AdGuardResponse{}, fmt.Errorf("adguard: decode response: %w", err)
	}
	if page.Data == nil {
		return AdGuardResponse{}, fmt.Errorf("adguard: response missing data array")
	}
	if len(page.Data) > limit {
		return AdGuardResponse{}, fmt.Errorf("adguard: response contains %d queries, requested page limit is %d", len(page.Data), limit)
	}
	for index := range page.Data {
		if page.Data[index].ElapsedMs == "" {
			page.Data[index].ElapsedMs = page.Data[index].LegacyElapsedMs
		}
		page.Data[index].LegacyElapsedMs = ""
	}
	return page, nil
}

// IsBlocked returns true if the AdGuard query was blocked.
// Blocked reasons: FilteredBlackList, FilteredSafeBrowsing, FilteredParental,
// FilteredSafeSearch, FilteredBlockedService, FilteredInvalid
func (q *AdGuardQuery) IsBlocked() bool {
	switch q.Reason {
	case "FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
		"FilteredSafeSearch", "FilteredBlockedService", "FilteredInvalid":
		return true
	default:
		return false
	}
}
