// Package feed materializes the advisory community feed response per
// specs/003-threat-network/contracts/community-feed-api.md. Every item is
// advisory-only: advisory=true, recommended_action="advise" — no other value
// exists in schema v1.
package feed

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// SchemaVersion is the feed contract version.
const SchemaVersion = 1

// DefaultLimit / MaxLimit bound page size (contract query params).
const (
	DefaultLimit = 1000
	MaxLimit     = 5000
)

// Item is one advisory feed item as serialized on the wire.
type Item struct {
	FeedID            string   `json:"feed_id"`
	Kind              string   `json:"kind"`
	Indicator         string   `json:"indicator"`
	IndicatorType     string   `json:"indicator_type"`
	Confidence        float64  `json:"confidence"`
	Severity          string   `json:"severity"`
	Advisory          bool     `json:"advisory"`
	RecommendedAction string   `json:"recommended_action"`
	SourcesRequired   int      `json:"sources_required"`
	SourcesObserved   int      `json:"sources_observed"`
	Reasons           []string `json:"reasons"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	PublishedAt       string   `json:"published_at"`
	UpdatedAt         string   `json:"updated_at"`
	ExpiresAt         string   `json:"expires_at"`
}

// Response is the full feed envelope.
type Response struct {
	SchemaVersion int    `json:"schema_version"`
	Feed          string `json:"feed"`
	GeneratedAt   string `json:"generated_at"`
	TTLSeconds    int    `json:"ttl_seconds"`
	Advisory      bool   `json:"advisory"`
	TotalItems    int    `json:"total_items"`
	ReturnedItems int    `json:"returned_items"`
	NextCursor    string `json:"next_cursor,omitempty"`
	Items         []Item `json:"items"`
}

// Query holds parsed, validated request parameters.
type Query struct {
	Cursor        string
	Limit         int
	MinConfidence float64
	Kind          string
}

// QueryError is a 400 with a machine-readable code.
type QueryError struct {
	Code   string
	Detail string
}

func (e *QueryError) Error() string { return e.Code + ": " + e.Detail }

var validKinds = map[string]bool{
	"domain_indicator": true, "etld1_indicator": true, "behavior_cluster": true,
}

// ParseQuery validates raw query values into a Query.
func ParseQuery(cursor, limit, minConf, kind string) (Query, error) {
	q := Query{Limit: DefaultLimit}
	if limit != "" {
		n, err := parseInt(limit)
		if err != nil || n < 1 || n > MaxLimit {
			return q, &QueryError{Code: "INVALID_PARAMETER", Detail: "limit must be 1..5000"}
		}
		q.Limit = n
	}
	if minConf != "" {
		f, err := parseFloat(minConf)
		if err != nil || f < 0 || f > 1 {
			return q, &QueryError{Code: "INVALID_PARAMETER", Detail: "min_confidence must be 0..1"}
		}
		q.MinConfidence = f
	}
	if kind != "" {
		if !validKinds[kind] {
			return q, &QueryError{Code: "INVALID_PARAMETER", Detail: "unknown kind"}
		}
		q.Kind = kind
	}
	q.Cursor = cursor
	return q, nil
}

// cursorPayload is the opaque cursor content, tagged with schema version. The
// feed is ordered by (confidence DESC, feed_id ASC); the cursor is a keyset over
// that order plus a running Offset so pagination stops at the FeedItemCap.
type cursorPayload struct {
	V      int    `json:"v"`
	Conf   string `json:"c"` // confidence at the cursor position (formatted)
	FeedID string `json:"f"`
	Offset int    `json:"o"` // items already served before this page
}

func encodeCursor(conf, feedID string, offset int) string {
	p := cursorPayload{V: SchemaVersion, Conf: conf, FeedID: feedID, Offset: offset}
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(cur string) (conf, feedID string, offset int, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil {
		return "", "", 0, &QueryError{Code: "INVALID_CURSOR", Detail: "cursor not decodable"}
	}
	var p cursorPayload
	if json.Unmarshal(raw, &p) != nil || p.V != SchemaVersion {
		return "", "", 0, &QueryError{Code: "INVALID_CURSOR", Detail: "cursor from a different schema version"}
	}
	return p.Conf, p.FeedID, p.Offset, nil
}

// confCursor formats a confidence value into the stable string used both in the
// cursor and in the SQL keyset comparison, so the two always agree.
func confCursor(c float64) string {
	return strconv.FormatFloat(c, 'g', -1, 64)
}

// Builder serves feed queries from the store.
type Builder struct {
	DB  *store.DB
	Now func() time.Time
}

// New builds a feed Builder with real time.
func New(db *store.DB) *Builder {
	return &Builder{DB: db, Now: time.Now}
}

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Build returns the feed Response and an ETag for the given query.
func (b *Builder) Build(q Query) (*Response, string, error) {
	var afterConf, afterFeedID string
	var offset int
	if q.Cursor != "" {
		c, f, o, err := decodeCursor(q.Cursor)
		if err != nil {
			return nil, "", err
		}
		afterConf, afterFeedID, offset = c, f, o
	}

	now := b.now()
	// Never serve more than the feed cap, even if limit is higher, and never page
	// past the cap: the served feed is the top FeedItemCap items by confidence.
	effLimit := q.Limit
	if effLimit > MaxLimit {
		effLimit = MaxLimit
	}
	if remaining := store.FeedItemCap - offset; effLimit > remaining {
		effLimit = remaining
	}
	if effLimit < 0 {
		effLimit = 0
	}

	rows, total, err := b.DB.LiveFeedItems(store.FeedQuery{
		MinConfidence: q.MinConfidence,
		Kind:          q.Kind,
		AfterConf:     afterConf,
		AfterFeedID:   afterFeedID,
		Limit:         effLimit,
		Now:           now,
	})
	if err != nil {
		return nil, "", err
	}
	if total > MaxLimit {
		total = MaxLimit
	}

	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, toItem(r))
	}

	resp := &Response{
		SchemaVersion: SchemaVersion,
		Feed:          "community",
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		TTLSeconds:    900,
		Advisory:      true,
		TotalItems:    total,
		ReturnedItems: len(items),
		Items:         items,
	}
	// Emit a next cursor only when a full page was returned AND the cap has not
	// been reached — so a client can never page beyond the top FeedItemCap items.
	nextOffset := offset + len(rows)
	if len(rows) == effLimit && effLimit > 0 && nextOffset < store.FeedItemCap {
		last := rows[len(rows)-1]
		resp.NextCursor = encodeCursor(confCursor(last.Confidence), last.FeedID, nextOffset)
	}

	etag := computeETag(resp)
	return resp, etag, nil
}

func toItem(r store.FeedItem) Item {
	var reasons []string
	_ = json.Unmarshal([]byte(r.Reasons), &reasons)
	if reasons == nil {
		reasons = []string{}
	}
	return Item{
		FeedID:            r.FeedID,
		Kind:              r.Kind,
		Indicator:         r.Indicator,
		IndicatorType:     r.IndicatorType,
		Confidence:        r.Confidence,
		Severity:          r.Severity,
		Advisory:          true,     // contractual invariant
		RecommendedAction: "advise", // only value in schema v1
		SourcesRequired:   r.SourcesRequired,
		SourcesObserved:   r.SourcesObserved,
		Reasons:           reasons,
		FirstSeen:         r.FirstSeen,
		LastSeen:          r.LastSeen,
		PublishedAt:       r.PublishedAt,
		UpdatedAt:         r.UpdatedAt,
		ExpiresAt:         r.ExpiresAt,
	}
}

// computeETag derives a stable ETag from the returned item identities+versions.
func computeETag(resp *Response) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d;total=%d;", resp.SchemaVersion, resp.TotalItems)
	for _, it := range resp.Items {
		fmt.Fprintf(h, "%s@%s;", it.FeedID, it.UpdatedAt)
	}
	return `"feed-v1-` + hex.EncodeToString(h.Sum(nil)[:12]) + `"`
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}
