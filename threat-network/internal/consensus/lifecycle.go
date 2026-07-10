package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vedetta-network/vedetta/threat-network/internal/store"
)

// upsertFeedItem materializes or refreshes a promoted feed item. It sets
// last_seen/confidence/expires_at from the current window and always stamps the
// advisory reason "cross_reporter_match".
func (e *Engine) upsertFeedItem(now time.Time, ag *aggregate, d decision, conf float64, distinct int, reasons []string) error {
	reasons = withServerReason(reasons)
	reasonsJSON, _ := json.Marshal(reasons)

	existing, found, err := e.DB.GetFeedItemByIndicator(d.feedKind, ag.indicator)
	if err != nil {
		return err
	}

	// Defense in depth (GHSA-hwcf): expiry is anchored to last_seen (a reporter-
	// supplied time_bucket). Ingest already rejects future-dated buckets, but never
	// let a caller pin expires_at past now+ttl even if a future bucket slipped
	// through — clamp the anchor to server now so the horizon is bounded by ttl.
	anchor := ag.lastSeen
	if anchor.After(now) {
		anchor = now
	}
	expiresAt := anchor.Add(time.Duration(d.ttl) * time.Hour)
	nowStr := now.UTC().Format(time.RFC3339)

	fi := store.FeedItem{
		Kind:            d.feedKind,
		Indicator:       ag.indicator,
		IndicatorType:   d.indicatorType,
		Confidence:      conf,
		Severity:        d.severity,
		SourcesRequired: d.sourcesRequired,
		SourcesObserved: distinct,
		Reasons:         string(reasonsJSON),
		FirstSeen:       ag.firstSeen.UTC().Format(time.RFC3339),
		LastSeen:        ag.lastSeen.UTC().Format(time.RFC3339),
		UpdatedAt:       nowStr,
		ExpiresAt:       expiresAt.UTC().Format(time.RFC3339),
	}
	if found {
		fi.FeedID = existing.FeedID
		fi.PublishedAt = existing.PublishedAt
		// keep the earliest first_seen
		if existing.FirstSeen < fi.FirstSeen {
			fi.FirstSeen = existing.FirstSeen
		}
		// refreshing a previously-revoked item clears the revocation
		fi.RevokedAt = ""
	} else {
		fi.FeedID = deterministicFeedID(d.feedKind, ag.indicator)
		fi.PublishedAt = nowStr
	}
	return e.DB.UpsertFeedItem(fi)
}

// applyLifecycle revokes feed items whose expires_at has passed and are not
// being refreshed this run. Because upsertFeedItem already extended expires_at
// for still-corroborated items, anything still expired here has decayed out.
func (e *Engine) applyLifecycle(now time.Time) error {
	items, err := e.DB.AllFeedItems()
	if err != nil {
		return err
	}
	nowStr := now.UTC().Format(time.RFC3339)
	for _, fi := range items {
		if fi.RevokedAt != "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, fi.ExpiresAt)
		if err != nil {
			continue
		}
		if !now.Before(exp) { // now >= expires_at → expired
			if err := e.DB.RevokeFeedItem(fi.FeedID, nowStr); err != nil {
				return err
			}
		}
	}
	return nil
}

func withServerReason(reasons []string) []string {
	for _, r := range reasons {
		if r == "cross_reporter_match" {
			return reasons
		}
	}
	return append(append([]string{}, reasons...), "cross_reporter_match")
}

// deterministicFeedID derives a stable UUID-shaped id from (kind, indicator) so
// the same indicator keeps the same feed_id across runs and restarts.
func deterministicFeedID(kind, indicator string) string {
	sum := sha256.Sum256([]byte(kind + "|" + indicator))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}
