package transmit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/telemetry/internal/export"
	"github.com/vedetta-network/vedetta/telemetry/internal/idgen"
)

// Transmitter signs, compresses, and POSTs batches to the threat network with
// exponential backoff and a bounded on-disk spool. In dry-run mode it runs the
// full pipeline but performs ZERO egress — batches go to the spool only.
type Transmitter struct {
	IngestURL string
	Reporter  Reporter
	Spool     *Spool
	HTTP      *http.Client
	DryRun    bool

	MaxBatchItems int

	// Backoff schedule (overridable in tests).
	BackoffBase time.Duration // 1s
	BackoffMax  time.Duration // 5m
	MaxAttempts int           // attempts within a tick before spooling

	// Now / Sleep are injectable for deterministic tests.
	Now   func() time.Time
	Sleep func(time.Duration)

	nonceGen func() string
}

// New builds a Transmitter with contract defaults.
func New(ingestURL string, r Reporter, spool *Spool, dryRun bool, maxBatchItems int) *Transmitter {
	return &Transmitter{
		IngestURL:     strings.TrimRight(ingestURL, "/") + "/api/v1/ingest",
		Reporter:      r,
		Spool:         spool,
		HTTP:          &http.Client{Timeout: 30 * time.Second},
		DryRun:        dryRun,
		MaxBatchItems: maxBatchItems,
		BackoffBase:   time.Second,
		BackoffMax:    5 * time.Minute,
		MaxAttempts:   6,
		Now:           func() time.Time { return time.Now().UTC() },
		Sleep:         time.Sleep,
		nonceGen:      idgen.UUIDv4,
	}
}

// BuildBatches splits signals into batch envelopes capped at MaxBatchItems.
func (t *Transmitter) BuildBatches(sigs []export.Signal, windowStart, windowEnd time.Time) []export.Batch {
	limit := t.MaxBatchItems
	if limit <= 0 {
		limit = 250
	}
	var batches []export.Batch
	for start := 0; start < len(sigs); start += limit {
		end := start + limit
		if end > len(sigs) {
			end = len(sigs)
		}
		batches = append(batches, export.Batch{
			SchemaVersion: export.SchemaVersion,
			BatchID:       idgen.UUIDv4(),
			GeneratedAt:   t.Now().Format(time.RFC3339),
			WindowStart:   windowStart.UTC().Format(time.RFC3339),
			WindowEnd:     windowEnd.UTC().Format(time.RFC3339),
			Signals:       sigs[start:end],
		})
	}
	return batches
}

// SpoolBatch serializes a batch (JSON + gzip) and writes it to the spool without
// attempting any egress. Used for overflow batches that exceed a tick's send cap
// but whose source events have already been consumed — they must be retried by
// DrainSpool on a later tick rather than dropped.
func (t *Transmitter) SpoolBatch(batch export.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return err
	}
	return t.Spool.Add(batch.BatchID, gz)
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SendResult reports the outcome of sending one batch.
type SendResult struct {
	BatchID   string
	Accepted  bool
	Duplicate bool
	Spooled   bool
	Rejected  bool // 4xx poison-pill
	Err       error
}

// Send transmits a single batch. Behavior:
//   - dry-run: gzip + spool, no egress.
//   - success (2xx): accepted (parse duplicate flag).
//   - 4xx: poison-pill — NO retry, moved to rejected spool.
//   - 5xx / network: exponential backoff up to MaxAttempts, then spool.
func (t *Transmitter) Send(ctx context.Context, batch export.Batch) SendResult {
	body, err := json.Marshal(batch)
	if err != nil {
		return SendResult{BatchID: batch.BatchID, Err: err}
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return SendResult{BatchID: batch.BatchID, Err: err}
	}

	if t.DryRun {
		if err := t.Spool.Add(batch.BatchID, gz); err != nil {
			return SendResult{BatchID: batch.BatchID, Err: err}
		}
		return SendResult{BatchID: batch.BatchID, Spooled: true}
	}

	var lastErr error
	delay := t.BackoffBase
	for attempt := 0; attempt < t.MaxAttempts; attempt++ {
		if attempt > 0 {
			t.Sleep(delay)
			delay *= 2
			if delay > t.BackoffMax {
				delay = t.BackoffMax
			}
		}
		status, respBody, err := t.doPost(ctx, body, gz)
		if err != nil {
			lastErr = err
			continue // network error → retry
		}
		switch {
		case status >= 200 && status < 300:
			dup := false
			var r struct {
				Duplicate bool `json:"duplicate"`
			}
			if json.Unmarshal(respBody, &r) == nil {
				dup = r.Duplicate
			}
			return SendResult{BatchID: batch.BatchID, Accepted: true, Duplicate: dup}
		case status >= 400 && status < 500:
			// Poison pill: do NOT retry.
			_ = t.Spool.AddRejected(batch.BatchID, gz)
			return SendResult{BatchID: batch.BatchID, Rejected: true,
				Err: fmt.Errorf("rejected %d: %s", status, strings.TrimSpace(string(respBody)))}
		default:
			lastErr = fmt.Errorf("server status %d", status)
			continue // 5xx → retry
		}
	}
	// Exhausted retries → spool for a later tick.
	if err := t.Spool.Add(batch.BatchID, gz); err != nil {
		return SendResult{BatchID: batch.BatchID, Err: err}
	}
	return SendResult{BatchID: batch.BatchID, Spooled: true, Err: lastErr}
}

// doPost performs one signed POST and returns status + response body.
func (t *Transmitter) doPost(ctx context.Context, uncompressed, gz []byte) (int, []byte, error) {
	ts := strconv.FormatInt(t.Now().Unix(), 10)
	nonce := t.nonceGen()
	sig := Sign([]byte(SigningKey(t.Reporter.ReporterSecret)), SignatureInput{
		Timestamp: ts, Nonce: nonce, Body: uncompressed,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.IngestURL, bytes.NewReader(gz))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "VedettaReporter "+t.Reporter.ReporterID)
	req.Header.Set("X-Vedetta-Timestamp", ts)
	req.Header.Set("X-Vedetta-Nonce", nonce)
	req.Header.Set("X-Vedetta-Signature", sig)

	resp, err := t.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes(), nil
}

// DrainSpool attempts to resend spooled batches (oldest first) before new work.
// Successful sends are removed; failures leave the batch spooled. Rejected 4xx
// re-sends move to the rejected dir. Dry-run leaves the spool untouched.
func (t *Transmitter) DrainSpool(ctx context.Context) (sent, remaining int) {
	if t.DryRun {
		return 0, t.Spool.Depth()
	}
	items, err := t.Spool.List()
	if err != nil {
		return 0, t.Spool.Depth()
	}
	for _, it := range items {
		status, respBody, err := t.doPostGZ(ctx, it.GZ)
		if err != nil {
			break // network down: stop draining, keep the rest spooled
		}
		switch {
		case status >= 200 && status < 300:
			_ = t.Spool.Remove(it.Path)
			sent++
		case status >= 400 && status < 500:
			_ = t.Spool.Remove(it.Path)
			_ = t.Spool.AddRejected("spooled", it.GZ)
			_ = respBody
		default:
			// 5xx: stop; try again next tick.
			return sent, t.Spool.Depth()
		}
	}
	return sent, t.Spool.Depth()
}

// doPostGZ signs and posts an already-gzip'd spooled batch. It must reconstruct
// the uncompressed body to sign; it decompresses in-place.
func (t *Transmitter) doPostGZ(ctx context.Context, gz []byte) (int, []byte, error) {
	uncompressed, err := gunzip(gz)
	if err != nil {
		return 0, nil, err
	}
	return t.doPost(ctx, uncompressed, gz)
}

func gunzip(gz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(zr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
