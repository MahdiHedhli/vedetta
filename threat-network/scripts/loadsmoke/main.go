//go:build ignore

// loadsmoke is a synthetic load generator (T6.3): it registers N reporters and
// posts signed batches of known_bad domains at a compressed cadence, then prints
// basic latency stats. All data is synthetic (RFC 2606 .example domains). Run
// against a locally running threat-network:
//
//	go run scripts/loadsmoke/main.go -url http://localhost:9090 -reporters 50 -batches 4
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:9090", "base URL")
	reporters := flag.Int("reporters", 50, "number of reporters")
	batches := flag.Int("batches", 4, "batches per reporter")
	flag.Parse()

	type cred struct{ id, key string }
	var creds []cred
	for i := 0; i < *reporters; i++ {
		body, _ := json.Marshal(map[string]any{
			"schema_version": 1,
			"install_id":     fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
			"capabilities":   []string{"known_bad_domain_hit"},
		})
		resp, err := http.Post(*url+"/api/v1/reporters/register", "application/json", bytes.NewReader(body))
		if err != nil {
			log.Fatalf("register: %v", err)
		}
		var rr struct {
			ReporterID     string `json:"reporter_id"`
			ReporterSecret string `json:"reporter_secret"`
		}
		json.NewDecoder(resp.Body).Decode(&rr)
		resp.Body.Close()
		sum := sha256.Sum256([]byte(rr.ReporterSecret))
		creds = append(creds, cred{id: rr.ReporterID, key: hex.EncodeToString(sum[:])})
	}
	log.Printf("registered %d reporters", len(creds))

	var latencies []time.Duration
	nonce := 0
	for b := 0; b < *batches; b++ {
		for _, c := range creds {
			nonce++
			batchID := fmt.Sprintf("%s-%d", c.id, b)
			body := synthBatch(batchID)
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			msg := ts + "\n" + strconv.Itoa(nonce) + "\n" + sha256hex(body)
			mac := hmac.New(sha256.New, []byte(c.key))
			mac.Write([]byte(msg))
			sig := hex.EncodeToString(mac.Sum(nil))

			req, _ := http.NewRequest(http.MethodPost, *url+"/api/v1/ingest", bytes.NewReader(body))
			req.Header.Set("Authorization", "VedettaReporter "+c.id)
			req.Header.Set("X-Vedetta-Timestamp", ts)
			req.Header.Set("X-Vedetta-Nonce", strconv.Itoa(nonce))
			req.Header.Set("X-Vedetta-Signature", sig)
			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Fatalf("ingest: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				log.Fatalf("5xx from ingest: %d", resp.StatusCode)
			}
			latencies = append(latencies, time.Since(start))
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		p95 := latencies[int(float64(len(latencies))*0.95)]
		log.Printf("sent %d batches, p95 ingest latency = %v", len(latencies), p95)
	}
}

func synthBatch(batchID string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"batch_id":%q,
      "generated_at":"2026-07-03T14:15:02Z","window_start":"2026-07-03T14:00:00Z",
      "window_end":"2026-07-03T15:00:00Z","signals":[
        {"signal_id":%q,"kind":"known_bad_domain_hit","time_bucket":"2026-07-03T14:00:00Z",
         "domain":"c2.badzone.example","etld_plus_one":"badzone.example","local_confidence":0.99,
         "local_reasons":["known_bad"],"observation_count":4,"distinct_asset_count":2}]}`,
		batchID, batchID+"-sig"))
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
