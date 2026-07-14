package main

/*
Simulation tool for Vedetta SNR (Signal-to-Noise Ratio) validation.

Generates realistic DNS events across three risk tiers:

  false_positive  → Legitimate traffic that should NOT trigger high scores
  mid_warning     → Moderately suspicious behavior (should score ~0.3-0.65)
  high_threat     → Clearly malicious patterns (should score >0.6-0.8+)
  mixed           → Balanced mix of all three

Examples:
  go run main.go -count 80  -scenario false_positive
  go run main.go -count 40  -scenario mid_warning
  go run main.go -count 30  -scenario high_threat
  go run main.go -count 100 -scenario mixed

  # Use the current local inventory as context for otherwise synthetic events:
  go run main.go -count 50 -scenario mixed -real-context
*/

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dbPath := flag.String("db", "/data/vedetta.db", "Path to vedetta.db")
	count := flag.Int("count", 50, "Number of events to generate")
	scenario := flag.String("scenario", "mixed", "Scenario: false_positive | mid_warning | high_threat | mixed")
	realContext := flag.Bool("real-context", false, "Use the current local device inventory for vendor, segment, and first-seen context on synthetic events. Enables realistic SNR testing without embedding inventory data.")
	enrich := flag.Bool("enrich", false, "POST generated events to /api/v1/ingest so they go through the full Enricher pipeline for computed scores, context boosts, tags, and threat descriptions.")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	rand.Seed(time.Now().UnixNano())

	fmt.Printf("Generating %d events with scenario '%s'...\n", *count, *scenario)

	var realDevices []realDevice
	if *realContext {
		realDevices = loadRealDevices(db)
		fmt.Printf("  real-context: loaded %d devices from the current local inventory for authentic vendor/segment context\n", len(realDevices))
	}

	now := time.Now().UTC()
	var eventsToPersist []SimEvent

	for i := 0; i < *count; i++ {
		event := generateEvent(*scenario, now.Add(-time.Duration(rand.Intn(7200))*time.Second))

		if len(realDevices) > 0 {
			dev := realDevices[rand.Intn(len(realDevices))]
			event.SourceIP = dev.IP
			if dev.Vendor != "" {
				event.DeviceVendor = dev.Vendor
			}
			if dev.Segment != "" {
				event.NetworkSegment = dev.Segment
			}
			// If this inventory device is established at the event time, strip spurious
			// new_device/very_new tags so established IoT devices do not receive fake
			// context boosts in the synthetic test data.
			if !dev.FirstSeen.IsZero() && event.Timestamp.Sub(dev.FirstSeen) > 48*time.Hour {
				event.TagsJSON = strings.ReplaceAll(event.TagsJSON, `"new_device",`, "")
				event.TagsJSON = strings.ReplaceAll(event.TagsJSON, `"very_new_device",`, "")
				event.TagsJSON = strings.ReplaceAll(event.TagsJSON, `"new_device"`, "")
				event.TagsJSON = strings.ReplaceAll(event.TagsJSON, `"very_new_device"`, "")
				// (high-threat scenarios still demonstrate boosts via their domains + remaining tags)
			}
		}

		eventsToPersist = append(eventsToPersist, event)
	}

	if *enrich {
		// Send through public ingest so Enricher runs scoring, current-inventory
		// context lookup, boosts, and threat descriptions.
		ingestURL := "http://localhost:8080/api/v1/ingest"
		// Build minimal payloads that the ingest will accept and enrich (it calls Enricher.Enrich)
		var payloads []map[string]any
		for _, e := range eventsToPersist {
			payloads = append(payloads, ingestPayload(e))
		}
		body, err := json.Marshal(payloads)
		if err != nil {
			log.Fatalf("encode enrich payload: %v", err)
		}
		req, err := newIngestRequest(ingestURL, body, os.Getenv("VEDETTA_INGEST_TOKEN"))
		if err != nil {
			log.Fatalf("build enrich request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("enrich POST error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			log.Fatalf("enrich POST returned %s", resp.Status)
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			log.Fatalf("decode enrich response: %v", err)
		}
		log.Printf("Enriched via pipeline: %v", result)
		fmt.Printf("Sent %d synthetic events through Enricher with current-inventory context.\n", len(eventsToPersist))
	} else {
		// Legacy direct insert path (for existing targets that expect pre-scored or 0-score test data)
		inserted := 0
		for _, event := range eventsToPersist {
			_, err := db.Exec(`
				INSERT INTO events (
					event_id, timestamp, event_type, source_hash, source_ip, domain,
					query_type, resolved_ip, blocked, anomaly_score, tags,
					geo, device_vendor, network_segment, dns_source, threat_desc, metadata
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`,
				event.EventID, event.Timestamp, event.EventType, event.SourceHash, event.SourceIP,
				event.Domain, event.QueryType, event.ResolvedIP, event.Blocked, event.AnomalyScore,
				event.TagsJSON, event.Geo, event.DeviceVendor, event.NetworkSegment, event.DNSSource,
				event.ThreatDesc, event.Metadata,
			)
			if err != nil {
				log.Printf("insert error: %v", err)
				continue
			}
			inserted++
		}
		fmt.Printf("Inserted %d events successfully (direct, no Enricher).\n", inserted)
	}
}

type SimEvent struct {
	EventID        string
	Timestamp      time.Time
	EventType      string
	SourceHash     string
	SourceIP       string
	Domain         string
	QueryType      string
	ResolvedIP     string
	Blocked        bool
	AnomalyScore   float64
	TagsJSON       string
	Geo            string
	DeviceVendor   string
	NetworkSegment string
	DNSSource      string
	ThreatDesc     string
	Metadata       string
}

func ingestPayload(e SimEvent) map[string]any {
	p := map[string]any{
		"event_id":        e.EventID,
		"timestamp":       e.Timestamp,
		"event_type":      e.EventType,
		"domain":          e.Domain,
		"source_ip":       e.SourceIP,
		"device_vendor":   e.DeviceVendor,
		"network_segment": e.NetworkSegment,
		"dns_source":      e.DNSSource,
		"query_type":      e.QueryType,
	}
	if e.ResolvedIP != "" {
		p["resolved_ip"] = e.ResolvedIP
	}
	return p
}

func newIngestRequest(ingestURL string, body []byte, token string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, ingestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token = strings.TrimSpace(token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func generateEvent(scenario string, ts time.Time) SimEvent {
	e := SimEvent{
		EventID:    uuid.New().String(),
		Timestamp:  ts,
		EventType:  "dns_query",
		QueryType:  "A",
		DNSSource:  "simulation",
		SourceHash: "sim-" + uuid.New().String()[:8],
	}

	switch scenario {
	// ==================== FALSE POSITIVES ====================
	case "false_positive":
		// Legitimate behavior that might look suspicious at first glance
		switch rand.Intn(5) {
		case 0:
			// Normal Apple update from MacBook on default
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "swcdn.apple.com"
			e.DeviceVendor = "Apple"
			e.NetworkSegment = "default"
			e.TagsJSON = `[]`
		case 1:
			// Google telemetry from normal laptop
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "play.googleapis.com"
			e.DeviceVendor = "Google"
			e.NetworkSegment = "default"
		case 2:
			// CloudFront long subdomain (very common)
			e.SourceIP = randomIP("192.168.1")
			e.Domain = fmt.Sprintf("%s.cloudfront.net", randomString(16))
			e.DeviceVendor = "Apple"
			e.NetworkSegment = "default"
		case 3:
			// Samsung TV checking for updates (established device)
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "samsungapps.com"
			e.DeviceVendor = "Samsung"
			e.NetworkSegment = "default"
		default:
			// Microsoft Windows telemetry from known laptop
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "vortex.data.microsoft.com"
			e.DeviceVendor = "Dell"
			e.NetworkSegment = "default"
		}

	// ==================== MID-LEVEL WARNING ====================
	case "mid_warning":
		switch rand.Intn(4) {
		case 0:
			// Beaconing from a *new* device on default segment
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "api.tracker.example.com"
			e.DeviceVendor = "Apple"
			e.NetworkSegment = "default"
			e.TagsJSON = `["new_device"]`
		case 1:
			// Public DNS resolver use from IoT segment (not brand new)
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "api.smartthings.com"
			e.ResolvedIP = "8.8.8.8"
			e.DeviceVendor = "Samsung"
			e.NetworkSegment = "iot"
			e.TagsJSON = `["new_device"]`
		case 2:
			// Slightly suspicious domain from new device
			e.SourceIP = randomIP("192.168.1")
			e.Domain = "xnvbckjdhf-update.net"
			e.DeviceVendor = "Apple"
			e.NetworkSegment = "default"
			e.TagsJSON = `["new_device"]`
		default:
			// Regular but slightly odd behavior from IoT device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "telemetry.lge.com"
			e.DeviceVendor = "LG"
			e.NetworkSegment = "iot"
			e.TagsJSON = `["new_device"]`
		}

	// ==================== HIGH THREAT ====================
	case "high_threat":
		switch rand.Intn(5) {
		case 0:
			// DGA-like from *very new* IoT device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = randomDGADomain()
			e.DeviceVendor = "Espressif"
			e.NetworkSegment = "iot"
			e.TagsJSON = `["very_new_device","new_device"]`
		case 1:
			// Public DNS bypass from very new IoT device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "api.malicious-c2.com"
			e.ResolvedIP = "1.1.1.1"
			e.DeviceVendor = "Espressif"
			e.NetworkSegment = "iot"
			e.TagsJSON = `["very_new_device","new_device"]`
		case 2:
			// DNS tunneling style from new IoT device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "aGVsbG8td29ybGQ.tunnel.evil.com"
			e.DeviceVendor = "Realtek"
			e.NetworkSegment = "guest"
			e.TagsJSON = `["new_device"]`
		case 3:
			// Rebinding attack targeting new device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "rebind-attack.com"
			e.ResolvedIP = "192.168.50.42"
			e.DeviceVendor = "MediaTek"
			e.NetworkSegment = "iot"
			e.TagsJSON = `["very_new_device","new_device"]`
		default:
			// Known bad domain from new/unknown device
			e.SourceIP = randomIP("192.168.50")
			e.Domain = "c2.malware-family.net"
			e.DeviceVendor = ""
			e.NetworkSegment = "iot"
			e.TagsJSON = `["new_device"]`
		}

	// ==================== MIXED (good test set) ====================
	default:
		r := rand.Float32()
		if r < 0.55 {
			return generateEvent("false_positive", ts)
		} else if r < 0.80 {
			return generateEvent("mid_warning", ts)
		} else {
			return generateEvent("high_threat", ts)
		}
	}

	return e
}

// === Helpers ===

func randomIP(prefix string) string {
	return fmt.Sprintf("%s.%d", prefix, rand.Intn(180)+20)
}

func randomDGADomain() string {
	domains := []string{
		"asdkjfhqweoiu.com", "xnvbckjdhf.net", "plkmnjbvcx.org",
		"qwertyuiopasdfgh.com", "zxcvbnmlkjhgfdsa.net", "mnbvcxzasdfghjkl.com",
	}
	return domains[rand.Intn(len(domains))]
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// === Current local device context support for SNR validation ===

type realDevice struct {
	IP        string
	Vendor    string
	Segment   string
	FirstSeen time.Time
}

func loadRealDevices(db *sql.DB) []realDevice {
	rows, err := db.Query(`
		SELECT ip_address, COALESCE(vendor, ''), COALESCE(segment, 'default'), first_seen
		FROM devices
		ORDER BY last_seen DESC
		LIMIT 200
	`)
	if err != nil {
		log.Printf("loadRealDevices query error: %v", err)
		return nil
	}
	defer rows.Close()

	var devs []realDevice
	for rows.Next() {
		var d realDevice
		if err := rows.Scan(&d.IP, &d.Vendor, &d.Segment, &d.FirstSeen); err != nil {
			continue
		}
		if d.IP != "" {
			devs = append(devs, d)
		}
	}
	return devs
}
