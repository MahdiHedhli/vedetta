package firewall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newUniFiTestServer stands up a synthetic UniFi controller. All values are
// synthetic (RFC 5737 IPs, 00:00:5E:00:53:xx MACs). It records whether requests
// carried the X-API-KEY header so tests can assert the auth mode.
type fakeUniFi struct {
	apiKeySeen  bool
	loginCalled bool
	ipsEvents   []map[string]any
	clients     []map[string]any
}

func (f *fakeUniFi) handler() http.Handler {
	mux := http.NewServeMux()
	// UDM/UDR probe → makes the connector select /proxy/network.
	mux.HandleFunc("/proxy/network/api/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "" {
			f.apiKeySeen = true
		}
		writeData(w, []map[string]any{{"name": "admin"}})
	})
	mux.HandleFunc("/proxy/network/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalled = true
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/event", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "" {
			f.apiKeySeen = true
		}
		writeData(w, f.ipsEvents)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/alarm", func(w http.ResponseWriter, r *http.Request) {
		writeData(w, []map[string]any{})
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "" {
			f.apiKeySeen = true
		}
		writeData(w, f.clients)
	})
	return mux
}

func writeData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// testConnector points a UniFiConnector at ts using the given API key.
func testConnector(t *testing.T, ts *httptest.Server, apiKey string) *UniFiConnector {
	t.Helper()
	host := strings.TrimPrefix(ts.URL, "https://")
	// httptest.NewTLSServer uses a random port; split host:port.
	cfg := ConnectorConfig{
		Name:          "unifi-test",
		Type:          "unifi",
		Host:          strings.Split(host, ":")[0],
		Port:          atoiPort(host),
		APIKey:        apiKey,
		TLSSkipVerify: true,
		Enabled:       true,
	}
	uc := NewUniFiConnector(cfg)
	// Reuse the test server's TLS client so the self-signed cert is trusted.
	uc.client = ts.Client()
	return uc
}

func atoiPort(hostport string) int {
	parts := strings.Split(hostport, ":")
	if len(parts) != 2 {
		return 443
	}
	p := 0
	for _, c := range parts[1] {
		p = p*10 + int(c-'0')
	}
	return p
}

func TestUniFiConnector_APIKeyAuth(t *testing.T) {
	fake := &fakeUniFi{
		ipsEvents: []map[string]any{
			{"timestamp": float64(time.Now().Unix()), "proto": "tcp", "srcip": "203.0.113.77",
				"srcport": float64(54321), "dstip": "198.51.100.2", "dstport": float64(22),
				"msg": "ET SCAN probe", "inner_alert_severity": float64(2)},
		},
	}
	ts := httptest.NewTLSServer(fake.handler())
	defer ts.Close()

	uc := testConnector(t, ts, "test-api-key")
	ctx := context.Background()
	if err := uc.Connect(ctx); err != nil {
		t.Fatalf("Connect with API key: %v", err)
	}
	if fake.loginCalled {
		t.Error("API-key mode must NOT call cookie login")
	}
	if !uc.isUniFiOS {
		t.Error("expected UDM/UDR (/proxy/network) detection")
	}

	events, err := uc.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if !fake.apiKeySeen {
		t.Error("requests should carry the X-API-KEY header in API-key mode")
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 IPS event, got %d", len(events))
	}
	ev := events[0]
	if !ev.IPS || ev.Severity != 2 {
		t.Errorf("IPS event parse: IPS=%v severity=%d, want true/2", ev.IPS, ev.Severity)
	}

	// ToEvent shape: tags + metadata dialect rest + ips_severity.
	me := ev.ToEvent("")
	if !containsStr(me.Tags, "source:unifi") || !containsStr(me.Tags, "ips") {
		t.Errorf("ToEvent tags missing source:unifi/ips: %v", me.Tags)
	}
	if !strings.Contains(me.Metadata, `"dialect":"rest"`) || !strings.Contains(me.Metadata, `"ips_severity":2`) {
		t.Errorf("ToEvent metadata missing dialect/severity: %s", me.Metadata)
	}
}

func TestUniFiConnector_CookieFallback(t *testing.T) {
	fake := &fakeUniFi{}
	ts := httptest.NewTLSServer(fake.handler())
	defer ts.Close()

	uc := testConnector(t, ts, "") // no API key → cookie login
	uc.cfg.Username = "ro-user"
	uc.cfg.Password = "ro-pass"
	if err := uc.Connect(context.Background()); err != nil {
		t.Fatalf("Connect (cookie): %v", err)
	}
	if !fake.loginCalled {
		t.Error("cookie mode should call /api/auth/login")
	}
	if fake.apiKeySeen {
		t.Error("cookie mode must not send X-API-KEY")
	}
}

func TestUniFiConnector_IPSDedupHighWaterMark(t *testing.T) {
	evt := map[string]any{"timestamp": float64(1_700_000_000), "proto": "tcp",
		"srcip": "203.0.113.10", "srcport": float64(1), "dstip": "198.51.100.5",
		"dstport": float64(443), "msg": "rule-x", "inner_alert_severity": float64(3)}
	fake := &fakeUniFi{ipsEvents: []map[string]any{evt}}
	ts := httptest.NewTLSServer(fake.handler())
	defer ts.Close()

	uc := testConnector(t, ts, "k")
	ctx := context.Background()
	if err := uc.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	first, _ := uc.Poll(ctx)
	if len(first) != 1 {
		t.Fatalf("first poll: expected 1 event, got %d", len(first))
	}
	second, _ := uc.Poll(ctx)
	if len(second) != 0 {
		t.Fatalf("second poll: expected 0 (deduped), got %d", len(second))
	}
}

func TestUniFiConnector_ListClients(t *testing.T) {
	fake := &fakeUniFi{
		clients: []map[string]any{
			{"ip": "192.0.2.45", "mac": "00:00:5E:00:53:0A", "hostname": "iot-plug",
				"oui": "Espressif", "network": "IoT VLAN"},
			{"ip": "192.0.2.10", "mac": "00:00:5E:00:53:0B", "name": "laptop",
				"oui": "Apple", "network": "Default"},
		},
	}
	ts := httptest.NewTLSServer(fake.handler())
	defer ts.Close()

	uc := testConnector(t, ts, "k")
	ctx := context.Background()
	if err := uc.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	clients, err := uc.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].Hostname != "iot-plug" || clients[0].Vendor != "Espressif" {
		t.Errorf("client[0] parse wrong: %+v", clients[0])
	}
	if clients[1].Hostname != "laptop" {
		t.Errorf("client[1] should fall back to name field: %+v", clients[1])
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
