package dnsintel

import "testing"

func TestScoreTunnel_NormalDomains(t *testing.T) {
	normal := []string{
		"www.google.com",
		"api.github.com",
		"mail.yahoo.com",
		"cdn.cloudflare.net",
		"s3.amazonaws.com",
	}

	for _, domain := range normal {
		result := ScoreTunnel(domain)
		if result.IsTunnel {
			t.Errorf("false positive: %q scored %.2f, signals=%v",
				domain, result.Score, result.Signals)
		}
	}
}

func TestScoreTunnel_HexEncoded(t *testing.T) {
	// Simulated DNS tunnel with hex-encoded data in subdomain
	domain := "4e6f7468696e67746f736565686572650a.data.evil.com"
	result := ScoreTunnel(domain)

	if !result.IsTunnel {
		t.Errorf("expected tunnel detection for hex-encoded subdomain, score=%.2f", result.Score)
	}
	if !containsSignal(result.Signals, "hex_encoded") {
		t.Errorf("expected hex_encoded signal, got %v", result.Signals)
	}
}

func TestScoreTunnel_Base64Encoded(t *testing.T) {
	domain := "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=.tunnel.bad.xyz"
	result := ScoreTunnel(domain)

	if !result.IsTunnel {
		t.Errorf("expected tunnel detection for base64 subdomain, score=%.2f", result.Score)
	}
}

func TestScoreTunnel_LongSubdomain(t *testing.T) {
	// 55-char subdomain label
	domain := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst.evil.com"
	result := ScoreTunnel(domain)

	if !containsSignal(result.Signals, "very_long_label") {
		t.Errorf("expected very_long_label signal for 55-char label, got %v", result.Signals)
	}
}

func TestScoreTunnel_DeepSubdomain(t *testing.T) {
	domain := "a.b.c.d.e.tunnel.evil.com"
	result := ScoreTunnel(domain)

	if !containsSignal(result.Signals, "deep_subdomain") {
		t.Errorf("expected deep_subdomain signal, got %v", result.Signals)
	}
}

func TestScoreTunnel_ShortDomains(t *testing.T) {
	// Two-label domains shouldn't be analyzed for tunneling
	short := []string{"google.com", "evil.net"}
	for _, domain := range short {
		result := ScoreTunnel(domain)
		if result.IsTunnel {
			t.Errorf("short domain %q should not trigger tunnel detection", domain)
		}
		if result.Score > 0 {
			t.Errorf("short domain %q should have score 0, got %.2f", domain, result.Score)
		}
	}
}

func TestIsTXTTunnelCandidate(t *testing.T) {
	if !IsTXTTunnelCandidate("TXT") {
		t.Error("TXT should be a tunnel candidate")
	}
	if !IsTXTTunnelCandidate("txt") {
		t.Error("txt (lowercase) should be a tunnel candidate")
	}
	if !IsTXTTunnelCandidate("NULL") {
		t.Error("NULL should be a tunnel candidate")
	}
	if IsTXTTunnelCandidate("A") {
		t.Error("A should not be a tunnel candidate")
	}
}

func containsSignal(signals []string, target string) bool {
	for _, s := range signals {
		if s == target {
			return true
		}
	}
	return false
}
