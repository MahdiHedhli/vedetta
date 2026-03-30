package dnsintel

import "testing"

func TestScoreDGA_BenignDomains(t *testing.T) {
	benign := []string{
		"google.com",
		"amazon.co.uk",
		"reddit.com",
		"stackoverflow.com",
		"en.wikipedia.org",
		"mail.google.com",
		"docs.github.com",
		"news.ycombinator.com",
	}

	for _, domain := range benign {
		result := ScoreDGA(domain)
		if result.IsDGA {
			t.Errorf("false positive: %q scored %.2f (entropy=%.2f, bigram=%.2f)",
				domain, result.Score, result.Entropy, result.BigramScore)
		}
	}
}

func TestScoreDGA_DGADomains(t *testing.T) {
	dga := []string{
		"asdfjklqwerty.com",       // random keyboard mash
		"xn3kd9fj2mz8p.net",      // hex-like random
		"kj3hf8s2m4n7q.org",      // alphanumeric DGA
		"qxzjkvbwnmpl.evil.com",  // consonant-heavy random
		"r7t2x9k4m1n8.biz",       // number-heavy random
	}

	flagged := 0
	for _, domain := range dga {
		result := ScoreDGA(domain)
		if result.IsDGA {
			flagged++
		}
		// Even if not flagged as DGA, score should be elevated
		if result.Score < 0.2 {
			t.Errorf("DGA domain %q scored too low: %.2f", domain, result.Score)
		}
	}

	// We expect most DGA domains to be flagged, but the heuristic isn't perfect
	if flagged < len(dga)/2 {
		t.Errorf("only %d/%d DGA domains flagged", flagged, len(dga))
	}
}

func TestScoreDGA_ShortDomains(t *testing.T) {
	// Short domains should not trigger DGA detection
	short := []string{"go.dev", "t.co", "x.com", "ab.cd"}
	for _, domain := range short {
		result := ScoreDGA(domain)
		if result.IsDGA {
			t.Errorf("short domain %q should not be flagged as DGA", domain)
		}
		if result.Score > 0 {
			t.Errorf("short domain %q should have score 0, got %.2f", domain, result.Score)
		}
	}
}

func TestScoreDGA_MultiPartTLD(t *testing.T) {
	result := ScoreDGA("xkjf8m2nq4.co.uk")
	// Should score the "xkjf8m2nq4" label, not "co"
	if result.Label != "xkjf8m2nq4" {
		t.Errorf("expected label 'xkjf8m2nq4', got %q", result.Label)
	}
}

func TestShannonEntropy(t *testing.T) {
	// Single character repeated = 0 entropy
	if e := shannonEntropy("aaaa"); e != 0 {
		t.Errorf("expected 0 entropy for 'aaaa', got %f", e)
	}

	// Two equally distributed chars = 1 bit
	e := shannonEntropy("abab")
	if e < 0.99 || e > 1.01 {
		t.Errorf("expected ~1.0 entropy for 'abab', got %f", e)
	}

	// Empty string
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestEffectiveLabel(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"google.com", "google"},
		{"sub.domain.com", "domain"},       // longest label
		{"verylongsub.d.com", "verylongsub"},
		{"test.co.uk", "test"},             // multi-part TLD
		{"a.b.c.example.com", "example"},   // picks longest
	}

	for _, tt := range tests {
		got := effectiveLabel(tt.domain)
		if got != tt.want {
			t.Errorf("effectiveLabel(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
