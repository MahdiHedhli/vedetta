package threatintel

import "testing"

func TestBloomFilter_BasicOperations(t *testing.T) {
	bf := NewBloomFilter(10000, 7)

	// Add some values
	bf.Add("evil.com")
	bf.Add("malware.net")
	bf.Add("phishing.org")

	// Should be found
	if !bf.MayContain("evil.com") {
		t.Error("expected evil.com to be found")
	}
	if !bf.MayContain("malware.net") {
		t.Error("expected malware.net to be found")
	}
	if !bf.MayContain("phishing.org") {
		t.Error("expected phishing.org to be found")
	}

	// Should not be found (with very high probability)
	if bf.MayContain("google.com") {
		t.Log("false positive for google.com (possible but unlikely)")
	}
	if bf.MayContain("github.com") {
		t.Log("false positive for github.com (possible but unlikely)")
	}
}

func TestBloomFilter_NoFalseNegatives(t *testing.T) {
	bf := NewBloomFilter(100000, 7)

	// Insert 1000 values
	for i := 0; i < 1000; i++ {
		bf.Add("domain-" + string(rune(i+'A')) + ".com")
	}

	// Every inserted value MUST be found (no false negatives allowed)
	for i := 0; i < 1000; i++ {
		key := "domain-" + string(rune(i+'A')) + ".com"
		if !bf.MayContain(key) {
			t.Fatalf("false negative: %q was inserted but not found", key)
		}
	}
}

func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	bf := OptimalBloomFilter(10000, 0.01) // 1% target FP rate

	// Insert 10K values
	for i := 0; i < 10000; i++ {
		bf.Add("inserted-" + string(rune(i)) + ".com")
	}

	// Test 10K values that were NOT inserted
	falsePositives := 0
	for i := 0; i < 10000; i++ {
		key := "not-inserted-" + string(rune(i)) + ".xyz"
		if bf.MayContain(key) {
			falsePositives++
		}
	}

	fpRate := float64(falsePositives) / 10000.0
	// Allow up to 5% (generous margin for the statistical test)
	if fpRate > 0.05 {
		t.Errorf("false positive rate %.2f%% exceeds 5%% threshold", fpRate*100)
	}
	t.Logf("False positive rate: %.2f%% (%d/10000)", fpRate*100, falsePositives)
}

func TestOptimalBloomFilter(t *testing.T) {
	bf := OptimalBloomFilter(100000, 0.001) // 100K elements, 0.1% FP

	if bf.numBits == 0 {
		t.Error("expected non-zero bit count")
	}
	if bf.numHash < 1 {
		t.Error("expected at least 1 hash function")
	}

	t.Logf("Optimal for 100K/0.1%%: %d bits (%d KB), %d hashes",
		bf.numBits, bf.numBits/8/1024, bf.numHash)
}

func TestBloomFilter_Empty(t *testing.T) {
	bf := NewBloomFilter(1000, 7)

	// Empty filter should not match anything
	if bf.MayContain("anything") {
		t.Error("empty filter should not match")
	}
}
