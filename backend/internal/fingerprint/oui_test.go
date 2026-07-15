package fingerprint

import "testing"

func TestLookup_CuratedColonKeyMatches(t *testing.T) {
	// Regression: ouiDatabase keys carry colons ("ac:bc:32") while Lookup strips them.
	// Before the normalized curated index this never matched and the overlay was dead.
	e := NewEngine()
	r := e.Lookup("ac:bc:32:de:ad:be")
	if r == nil {
		t.Fatal("curated Apple prefix ac:bc:32 did not match (colon-key regression)")
	}
	if r.Vendor != "Apple" {
		t.Errorf("vendor = %q, want curated %q", r.Vendor, "Apple")
	}
	if r.Confidence != 0.2 {
		t.Errorf("confidence = %v, want 0.2", r.Confidence)
	}
}

func TestLookup_CuratedDeviceTypeHint(t *testing.T) {
	e := NewEngine()
	r := e.Lookup("b8:27:eb:00:00:01") // Raspberry Pi Foundation
	if r == nil || r.DeviceType != "computer" {
		t.Fatalf("expected Raspberry Pi device_type=computer, got %+v", r)
	}
}

func TestLookup_CuratedWinsOverIEEE(t *testing.T) {
	// acbc32 is Apple in both tables; curated ("Apple") must win over IEEE ("Apple, Inc.").
	e := NewEngine()
	r := e.Lookup("ACBC32000000")
	if r == nil || r.Vendor != "Apple" {
		t.Fatalf("curated overlay should win, got %+v", r)
	}
}

func TestLookup_IEEEFallback(t *testing.T) {
	// 000000 (XEROX) is in the IEEE table only, not the curated overlay.
	e := NewEngine()
	r := e.Lookup("00:00:00:12:34:56")
	if r == nil {
		t.Fatal("IEEE-only prefix 000000 did not resolve")
	}
	if r.Vendor == "" {
		t.Error("IEEE fallback vendor is empty")
	}
	if r.DeviceType != "" {
		t.Errorf("IEEE fallback should carry no device type, got %q", r.DeviceType)
	}
	if r.Confidence != 0.2 {
		t.Errorf("confidence = %v, want 0.2", r.Confidence)
	}
}

func TestExtractOUI(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ac:bc:32", "acbc32", true},
		{"AC-BC-32", "acbc32", true},          // uppercase + dashes
		{"ac bc 32", "acbc32", true},          // spaces
		{"acbc32", "acbc32", true},            // no separators
		{"ac:bc:32:de:ad:be", "acbc32", true}, // full MAC — stops after 6
		{"AcBc32dead", "acbc32", true},        // mixed case, early stop
		{"ab:cd", "", false},                  // fewer than 6 hex
		{"", "", false},                       // empty
		{":::::", "", false},                  // only separators
	}
	for _, c := range cases {
		got, ok := extractOUI(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("extractOUI(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLookup_Rejects(t *testing.T) {
	e := NewEngine()
	for _, in := range []string{"", "ab:cd", "zz:zz:zz"} {
		if r := e.Lookup(in); r != nil {
			t.Errorf("Lookup(%q) = %+v, want nil", in, r)
		}
	}
}
