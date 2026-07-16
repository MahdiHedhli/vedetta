package fingerprint

import "testing"

func TestLookup_IEEEVendorIsAuthoritative(t *testing.T) {
	e := NewEngine()
	r := e.Lookup("ac:bc:32:de:ad:be")
	if r == nil {
		t.Fatal("IEEE Apple prefix ac:bc:32 did not match")
	}
	if r.Vendor != "Apple, Inc." {
		t.Errorf("vendor = %q, want IEEE %q", r.Vendor, "Apple, Inc.")
	}
	if r.DeviceType != "" {
		t.Errorf("OUI-only evidence must not assign a device type, got %q", r.DeviceType)
	}
}

func TestLookup_StaleCuratedConflictCannotOverrideIEEE(t *testing.T) {
	e := NewEngine()
	// The legacy curated map incorrectly labels 00:0a:95 as Dell/computer, while the
	// current IEEE registry assigns it to Apple. IEEE must win and no type may leak.
	r := e.Lookup("00:0a:95:12:34:56")
	if r == nil || r.Vendor != "Apple, Inc." || r.DeviceType != "" {
		t.Fatalf("stale curated assignment overrode IEEE: %+v", r)
	}
}

func TestLookup_UncorroboratedCuratedPrefixIgnored(t *testing.T) {
	e := NewEngine()
	// This Roku entry exists only in the legacy curated table, not the current MA-L
	// registry. A stale local row is not manufacturer evidence.
	if r := e.Lookup("d4:a5:d8:12:34:56"); r != nil {
		t.Fatalf("uncorroborated curated assignment produced evidence: %+v", r)
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
		{"AcBc32dead", "", false},             // ten hex digits is not a prefix/EUI-48
		{"ab:cd", "", false},                  // fewer than 6 hex
		{"ac:bg:32", "", false},               // non-hex input
		{"zz:zz:zz", "", false},               // non-hex input
		{"ac:bc:32:not-a-mac", "", false},     // malformed suffix after valid prefix
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
	for _, in := range []string{
		"",
		"ab:cd",
		"zz:zz:zz",
		"02:07:01:12:34:56", // locally administered/private; historical registry hit
		"11:00:aa:12:34:56", // multicast; historical registry hit
	} {
		if r := e.Lookup(in); r != nil {
			t.Errorf("Lookup(%q) = %+v, want nil", in, r)
		}
	}
}
