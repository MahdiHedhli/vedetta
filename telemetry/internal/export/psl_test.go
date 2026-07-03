package export

import "testing"

func TestETLDPlusOne(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"c2-payload.badzone.example", "badzone.example", true},
		{"a.b.badzone.example", "badzone.example", true},
		{"badzone.example", "badzone.example", true},
		{"example", "", false}, // bare single-label suffix-ish
		{"sub.foo.co.uk", "foo.co.uk", true},
		{"foo.co.uk", "foo.co.uk", true},
		{"co.uk", "", false}, // bare multi-part suffix
		{"deep.sub.example.com", "example.com", true},
		{"localhost", "", false}, // single label
		{"", "", false},
		{"a..b.com", "", false}, // empty label
		{"host.unknownfaketld", "", false},
	}
	for _, tc := range cases {
		got, ok := eTLDPlusOne(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("eTLDPlusOne(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsPublicDomain(t *testing.T) {
	public := []string{"badzone.example", "sub.foo.co.uk", "c2.qxv-rotator.example"}
	private := []string{
		"nas.local", "printer.lan", "x.home", "y.internal", "z.corp",
		"printer.home.arpa", "5.2.0.192.in-addr.arpa", "localhost", "",
		"192.0.2.10", "evil.example/path", "user@host.example", "with space.example",
	}
	for _, d := range public {
		if !isPublicDomain(d) {
			t.Errorf("expected %q public", d)
		}
	}
	for _, d := range private {
		if isPublicDomain(d) {
			t.Errorf("expected %q NOT public", d)
		}
	}
}
