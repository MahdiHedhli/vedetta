package dnscap

import (
	"reflect"
	"testing"
)

func TestDNSTypeName(t *testing.T) {
	cases := map[string]string{
		"1":   "A",
		"28":  "AAAA",
		"5":   "CNAME",
		"15":  "MX",
		"16":  "TXT",
		"12":  "PTR",
		"2":   "NS",
		"33":  "SRV",
		"65":  "HTTPS",
		"255": "ANY",
		"":    "",
		"999": "TYPE999",
		" 1 ": "A",
	}
	for in, want := range cases {
		if got := dnsTypeName(in); got != want {
			t.Errorf("dnsTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Fixtures use RFC 5737 / RFC 3849 documentation addresses and .example domains
// per the spec 006 env-data rule — never real captured data.
func TestParseQueryResults(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single A", "type: 1 192.0.2.34", []string{"192.0.2.34"}},
		{"cname then A", "type: 5 cname.example.com;type: 1 192.0.2.34", []string{"cname.example.com", "192.0.2.34"}},
		{"ipv4-mapped", "type: 1 ::ffff:198.51.100.7", []string{"198.51.100.7"}},
		{"trailing semicolon", "type: 28 2001:db8::1;", []string{"2001:db8::1"}},
		{"blank inner entry", "type: 1 203.0.113.1; ;type: 1 203.0.113.2", []string{"203.0.113.1", "203.0.113.2"}},
	}
	for _, c := range cases {
		if got := parseQueryResults(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseQueryResults(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}
