package discovery

// GHSA-c5gj: nmap option/argument injection. ValidateScanTarget must accept only
// clean supported scan targets (bare IPv4, IPv4 CIDR, nmap numeric range/list) and
// reject anything that begins with "-", contains whitespace, or contains a shell
// metacharacter. Synthetic values only.

import "testing"

func TestValidateScanTarget_Accepts(t *testing.T) {
	valid := []string{
		"192.168.1.1",     // bare IPv4
		"192.168.1.0/24",  // IPv4 CIDR
		"10.0.0.1-50",     // nmap octet range
		"192.168.1.1-254", // nmap octet range
		"10.0.0.1,2,3",    // nmap octet list
		"10.0.0-255.1-10", // nmap multi-octet range
	}
	for _, target := range valid {
		if err := ValidateScanTarget(target); err != nil {
			t.Errorf("expected %q to be accepted, got error: %v", target, err)
		}
	}
}

func TestValidateScanTarget_Rejects(t *testing.T) {
	invalid := []string{
		"",                       // empty
		"-oG",                    // leading dash → nmap flag injection
		"-192.168.1.1",           // leading dash
		"--script=http-vuln",     // leading dash
		"192.168.1.1 -oG /tmp/x", // whitespace + flag smuggling
		"192.168.1.1;rm -rf /",   // shell metachar ;
		"192.168.1.1|cat",        // pipe
		"192.168.1.1&whoami",     // ampersand
		"$(whoami)",              // command substitution
		"`id`",                   // backticks
		"host>out",               // redirection
		"a<b",                    // redirection
		"foo(bar)",               // parens
		"host'name",              // single quote
		"host\"name",             // double quote
		"10.0.0.1\t50",           // embedded tab
		"2001:db8::1",            // IPv6 unsupported by current sensor
		"2001:db8::/32",          // IPv6 CIDR unsupported
		"::ffff:192.0.2.1",       // mapped IPv6 must not become false-empty Nmap success
		"::ffff:192.0.2.1/128",   // mapped IPv6 CIDR must not normalize to IPv4
		"router.local",           // hostname scanning disabled in no-DNS mode
		"host-1.example.com",     // hostname scanning disabled in no-DNS mode
		"999.0.0.1",              // out-of-range numeric octet
		"10.0.0.1-999",           // out-of-range numeric range endpoint
	}
	for _, target := range invalid {
		if err := ValidateScanTarget(target); err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", target)
		}
	}
}
