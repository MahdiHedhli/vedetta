package main

import "testing"

func TestValidateAdminListenAddr(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		allow bool
		ok    bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:9091", ok: true},
		{name: "ipv6 loopback", addr: "[::1]:9091", ok: true},
		{name: "wildcard refused", addr: "0.0.0.0:9091"},
		{name: "empty wildcard refused", addr: ":9091"},
		{name: "ipv6 wildcard refused", addr: "[::]:9091"},
		{name: "hostname refused", addr: "localhost:9091"},
		{name: "nonloopback explicit opt in", addr: "192.0.2.10:9091", allow: true, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdminListenAddr(tt.addr, tt.allow)
			if (err == nil) != tt.ok {
				t.Fatalf("validateAdminListenAddr(%q, %t) error=%v, want ok=%t", tt.addr, tt.allow, err, tt.ok)
			}
		})
	}
}
