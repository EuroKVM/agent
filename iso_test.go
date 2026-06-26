package main

import (
	"net"
	"testing"
)

func TestIPPubliclyRoutable(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"8.8.8.8", true, "public IPv4"},
		{"1.1.1.1", true, "public IPv4"},
		{"2606:4700:4700::1111", true, "public IPv6"},
		{"127.0.0.1", false, "loopback"},
		{"::1", false, "loopback v6"},
		{"10.0.0.5", false, "RFC1918 10/8"},
		{"172.16.3.4", false, "RFC1918 172.16/12"},
		{"192.168.1.10", false, "RFC1918 192.168/16"},
		{"169.254.169.254", false, "link-local — cloud metadata endpoint"},
		{"fe80::1", false, "link-local v6"},
		{"fc00::1", false, "ULA v6 (IsPrivate)"},
		{"224.0.0.1", false, "multicast"},
		{"0.0.0.0", false, "unspecified"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := ipPubliclyRoutable(ip); got != c.want {
			t.Errorf("ipPubliclyRoutable(%s) = %v, want %v (%s)", c.ip, got, c.want, c.why)
		}
	}
	if ipPubliclyRoutable(nil) {
		t.Error("nil IP must be rejected")
	}
}
