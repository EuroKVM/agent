package main

import (
	"net"
	"testing"
)

func TestIPMIHostFromPath(t *testing.T) {
	cases := map[string]string{
		"/ipmi/relay?host=10.0.0.5":            "10.0.0.5",
		"/ipmi/relay?host=192.168.1.10&x=1":    "192.168.1.10",
		"/ipmi/relay?host=bmc.local":           "bmc.local",
		"/ipmi/relay":                          "",
		"/ipmi/relay?host=":                     "",
		"/ipmi/relay?foo=bar":                  "",
	}
	for path, want := range cases {
		if got := ipmiHostFromPath(path); got != want {
			t.Errorf("ipmiHostFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// The relay must refuse to forward to a public address (no open UDP reflector);
// a BMC is always on the management LAN. ipPubliclyRoutable (shared with the ISO
// guard) is the gate — assert the IPMI-relevant cases here for intent.
func TestIPMIRelayTargetGuard(t *testing.T) {
	lanOK := []string{"10.0.0.5", "192.168.1.10", "172.16.4.4", "169.254.0.9", "127.0.0.1", "fd00::1"}
	for _, s := range lanOK {
		if ip := net.ParseIP(s); ip == nil || ipPubliclyRoutable(ip) {
			t.Errorf("%s should be allowed as a LAN BMC target", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range public {
		if ip := net.ParseIP(s); ip == nil || !ipPubliclyRoutable(ip) {
			t.Errorf("%s should be REFUSED (public) as an IPMI relay target", s)
		}
	}
}
