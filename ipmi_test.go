package main

import (
	"net"
	"testing"
)

func TestIPMITargetFromPath(t *testing.T) {
	type want struct {
		host string
		port int
	}
	cases := map[string]want{
		"/ipmi/relay?host=10.0.0.5":         {"10.0.0.5", 623},
		"/ipmi/relay?host=192.168.1.10&x=1": {"192.168.1.10", 623},
		"/ipmi/relay?host=bmc.local":        {"bmc.local", 623},
		"/ipmi/relay?host=10.0.5.20&port=161": {"10.0.5.20", 161},
		"/ipmi/relay?host=10.0.5.20&port=xx":  {"10.0.5.20", 623},
		"/ipmi/relay":                        {"", 623},
		"/ipmi/relay?host=":                  {"", 623},
		"/ipmi/relay?foo=bar":                {"", 623},
	}
	for path, w := range cases {
		host, port := ipmiTargetFromPath(path)
		if host != w.host || port != w.port {
			t.Errorf("ipmiTargetFromPath(%q) = (%q,%d), want (%q,%d)", path, host, port, w.host, w.port)
		}
	}
}

// relayPortAllowed gates the UDP target port — only IPMI/623 and SNMP/161.
func TestRelayPortAllowed(t *testing.T) {
	for _, p := range []int{623, 161} {
		if !relayPortAllowed(p) {
			t.Errorf("port %d should be allowed", p)
		}
	}
	for _, p := range []int{0, 22, 80, 443, 53, 8080, 65535} {
		if relayPortAllowed(p) {
			t.Errorf("port %d should be REFUSED", p)
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
