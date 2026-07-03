package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildMagicPacket(t *testing.T) {
	hw, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	pkt := buildMagicPacket(hw)
	if len(pkt) != 102 {
		t.Fatalf("packet len = %d, want 102", len(pkt))
	}
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xff {
			t.Fatalf("byte %d = %#x, want 0xff", i, pkt[i])
		}
	}
	// The MAC repeats 16 times starting at offset 6.
	if !bytes.Equal(pkt[6:12], hw) || !bytes.Equal(pkt[96:102], hw) {
		t.Fatalf("MAC not repeated correctly")
	}
}

func TestWolHandlerRejects(t *testing.T) {
	cases := []struct {
		name string
		body wolRequest
		want string
	}{
		{"bad mac", wolRequest{MAC: "nope", Broadcast: "192.168.1.255"}, "invalid_mac"},
		{"missing broadcast", wolRequest{MAC: "AA:BB:CC:DD:EE:FF"}, "no_broadcast_addr"},
		{"ipv6 broadcast", wolRequest{MAC: "AA:BB:CC:DD:EE:FF", Broadcast: "fe80::1"}, "no_broadcast_addr"},
	}
	for _, c := range cases {
		b, _ := json.Marshal(c.body)
		req := httptest.NewRequest(http.MethodPost, "/internal/wol", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		wolHandler(rec, req)
		if rec.Code < 400 {
			t.Errorf("%s: status %d, want 4xx", c.name, rec.Code)
			continue
		}
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out["error"] != c.want {
			t.Errorf("%s: error=%q, want %q", c.name, out["error"], c.want)
		}
	}
}

func TestWolHandlerRejectsGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/internal/wol", nil)
	rec := httptest.NewRecorder()
	wolHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}
}
