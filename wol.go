// Agent-side Wake-on-LAN — handles the platform-originated `POST /internal/wol`
// http.request frame.
//
// A WoL magic packet is an L2 broadcast that must originate on the target host's
// own LAN segment. The platform in the cloud cannot broadcast into a customer
// LAN, so — like IPMI/PDU — the wake is emitted BY the agent already on that
// segment. Unlike the IPMI/PDU relay (a unicast datagram shuttle), WoL is a
// fire-and-forget broadcast with no reply, so it is a native agent command, not
// a relay channel.
//
// The platform sends the target MAC + a REQUIRED subnet-directed broadcast
// address (e.g. 192.168.20.255). We do NOT default to 255.255.255.255: on a
// multi-homed agent host the OS routes the global broadcast out one arbitrary
// interface, which may not be the target's segment. A subnet-directed address
// pins egress to the correct L2 network.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"syscall"
)

// wolRequest is the JSON body of POST /internal/wol.
type wolRequest struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast"`
	Port      int    `json:"port"`
}

// buildMagicPacket returns the 102-byte WoL payload: 6×0xFF followed by the
// 6-byte MAC repeated 16 times. Mirrors bmc-adapters wol._build_magic_packet.
func buildMagicPacket(hw net.HardwareAddr) []byte {
	pkt := make([]byte, 0, 6+16*len(hw))
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xff)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	return pkt
}

// sendMagicPacket opens a UDP socket with SO_BROADCAST and sends the packet to
// the subnet-directed broadcast address.
func sendMagicPacket(pkt []byte, broadcast string, port int) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Enable broadcast on the underlying socket.
	if raw, cerr := conn.SyscallConn(); cerr == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}

	dst := &net.UDPAddr{IP: net.ParseIP(broadcast), Port: port}
	_, err = conn.WriteTo(pkt, dst)
	return err
}

// wolHandler validates the request, builds the packet, and broadcasts it. A 204
// means the packet was EMITTED — never that the host woke (WoL is unverifiable).
func wolHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req wolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		wolError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	hw, err := net.ParseMAC(req.MAC)
	if err != nil || len(hw) != 6 {
		wolError(w, http.StatusBadRequest, "invalid_mac")
		return
	}
	bcast := net.ParseIP(req.Broadcast)
	if bcast == nil || bcast.To4() == nil {
		// Subnet-directed IPv4 broadcast is required; no global-broadcast default.
		wolError(w, http.StatusBadRequest, "no_broadcast_addr")
		return
	}
	port := req.Port
	if port == 0 {
		port = 9
	}
	if err := sendMagicPacket(buildMagicPacket(hw), req.Broadcast, port); err != nil {
		log.Printf("wol: send to %s:%d for %s failed: %v", req.Broadcast, port, hw, err)
		wolError(w, http.StatusBadGateway, "send_failed")
		return
	}
	log.Printf("wol: magic packet sent → %s via %s:%d", hw, req.Broadcast, port)
	w.WriteHeader(http.StatusNoContent)
}

func wolError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
