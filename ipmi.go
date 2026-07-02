// Agent-side IPMI relay — handles `ws.open` for path `/ipmi/relay`.
//
// IPMI is RMCP+ over UDP port 623, and a BMC's IPMI interface lives on the
// management LAN — it is essentially never reachable from the platform's cloud
// egress (and exposing it would be the CVE-2013-4786 disaster). So the platform
// does NOT speak IPMI directly. Instead the agent, which already sits on the
// customer LAN, acts as a thin, stateless UDP relay: the platform's pyghmi
// client runs server-side and its raw RMCP+ datagrams are tunnelled here over
// the existing agent WS channel; the agent forwards each datagram to the BMC on
// the LAN and relays replies back.
//
// All IPMI protocol state (RAKP session, sequence numbers, cipher negotiation,
// findings) lives platform-side in Python. The agent owns nothing but the
// socket: one inbound ws.frame == one UDP datagram to the BMC; one datagram
// from the BMC == one outbound ws.frame. UDP preserves datagram boundaries, so
// the 1:1 framing pyghmi expects is maintained without any reassembly here.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultIPMIUDPPort is the RMCP/RMCP+ port. The relay also carries other
// LAN-management UDP protocols that share this exact machinery — notably SNMP
// (UDP 161) for PDU control — selected via the ?port= query param. We restrict
// the target to a small allowlist of known management ports so the relay can't
// be turned into a general-purpose UDP proxy.
const defaultIPMIUDPPort = 623

// relayPortAllowed gates which UDP ports the relay will dial. 623 = IPMI/RMCP+,
// 161 = SNMP (PDUs). Anything else is refused.
func relayPortAllowed(p int) bool {
	return p == 623 || p == 161
}

// maxIPMIDatagram caps a single relayed datagram. IPMI/RMCP+ packets are well
// under an Ethernet MTU; 9 KB covers jumbo-frame paranoia without allowing a
// peer to make us buffer large reads.
const maxIPMIDatagram = 9000

// handleIPMIRelayOpen bridges a platform WS channel to a BMC's UDP/623 endpoint
// on the local network. Path form: /ipmi/relay?host=<bmc-ip-or-hostname>.
//
// The target MUST resolve to a non-publicly-routable address (a BMC on the
// management LAN). We refuse to relay to a public IP so the agent can't be
// abused as an open UDP reflector toward the internet.
func handleIPMIRelayOpen(ctx context.Context, writes chan<- []byte, channelID, path string) {
	host, port := ipmiTargetFromPath(path)
	if host == "" {
		log.Printf("ipmi.relay: ws.open missing ?host=")
		sendWSClose(writes, channelID)
		return
	}
	if !relayPortAllowed(port) {
		log.Printf("ipmi.relay: REFUSING relay to disallowed port %d (only 623/161)", port)
		sendWSClose(writes, channelID)
		return
	}

	// Resolve + guard: only LAN / private / loopback targets are allowed.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		log.Printf("ipmi.relay: cannot resolve %q: %v", host, err)
		sendWSClose(writes, channelID)
		return
	}
	target := ips[0]
	if ipPubliclyRoutable(target) {
		log.Printf("ipmi.relay: REFUSING relay to public address %s for host %q (LAN-only)", target, host)
		sendWSClose(writes, channelID)
		return
	}

	raddr := &net.UDPAddr{IP: target, Port: port}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Printf("ipmi.relay: dial %s: %v", raddr, err)
		sendWSClose(writes, channelID)
		return
	}

	dialCtx, cancel := context.WithCancel(ctx)
	ch := &wsChannel{cancel: cancel, ipmiConn: conn}
	wsChannelsMu.Lock()
	wsChannels[channelID] = ch
	wsChannelsMu.Unlock()

	// Acknowledge the channel so the platform side completes its handshake.
	opened, _ := json.Marshal(map[string]any{"type": "ws.opened", "channel": channelID})
	select {
	case writes <- opened:
	case <-dialCtx.Done():
		_ = conn.Close()
		return
	}
	log.Printf("ipmi.relay: channel %s open → %s:%d", channelID[:8], target, port)

	// BMC → platform reader. Each UDP datagram becomes exactly one ws.frame.
	go func() {
		defer func() {
			cancel()
			wsChannelsMu.Lock()
			if wsChannels[channelID] == ch {
				delete(wsChannels, channelID)
			}
			wsChannelsMu.Unlock()
			_ = conn.Close()
			sendWSClose(writes, channelID)
			log.Printf("ipmi.relay: channel %s closed", channelID[:8])
		}()
		buf := make([]byte, maxIPMIDatagram)
		for {
			if dialCtx.Err() != nil {
				return
			}
			// A read deadline lets the loop notice ctx cancellation + lets an
			// idle IPMI session (60s inactivity) reclaim the socket.
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			n, rerr := conn.Read(buf)
			if n > 0 {
				frame, _ := json.Marshal(map[string]any{
					"type":     "ws.frame",
					"channel":  channelID,
					"binary":   true,
					"data_b64": base64.StdEncoding.EncodeToString(buf[:n]),
				})
				select {
				case writes <- frame:
				case <-dialCtx.Done():
					return
				}
			}
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					// Idle window elapsed with no traffic — end the relay; the
					// platform re-opens a channel for the next IPMI session.
					return
				}
				return
			}
		}
	}()
}

// ipmiTargetFromPath extracts (host, port) from /ipmi/relay?host=...&port=...
// port defaults to 623 (IPMI) when absent or unparseable; PDU relays pass
// port=161 (SNMP). The caller enforces the port allowlist.
func ipmiTargetFromPath(path string) (string, int) {
	q := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		q = path[i+1:]
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return "", 0
	}
	host := strings.TrimSpace(vals.Get("host"))
	port := defaultIPMIUDPPort
	if p := strings.TrimSpace(vals.Get("port")); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return host, port
}

// writeIPMIDatagram forwards one platform→BMC datagram. Called from
// handleWSFrame when the channel is an IPMI relay.
func writeIPMIDatagram(conn *net.UDPConn, data []byte) {
	if len(data) == 0 {
		return
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("ipmi.relay: write to BMC failed: %v", err)
	}
}
