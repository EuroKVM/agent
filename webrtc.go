// WebRTC console — preview path (MJPEG over DataChannel).
//
// The agent serves a `video` DataChannel that streams JPEG frames pulled
// from kvmd's existing MJPEG endpoint (/streamer/stream). The browser
// renders them to a <canvas> via createImageBitmap.
//
// This path was chosen because every KVM-over-IP product emits MJPEG
// while H.264 / VP8 sources are vendor-specific — it lets one shape ship
// today across PiKVM, Supermicro IPMI viewers, etc. The trade-off is real
// and visible: bandwidth at 1080p is several times higher than a hardware
// H.264 track would consume. The pipeline is tuned to keep latency low
// under that constraint (see pumpKvmdMJPEG below), but it is honestly a
// preview while we work toward per-vendor H.264.
//
// The per-vendor video roadmap (PiKVM kvmd-H.264 via Janus, noVNC for
// VNC-only BMCs, iframe pass-through for iDRAC / iLO HTML5 viewers) lives
// at docs/roadmap/console-video.md.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"nhooyr.io/websocket"
)

func makeWebrtcOfferHandler(cfg config, kvmdBasicAuth string, cookies []*http.Cookie, transport http.RoundTripper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			SDP  string `json:"sdp"`
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Type != "offer" || req.SDP == "" {
			http.Error(w, "type must be 'offer' and sdp must be non-empty", http.StatusBadRequest)
			return
		}

		iceServers := []webrtc.ICEServer{
			{URLs: []string{"stun:stun.cloudflare.com:3478"}},
		}
		if turnURL := os.Getenv("KVMFLEET_TURN_URL"); turnURL != "" {
			iceServers = append(iceServers, webrtc.ICEServer{
				URLs:           []string{turnURL},
				Username:       os.Getenv("KVMFLEET_TURN_USERNAME"),
				Credential:     os.Getenv("KVMFLEET_TURN_PASSWORD"),
				CredentialType: webrtc.ICECredentialTypePassword,
			})
		}

		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: iceServers})
		if err != nil {
			http.Error(w, "newPeerConnection: "+err.Error(), http.StatusInternalServerError)
			return
		}

		streamCtx, streamCancel := context.WithCancel(context.Background())

		// Establishment watchdog. The cleanup below fires on ICE/connection
		// Failed/Closed — but a peer that completes the SDP exchange and then
		// never connects (or abandons) drives neither, so without this the
		// PeerConnection, its UDP sockets, and the HID worker goroutine leak
		// until Pion's internal timeout. A remote caller looping the offer
		// endpoint could exhaust FDs/goroutines faster than they expire. The
		// timer reclaims the session unless it reaches Connected first.
		var connectedOnce sync.Once
		connected := make(chan struct{})
		go func() {
			select {
			case <-connected:
			case <-streamCtx.Done():
			case <-time.After(30 * time.Second):
				log.Printf("webrtc: peer did not connect within 30s — reclaiming session")
				streamCancel()
				_ = pc.Close()
			}
		}()

		pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
			log.Printf("webrtc: ICE state = %s", s.String())
			if s == webrtc.ICEConnectionStateFailed || s == webrtc.ICEConnectionStateClosed {
				streamCancel()
				_ = pc.Close()
			}
		})
		pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
			log.Printf("webrtc: connection state = %s", s.String())
			if s == webrtc.PeerConnectionStateConnected {
				connectedOnce.Do(func() { close(connected) }) // stop the watchdog
			}
			if s == webrtc.PeerConnectionStateClosed || s == webrtc.PeerConnectionStateFailed {
				streamCancel()
				_ = pc.Close()
			}
		})

		// HID dispatcher (single-worker, ordered, mouse-move coalescing).
		//
		// Pion serialises OnMessage per-channel. We can't make the
		// callback synchronous (a slow kvmd round-trip would stall the
		// channel and silently drop subsequent events). We also can't
		// fire-and-forget into goroutines per event — fast mouse drags
		// produce parallel HTTP POSTs that arrive at kvmd OUT OF ORDER,
		// so the cursor jumps to stale positions after fresh ones land.
		//
		// Compromise: one dedicated worker goroutine per session that
		// drains a small channel and POSTs serially. The channel holds
		// at most ONE pending mouse-move — a new mouse-move displaces
		// the old one. Keys/buttons go in unmodified so they're never
		// lost.
		hidQueue := make(chan []byte, 16) // small buffer; serial drain
		var hidPendingMoveMu sync.Mutex
		var hidPendingMove []byte
		go func() {
			for {
				select {
				case <-streamCtx.Done():
					return
				case payload := <-hidQueue:
					forwardHIDEvent(cfg, kvmdBasicAuth, cookies, transport, payload)
					// After draining a non-move event, also flush any
					// queued mouse-move so the cursor lands at the
					// latest position.
					hidPendingMoveMu.Lock()
					move := hidPendingMove
					hidPendingMove = nil
					hidPendingMoveMu.Unlock()
					if move != nil {
						forwardHIDEvent(cfg, kvmdBasicAuth, cookies, transport, move)
					}
				}
			}
		}()
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			log.Printf("webrtc: data channel '%s' opened (id=%d)", dc.Label(), dc.ID())
			switch dc.Label() {
			case "hid":
				dc.OnMessage(func(msg webrtc.DataChannelMessage) {
					if !msg.IsString {
						return
					}
					payload := append([]byte(nil), msg.Data...)
					// Quick peek at the event type — mouse-move events
					// get coalesced into hidPendingMove (latest wins),
					// everything else queues normally so keypresses
					// + clicks are never dropped.
					if isMouseMoveEvent(payload) {
						hidPendingMoveMu.Lock()
						hidPendingMove = payload
						hidPendingMoveMu.Unlock()
						// Wake the worker if it's idle. Non-blocking:
						// if the queue is full there's already pending
						// work and the worker will pick up the move
						// when it finishes.
						select {
						case hidQueue <- payload:
							// We enqueued; clear pending so the worker
							// doesn't double-send.
							hidPendingMoveMu.Lock()
							if bytesEqual(hidPendingMove, payload) {
								hidPendingMove = nil
							}
							hidPendingMoveMu.Unlock()
						default:
						}
					} else {
						// Keys + buttons: must not be lost. Block
						// briefly if the queue is full.
						select {
						case hidQueue <- payload:
						case <-streamCtx.Done():
						case <-time.After(500 * time.Millisecond):
							log.Printf("webrtc HID: dropped key/button event after 500ms wait — queue stuck")
						}
					}
				})
			case "video":
				dc.OnOpen(func() {
					log.Printf("webrtc: video data channel open; subscribing as kvmd stream-client + starting MJPEG pump")
					// Open the kvmd state-WS in the background. While it's
					// alive, kvmd's __has_stream_clients() counts us and
					// keeps ustreamer alive. Close it when streamCtx
					// cancels (i.e. when the WebRTC session ends).
					go subscribeKvmdStreamer(streamCtx, cfg, kvmdBasicAuth, cookies, transport)
					// pumpKvmdMJPEG retries on 502 internally for up
					// to 5s — covers the kvmd-spawn race where the
					// subscription has fired but ustreamer hasn't
					// finished initialising. No stale-socket check
					// needed.
					go pumpKvmdMJPEG(streamCtx, cfg, kvmdBasicAuth, cookies, transport, dc)
				})
			default:
				log.Printf("webrtc: ignoring unknown channel %q", dc.Label())
			}
		})

		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  req.SDP,
		}); err != nil {
			streamCancel()
			_ = pc.Close()
			http.Error(w, "setRemoteDescription: "+err.Error(), http.StatusBadRequest)
			return
		}

		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			streamCancel()
			_ = pc.Close()
			http.Error(w, "createAnswer: "+err.Error(), http.StatusInternalServerError)
			return
		}

		gatherComplete := webrtc.GatheringCompletePromise(pc)
		if err := pc.SetLocalDescription(answer); err != nil {
			streamCancel()
			_ = pc.Close()
			http.Error(w, "setLocalDescription: "+err.Error(), http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		select {
		case <-gatherComplete:
		case <-ctx.Done():
			log.Printf("webrtc: ICE gathering timeout, returning partial SDP")
		}

		local := pc.LocalDescription()
		if local == nil {
			streamCancel()
			_ = pc.Close()
			http.Error(w, "no local description", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sdp":  local.SDP,
			"type": local.Type.String(),
		})
	}
}

// pumpKvmdMJPEG pulls the multipart MJPEG stream from kvmd and forwards
// each JPEG frame as one binary message on the data channel. Uses the
// same Basic-auth + session-cookie scheme as the existing iframe console
// proxy, which is the known-good auth path on kvmd.
//
// Three concurrent levers keep latency bounded under variable bandwidth:
//
//   1. Frame-count backpressure. We track a sliding average of frame
//      size and drop frames when the SCTP send buffer holds more than
//      ~2.5 frames' worth of data. Stale frames are useless for
//      real-time display; the next one is ~33 ms away.
//
//   2. Proactive inter-frame skip. When sustained drop rate exceeds 30%,
//      we halve the source pull rate (skip alternate frames before
//      sending). This stops the buffer filling at all when the link is
//      genuinely slower than the source.
//
//   3. ordered=false on the browser side. A lost SCTP fragment doesn't
//      block newer frames behind a retransmit timeout; the next frame
//      arrives as soon as it's intact.
//
// The agent's data-channel ordering is set by the browser's offer; this
// function does not configure it directly.
func pumpKvmdMJPEG(ctx context.Context, cfg config, basicAuth string, cookies []*http.Cookie, transport http.RoundTripper, dc *webrtc.DataChannel) {
	streamURL := strings.TrimRight(cfg.KvmdURL, "/") + "/streamer/stream"

	// Retry the initial GET while kvmd's stream-controller is busy
	// spawning ustreamer. Cold-spawn typically completes in 200-800 ms,
	// but the very first frame can take longer. We retry on 502 (no
	// socket yet) and 503 (kvmd refuses) for up to 5 s.
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	attempt := 0
	for {
		attempt++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
		if err != nil {
			log.Printf("webrtc video: new request: %v", err)
			return
		}
		req.Header.Set("Authorization", basicAuth)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		// Long-running stream; no client-side timeout.
		client := &http.Client{Transport: transport}
		r, err := client.Do(req)
		if err != nil {
			log.Printf("webrtc video: GET %s: %v", streamURL, err)
			return
		}
		if r.StatusCode == 502 || r.StatusCode == 503 {
			_ = r.Body.Close()
			if time.Now().After(deadline) || ctx.Err() != nil {
				log.Printf("webrtc video: kvmd %s returned %d after %d attempts; giving up", streamURL, r.StatusCode, attempt)
				return
			}
			// Linear backoff — 200 ms keeps the retry rate light
			// without delaying the first frame much once ustreamer
			// finishes initialising.
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if r.StatusCode >= 400 {
			buf, _ := io.ReadAll(io.LimitReader(r.Body, 256))
			_ = r.Body.Close()
			log.Printf("webrtc video: kvmd %s returned %d: %s",
				streamURL, r.StatusCode, string(buf))
			return
		}
		if attempt > 1 {
			log.Printf("webrtc video: kvmd %s returned 200 on attempt %d", streamURL, attempt)
		}
		resp = r
		break
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		log.Printf("webrtc video: unexpected Content-Type %q from %s", ct, streamURL)
		return
	}
	boundary, ok := params["boundary"]
	if !ok {
		log.Printf("webrtc video: no boundary in Content-Type %q", ct)
		return
	}
	log.Printf("webrtc video: MJPEG stream open from %s (boundary=%s)", streamURL, boundary)

	mr := multipart.NewReader(resp.Body, boundary)
	var (
		frames     uint64
		dropped    uint64
		skipped    uint64
		avgSize    float64 // EWMA of frame size in bytes
		recent     int     // sliding 30-frame window count
		recentDrop int     // drops in that window
		skipEvery  int     // 0 = no skip, 2 = drop every other frame
		frameIdx   uint64
	)
	const (
		// Backpressure threshold expressed in frame-equivalents.
		// ~2.5 frames in flight at any size keeps perceptual lag below
		// ~80 ms even on 4K stills.
		bufferFrameCap = 2.5
		// EWMA smoothing for frame size — keeps the running average
		// stable while still adapting within a couple of seconds.
		ewmaAlpha = 0.05
		// Window of recent frames used to estimate sustained drop rate.
		dropWindow = 30
		// If drop rate exceeds this fraction across the window, we
		// proactively skip alternate frames (halve the pull rate).
		skipTriggerFraction = 0.30
	)
	logger := newRateLimitedLogger(15 * time.Second)
	defer logger.flush()

	for {
		if ctx.Err() != nil {
			return
		}
		part, err := mr.NextPart()
		if err == io.EOF {
			log.Printf("webrtc video: stream ended after %d frames (%d dropped, %d skipped)", frames, dropped, skipped)
			return
		}
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("webrtc video: read part: %v", err)
			}
			return
		}
		jpeg, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil || len(jpeg) == 0 {
			continue
		}

		frameIdx++

		// Proactive inter-frame skip when the link is sustainedly
		// slower than the source. Cheaper than waiting for the buffer
		// to fill, then dropping reactively.
		if skipEvery > 0 && frameIdx%uint64(skipEvery) != 0 {
			skipped++
			continue
		}

		// Update EWMA of frame size BEFORE the backpressure check so
		// the first few frames use their own size as the threshold.
		if avgSize == 0 {
			avgSize = float64(len(jpeg))
		} else {
			avgSize = ewmaAlpha*float64(len(jpeg)) + (1-ewmaAlpha)*avgSize
		}

		// Frame-count backpressure — adapts to variable frame size.
		// Drops the new frame rather than letting the SCTP buffer
		// grow unbounded; a stale frame is useless for real-time
		// display.
		threshold := uint64(bufferFrameCap * avgSize)
		if dc.BufferedAmount() > threshold {
			dropped++
			recentDrop++
		} else {
			if err := dc.Send(jpeg); err != nil {
				if ctx.Err() == nil {
					log.Printf("webrtc video: dc.Send error: %v", err)
				}
				return
			}
			frames++
		}
		recent++

		// Re-evaluate skip heuristic on every full window.
		if recent >= dropWindow {
			ratio := float64(recentDrop) / float64(recent)
			switch {
			case ratio >= skipTriggerFraction && skipEvery < 4:
				if skipEvery == 0 {
					skipEvery = 2
				} else {
					skipEvery *= 2
				}
				log.Printf("webrtc video: drop rate %.0f%% over last %d frames — skip-every=%d",
					ratio*100, recent, skipEvery)
			case ratio < skipTriggerFraction/3 && skipEvery > 0:
				// Plenty of headroom — relax the skip rate.
				if skipEvery == 2 {
					skipEvery = 0
				} else {
					skipEvery /= 2
				}
				log.Printf("webrtc video: drop rate %.0f%% — relaxing to skip-every=%d",
					ratio*100, skipEvery)
			}
			recent = 0
			recentDrop = 0
		}

		logger.maybeLog("webrtc video: %d sent, %d dropped, %d skipped, avg %.0fB, buf %dB, skip-every=%d",
			frames, dropped, skipped, avgSize, dc.BufferedAmount(), skipEvery)
	}
}

// --- utilities ------------------------------------------------------------

type rateLimitedLogger struct {
	interval time.Duration
	mu       sync.Mutex
	last     time.Time
	pending  string
}

func newRateLimitedLogger(interval time.Duration) *rateLimitedLogger {
	return &rateLimitedLogger{interval: interval}
}

func (l *rateLimitedLogger) maybeLog(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.last) < l.interval {
		l.pending = fmt.Sprintf(format, args...)
		return
	}
	l.last = now
	log.Printf(format, args...)
	l.pending = ""
}

func (l *rateLimitedLogger) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending != "" {
		log.Print(l.pending)
		l.pending = ""
	}
}

// --- HID forwarder (unchanged from phase 1) -------------------------------

func forwardHIDEvent(cfg config, basicAuth string, cookies []*http.Cookie, transport http.RoundTripper, raw []byte) {
	var ev struct {
		Type   string `json:"type"`
		Code   string `json:"code,omitempty"`
		State  bool   `json:"state,omitempty"`
		DX     int    `json:"dx,omitempty"`
		DY     int    `json:"dy,omitempty"`
		Button string `json:"button,omitempty"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return
	}

	var path string
	switch ev.Type {
	case "key":
		path = fmt.Sprintf(
			"/api/hid/events/send_key?key=%s&state=%v",
			url.QueryEscape(ev.Code),
			ev.State,
		)
	case "mouse-button":
		path = fmt.Sprintf(
			"/api/hid/events/send_mouse_button?button=%s&state=%v",
			url.QueryEscape(ev.Button),
			ev.State,
		)
	case "mouse-move":
		path = fmt.Sprintf("/api/hid/events/send_mouse_move?to_x=%d&to_y=%d", ev.DX, ev.DY)
	case "mouse-wheel":
		path = fmt.Sprintf("/api/hid/events/send_mouse_wheel?delta_x=%d&delta_y=%d", ev.DX, ev.DY)
	default:
		return
	}

	target := strings.TrimRight(cfg.KvmdURL, "/") + path
	req, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", basicAuth)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("webrtc HID forward error (%s): %v", ev.Type, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(resp.Body)
		log.Printf("webrtc HID forward kvmd %d: %s", resp.StatusCode, string(buf[:min(200, len(buf))]))
	}
}

// subscribeKvmdStreamer opens a long-lived WebSocket to kvmd's
// /api/ws?stream=1 endpoint and holds it open for the lifetime of ctx.
//
// kvmd's server.py runs a stream-controller loop that calls
// `ensure_start` on the streamer whenever `__has_stream_clients()` is
// true — and that helper counts WebSocket connections to `/api/ws`
// whose query string includes `stream=1`. So opening (and holding)
// this WS is how the standard PiKVM web UI keeps ustreamer alive;
// hitting `/api/streamer` GETs / `/api/streamer/snapshot` doesn't —
// kvmd refuses to spawn on those when the streamer is stopped.
//
// We swallow inbound messages because they're the standard kvmd
// state-stream events (streamer_state, hid_state, etc.) which we
// don't currently need on the agent side.
func subscribeKvmdStreamer(ctx context.Context, cfg config, basicAuth string, cookies []*http.Cookie, transport http.RoundTripper) {
	wsURL := strings.TrimRight(cfg.KvmdURL, "/") + "/api/ws?stream=1"
	if strings.HasPrefix(wsURL, "https") {
		wsURL = "wss" + wsURL[len("https"):]
	} else if strings.HasPrefix(wsURL, "http") {
		wsURL = "ws" + wsURL[len("http"):]
	}
	headers := http.Header{"Authorization": {basicAuth}}
	var cookieParts []string
	for _, c := range cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	if len(cookieParts) > 0 {
		headers.Set("Cookie", strings.Join(cookieParts, "; "))
	}
	opts := &websocket.DialOptions{
		HTTPHeader: headers,
		HTTPClient: &http.Client{Transport: transport},
	}

	c, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		log.Printf("kvmd stream-client: dial %s: %v", wsURL, err)
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	c.SetReadLimit(1024 * 1024)
	log.Printf("kvmd stream-client: subscription open — ustreamer will stay alive for this session")

	for {
		if _, _, err := c.Read(ctx); err != nil {
			log.Printf("kvmd stream-client: subscription ended: %v", err)
			return
		}
	}
}

// isMouseMoveEvent does a cheap byte-level check on the HID JSON
// payload. The browser sends `{"type":"mouse-move",...}` — we look for
// the literal substring so we don't have to JSON-decode the message
// twice (the agent forwarder decodes it for real later).
func isMouseMoveEvent(payload []byte) bool {
	const needle = `"type":"mouse-move"`
	if len(payload) < len(needle) {
		return false
	}
	// Fast path: scan once. The payload is small (~80 bytes).
	for i := 0; i+len(needle) <= len(payload); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if payload[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

