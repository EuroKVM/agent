// Agent-side serial bridge — handles `ws.open` for path `/api/serial`.
//
// Stock PiKVM kvmd has no `/api/serial` endpoint. The platform's
// Serial console feature (routers/serial.py) asks the agent to open a
// local WebSocket to that path and bridge frames; without an upstream
// the dial fails and the platform closes the browser-side WS with
// code 4504.
//
// This file plugs the gap. handleSerialOpen is called from
// handleWSOpen (main.go) when the requested path is /api/serial. Two
// modes:
//
//   - **Real serial.** KVMFLEET_SERIAL_DEV points at /dev/ttyUSB0
//     (or similar). The agent opens the TTY at the configured baud,
//     bridges browser ↔ wire. Echo behaviour is whatever the wired
//     target does — typically a real shell / BIOS / IOS that echoes.
//
//   - **Loopback shell (pty).** KVMFLEET_SERIAL_DEV=loopback. The
//     agent spawns /bin/bash (falling back to /bin/sh) on a pty pair
//     and bridges browser ↔ pty-master, giving a real interactive
//     shell without any hardware wired. Because that shell is reachable
//     by whoever opens the channel (the platform), it is gated: it
//     requires KVMFLEET_ALLOW_LOOPBACK_SHELL=1 AND runs UNPRIVILEGED
//     (dropped to KVMFLEET_LOOPBACK_SHELL_USER, default `nobody`) — the
//     agent refuses to bridge a root shell.
//
// install.sh probes /dev/ttyUSB0 → /dev/ttyACM0 → /dev/ttyAMA0 and
// writes the first match. With no serial hardware it enables the
// loopback shell ONLY for the console-less experimental device kinds
// (JetKVM / TinyPilot / NanoKVM); every other device leaves the serial
// bridge disabled unless an operator opts in deliberately.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const defaultSerialBaud = 115200

// activeSerial enforces "one session per TTY" so a second click
// preempts the first instead of two browsers fighting one UART.
// activeSerialProc tracks any spawned loopback shell so we can kill
// the child on session takeover.
var (
	activeSerialFile *os.File
	activeSerialProc *os.Process
	activeSerialMu   sync.Mutex
)

func handleSerialOpen(ctx context.Context, writes chan<- []byte, channelID string, cfg config) {
	dev := cfg.SerialDev
	if dev == "" {
		log.Printf("ws.open: /api/serial requested but KVMFLEET_SERIAL_DEV is unset")
		sendWSClose(writes, channelID)
		return
	}

	var file *os.File
	var childProc *os.Process
	var sessionLabel string

	if dev == "loopback" {
		// A loopback shell is reachable by whoever opens this channel — i.e.
		// the platform. Refuse unless explicitly allowed, so a compromised
		// platform can't turn a stray "loopback" config into a remote shell.
		if !cfg.AllowLoopbackShell {
			log.Printf("ws.open: /api/serial requested the loopback shell but KVMFLEET_ALLOW_LOOPBACK_SHELL is not set — REFUSING. A platform-reachable shell must be explicitly enabled.")
			sendWSClose(writes, channelID)
			return
		}
		// Spawn a real interactive shell on a pty so the operator
		// gets prompts + echo without any hardware wired. Dropped to an
		// unprivileged user — never root.
		f, proc, err := startLoopbackShell(cfg.LoopbackShellUser)
		if err != nil {
			log.Printf("ws.open: loopback shell: %v", err)
			sendWSClose(writes, channelID)
			return
		}
		file = f
		childProc = proc
		sessionLabel = "loopback shell"
	} else {
		if _, err := os.Stat(dev); errors.Is(err, os.ErrNotExist) {
			log.Printf("ws.open: serial device %s missing (USB-TTL adapter unplugged?)", dev)
			sendWSClose(writes, channelID)
			return
		} else if err != nil {
			log.Printf("ws.open: stat %s: %v", dev, err)
			sendWSClose(writes, channelID)
			return
		}
		baud := cfg.SerialBaud
		if baud == 0 {
			baud = defaultSerialBaud
		}
		if err := configureSerial(dev, baud); err != nil {
			log.Printf("ws.open: stty %s: %v", dev, err)
			sendWSClose(writes, channelID)
			return
		}
		f, err := os.OpenFile(dev, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err != nil {
			log.Printf("ws.open: open %s: %v", dev, err)
			sendWSClose(writes, channelID)
			return
		}
		file = f
		sessionLabel = fmt.Sprintf("%s @ %d baud", dev, baud)
	}

	// Preempt any prior session on the same TTY.
	activeSerialMu.Lock()
	if prev := activeSerialFile; prev != nil {
		_ = prev.Close()
	}
	if prev := activeSerialProc; prev != nil {
		_ = prev.Kill()
	}
	activeSerialFile = file
	activeSerialProc = childProc
	activeSerialMu.Unlock()

	dialCtx, cancel := context.WithCancel(ctx)
	ch := &wsChannel{cancel: cancel, serialOut: file}
	wsChannelsMu.Lock()
	wsChannels[channelID] = ch
	wsChannelsMu.Unlock()

	// Tell the platform the channel is open so the browser-side WS
	// completes its handshake (no more 4504).
	opened, _ := json.Marshal(map[string]any{"type": "ws.opened", "channel": channelID})
	select {
	case writes <- opened:
	case <-dialCtx.Done():
		_ = file.Close()
		return
	}

	log.Printf("serial: session %s open on %s", channelID[:8], sessionLabel)

	// TTY → platform reader goroutine.
	go func() {
		defer func() {
			cancel()
			activeSerialMu.Lock()
			if activeSerialFile == file {
				activeSerialFile = nil
			}
			if childProc != nil && activeSerialProc == childProc {
				activeSerialProc = nil
			}
			activeSerialMu.Unlock()
			_ = file.Close()
			if childProc != nil {
				_ = childProc.Kill()
				_, _ = childProc.Wait()
			}
			wsChannelsMu.Lock()
			delete(wsChannels, channelID)
			wsChannelsMu.Unlock()
			sendWSClose(writes, channelID)
			log.Printf("serial: session %s closed", channelID[:8])
		}()

		buf := make([]byte, 4096)
		for {
			if dialCtx.Err() != nil {
				return
			}
			n, rerr := file.Read(buf)
			if n > 0 {
				frame := map[string]any{
					"type":     "ws.frame",
					"channel":  channelID,
					"binary":   true,
					"data_b64": base64.StdEncoding.EncodeToString(buf[:n]),
				}
				b, _ := json.Marshal(frame)
				select {
				case writes <- b:
				case <-dialCtx.Done():
					return
				case <-time.After(5 * time.Second):
					return
				}
			}
			if rerr != nil && !errors.Is(rerr, syscall.EAGAIN) && !errors.Is(rerr, io.EOF) {
				return
			}
			if n == 0 {
				// Idle poll — 5 ms keeps perceived latency below human
				// reading speed without a tight busy-loop.
				select {
				case <-dialCtx.Done():
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
	}()
}

// configureSerial puts the TTY into raw 8N1 at the requested baud
// rate using `stty`. CGO-free; works for USB-CDC / FTDI / CH340 /
// Pi UART.
func configureSerial(dev string, baud int) error {
	cmd := exec.Command("stty", "-F", dev,
		fmt.Sprintf("%d", baud),
		"raw", "-echo", "-echoe", "-echok", "-echoctl", "-echoke",
		"cs8", "-cstopb", "-parenb", "ignbrk", "-icrnl", "-ixon", "-ixoff",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// --- Loopback pty + shell ------------------------------------------

// Linux ioctl numbers for pty ops. Hardcoded because Go's `syscall`
// package doesn't expose them on all build targets and we don't want
// a second dep for two constants.
const (
	linuxTIOCSPTLCK = 0x40045431 // unlockpt
	linuxTIOCGPTN   = 0x80045430 // ptsname (returns the slave number)
)

// startLoopbackShell allocates a pty pair, spawns /bin/bash as a child
// process attached to the slave, and returns the master file +
// process handle. The master is set non-blocking to match the read
// loop in handleSerialOpen.
//
// The operator gets a real interactive shell: real prompts, real
// echo (the tty line discipline + bash echo together), real command
// execution. No "fake" feel.
func startLoopbackShell(dropUser string) (*os.File, *os.Process, error) {
	// Resolve the unprivileged account to drop to. The agent runs as root for
	// device access, but the bridged shell must NOT — otherwise a compromised
	// platform that opens this channel gets root on the customer's box. If we
	// ARE root we require a valid non-root target and refuse to continue
	// without one (fail closed); if we're already unprivileged we just inherit.
	cred, dropHome, dropName, err := resolveDropCredential(dropUser)
	if err != nil {
		return nil, nil, err
	}

	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}

	// Unlock the slave.
	var unlock int32 = 0
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, ptmx.Fd(),
		uintptr(linuxTIOCSPTLCK), uintptr(unsafe.Pointer(&unlock)),
	); errno != 0 {
		_ = ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %v", errno)
	}

	// Find the slave path via the slave number.
	var ptn int32
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, ptmx.Fd(),
		uintptr(linuxTIOCGPTN), uintptr(unsafe.Pointer(&ptn)),
	); errno != 0 {
		_ = ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCGPTN: %v", errno)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptn)

	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		return nil, nil, fmt.Errorf("open slave %s: %w", slavePath, err)
	}

	shell := "/bin/bash"
	if _, err := os.Stat(shell); errors.Is(err, os.ErrNotExist) {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell, "-il")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"HOME="+dropHome,
		"USER="+dropName,
		"LOGNAME="+dropName,
		"SHELL="+shell,
		"PS1=\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]$ ",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Setctty:    true,
		Credential: cred, // nil when already unprivileged; drops to dropUser when root
	}

	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		_ = slave.Close()
		return nil, nil, fmt.Errorf("start %s: %w", shell, err)
	}
	// Child has the slave; we don't need our copy.
	_ = slave.Close()

	// Non-blocking master so the read loop's EAGAIN logic works
	// without the kernel ever blocking on us.
	if err := syscall.SetNonblock(int(ptmx.Fd()), true); err != nil {
		log.Printf("loopback: SetNonblock failed (continuing): %v", err)
	}

	log.Printf("loopback: spawned %s pid=%d on %s as user=%s", shell, cmd.Process.Pid, slavePath, dropName)
	return ptmx, cmd.Process, nil
}

// resolveDropCredential decides the unprivileged identity the loopback shell
// runs as. Returns (credential, HOME, USER, error).
//
//   - Running as root: the configured user MUST resolve to a non-root uid; we
//     return a *syscall.Credential that drops to it (with its supplementary
//     groups). If it can't be resolved, or resolves to uid 0, we FAIL — we will
//     not spawn a root shell bridged to the platform tunnel.
//   - Already unprivileged: return a nil credential (inherit the agent's own
//     uid — already not root) so deployments running the agent as a non-root
//     user keep working without needing the drop account to exist.
func resolveDropCredential(dropUser string) (cred *syscall.Credential, home, name string, err error) {
	euid := os.Geteuid()
	if dropUser == "" {
		dropUser = "nobody"
	}
	u, lookErr := user.Lookup(dropUser)

	if euid != 0 {
		// Already unprivileged — inherit. Prefer the configured user's metadata
		// for HOME/USER when resolvable, else fall back to the running user.
		if lookErr == nil {
			return nil, homeOrTmp(u.HomeDir), u.Username, nil
		}
		self, _ := user.Current()
		nm := "agent"
		hm := "/tmp"
		if self != nil {
			nm = self.Username
			hm = homeOrTmp(self.HomeDir)
		}
		return nil, hm, nm, nil
	}

	// We are root: a valid non-root target is mandatory.
	if lookErr != nil {
		return nil, "", "", fmt.Errorf("loopback shell: drop-user %q cannot be resolved (%v) — refusing to run a root shell; create the user or set KVMFLEET_LOOPBACK_SHELL_USER", dropUser, lookErr)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil, "", "", fmt.Errorf("loopback shell: drop-user %q has non-numeric uid/gid", dropUser)
	}
	if uid == 0 {
		return nil, "", "", fmt.Errorf("loopback shell: drop-user %q is root (uid 0) — refusing; the bridged shell must be unprivileged", dropUser)
	}
	var groups []uint32
	if gidStrs, gerr := u.GroupIds(); gerr == nil {
		for _, g := range gidStrs {
			if n, e := strconv.Atoi(g); e == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	return &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: groups,
	}, homeOrTmp(u.HomeDir), u.Username, nil
}

// homeOrTmp returns dir if it's an existing, usable directory, else /tmp — so a
// drop-user like `nobody` whose home is /nonexistent still gets a writable HOME.
func homeOrTmp(dir string) string {
	if dir == "" {
		return "/tmp"
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir
	}
	return "/tmp"
}
