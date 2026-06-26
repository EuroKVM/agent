# KVM Fleet Agent

Lightweight fleet agent for KVM-over-IP devices. Connects any KVM device with a web interface to the [KVM Fleet](https://kvmfleet.io) management platform.

## What it does

- Enrolls with the platform using a single-use token
- Opens an outbound WebSocket tunnel (works behind NAT, CGNAT, firewalls — no inbound ports)
- Reports health metrics (temperature, uptime, agent version)
- Tunnels HTTP requests **and WebSocket connections** through the tunnel — enabling full interactive KVM console (live video, keyboard, mouse) from anywhere
- Reverse-proxies the device's web UI (kvmd, Janus video gateway, streamer) through the platform
- Connects to local Unix sockets directly (e.g. Janus WebRTC gateway) for maximum compatibility
- **Serial console** — bridges a local serial device (e.g. a USB-TTL adapter on `/dev/ttyUSB0`) to the platform's Serial console, for BIOS/UEFI, IPMI serial-over-LAN, switches, and other gear that only speaks UART
- Works with any KVM device that has a local web interface — no vendor lock-in

## Install

SSH into your KVM device and run:

```bash
curl -sSL https://app.kvmfleet.io/install | sh -s -- --token <your-enrollment-token>
```

Get a token from the [KVM Fleet dashboard](https://app.kvmfleet.io) → Fleet → + Add device.

The script detects your device type and architecture, downloads the right binary, sets up a service, and enrolls automatically.

## Supported architectures

| Architecture | Binary | Example devices |
|---|---|---|
| ARMv7 (armv7l) | `kvmfleet-agent.linux-arm` | PiKVM v3 (32-bit), JetKVM, NanoKVM |
| ARM64 (aarch64) | `kvmfleet-agent.linux-arm64` | PiKVM v4, Raspberry Pi 4 (64-bit OS) |
| x86_64 | `kvmfleet-agent.linux-amd64` | Generic Linux, VMs, any x86 KVM appliance |

Single static binary, ~5 MB, no dependencies.

## Tested with

- **PiKVM v3/v4** — full video (H.264 via Janus WebRTC), keyboard, mouse, virtual media
- **JetKVM** — web UI proxy (WebRTC planned)
- Any device with an HTTP/WebSocket-based web UI

## Works with any KVM web UI

The agent is device-agnostic. It reverse-proxies whatever local web interface you point it at:

```bash
# Auto-detected for known devices, or set manually:
KVMFLEET_KVMD_URL=http://127.0.0.1/       # most devices
KVMFLEET_KVMD_URL=https://127.0.0.1/      # devices with self-signed TLS (PiKVM)
KVMFLEET_KVMD_URL=http://192.168.1.50/    # proxy a device on the local network
```

If your KVM has a web interface, the agent can proxy it through the KVM Fleet platform.

## Build from source

```bash
# Native build
go build -trimpath -o kvmfleet-agent ./

# Cross-compile for ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o kvmfleet-agent.linux-arm64 ./

# Cross-compile for ARMv7
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -o kvmfleet-agent.linux-arm ./
```

## Configuration

All configuration via environment variables or flags:

| Env var | Flag | Default | Description |
|---|---|---|---|
| `KVMFLEET_API` | `--api` | `http://localhost:8000` | Platform URL |
| `KVMFLEET_TOKEN_FILE` | `--token-file` | — | Path to file containing enrollment token |
| `KVMFLEET_STATE` | `--state` | `/var/lib/kvmfleet/state.json` | Persistent state file |
| `KVMFLEET_DEVICE_NAME` | `--name` | hostname | Device name in dashboard |
| `KVMFLEET_DEVICE_TAGS` | `--tags` | — | Comma-separated tags |
| `KVMFLEET_HW_KIND` | `--hw-kind` | auto | Hardware type identifier |
| `KVMFLEET_KVMD_URL` | `--kvmd-url` | auto-detected | URL of local web UI to proxy |
| `KVMFLEET_KVMD_USER` | `--kvmd-user` | `admin` | Basic auth username for kvmd |
| `KVMFLEET_KVMD_PASS` | `--kvmd-pass` | `admin` | Basic auth password for kvmd |
| `KVMFLEET_CONSOLE_ADDR` | `--console-addr` | `:8080` | Local HTTP server bind (`off` to disable) |
| `KVMFLEET_SERIAL_DEV` | — | — | Serial device to bridge (e.g. `/dev/ttyUSB0`), or `loopback`. Empty disables the Serial console |
| `KVMFLEET_SERIAL_BAUD` | — | `115200` | Baud rate for the serial device |
| `KVMFLEET_ALLOW_LOOPBACK_SHELL` | — | `0` | Required (`1`) to allow `SERIAL_DEV=loopback` to spawn a shell |
| `KVMFLEET_LOOPBACK_SHELL_USER` | — | `nobody` | Unprivileged user the loopback shell drops to |

## How it works

```
KVM device (your network, behind NAT)
    │
    │  Agent opens outbound WSS connection
    │  (no inbound ports needed)
    │
    ▼
KVM Fleet Platform (app.kvmfleet.io)
    │
    │  Two tunnel types over one WebSocket:
    │
    │  1. HTTP request/response — for static pages,
    │     CSS, JS, images, API calls
    │
    │  2. WebSocket channels — for live video (Janus/
    │     WebRTC), keyboard/mouse (HID), and other
    │     persistent streams. Multiple channels
    │     multiplexed simultaneously.
    │
    ▼
Operator browser (anywhere)
    │
    └─ Full interactive KVM console:
       live video + keyboard + mouse
```

## Architecture

The agent maintains a single outbound WebSocket to the platform. Over this connection, two types of traffic are multiplexed:

**HTTP tunnel:** The platform sends `http.request` frames; the agent serves them from the local KVM web UI and returns `http.response` frames. Used for HTML pages, CSS, JavaScript, images, and API calls.

**WebSocket tunnel:** The platform sends `ws.open` frames to establish persistent bidirectional channels. Used for:
- **kvmd API** (`/api/ws`) — device state, HID events (keyboard/mouse)
- **Janus WebRTC** (`/janus/ws` via Unix socket) — H.264 live video stream
- **Streamer** (`/streamer`) — MJPEG fallback video
- **Serial console** (`/api/serial`) — raw serial bytes, bridged to a local UART (handled by the agent itself; stock kvmd has no serial endpoint)

Each WebSocket channel gets a unique ID and is multiplexed over the single agent tunnel. The agent routes Janus connections directly to the Unix socket (`/run/kvmd/janus-ws.sock`) for maximum compatibility.

## Serial console

When `KVMFLEET_SERIAL_DEV` points at a serial device, the agent opens it at the
configured baud (raw 8N1) and bridges it to the platform's Serial console — so
you reach a target's BIOS/UEFI, IPMI serial-over-LAN, or a switch/router console
through the same outbound tunnel, no extra ports. `install.sh` auto-detects
`/dev/ttyUSB0` → `/dev/ttyACM0` and writes the first match.

For hardware without a wired serial port, a **loopback** mode
(`KVMFLEET_SERIAL_DEV=loopback`) spawns a real interactive shell on a pty and
bridges that instead. Because that shell is reachable by whoever opens the
channel, it is **off by default** and must be enabled explicitly with
`KVMFLEET_ALLOW_LOOPBACK_SHELL=1`; even then it runs **unprivileged** (dropped to
`KVMFLEET_LOOPBACK_SHELL_USER`, default `nobody`) — the agent refuses to bridge a
root shell. `install.sh` only turns it on automatically for the console-less
experimental device kinds (JetKVM / TinyPilot / NanoKVM).

## Security

Found a security issue? **Don't** file a public GitHub issue. See
[SECURITY.md](SECURITY.md) for the reporting channel, response SLA,
scope, and our trust-model summary.

The agent runs with privileged access on customer infrastructure — we
take security reports seriously and respond within 48 hours.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
