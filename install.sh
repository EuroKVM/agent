#!/bin/sh
#
# SINGLE SOURCE OF TRUTH NOTE (2026-06-03):
# This script is also published in the public agent repo at
# https://github.com/KVMFleet/agent/blob/main/install.sh under
# Apache 2.0. The two copies are identical today. Edits should be
# made on the public agent repo first (so external contributors
# can see them) and synced here via a routine sync step. Drift
# between the two is a bug — flag and fix.
#
# Security reports: see SECURITY.md in the public agent repo
# (https://github.com/KVMFleet/agent/blob/main/SECURITY.md) — NOT
# this kvmfleet repo, which is internal-platform-shaped.
#
# KVM Fleet — Universal agent installer
#
# WHAT THIS DOES (read before running):
#   1. Downloads the kvmfleet-agent binary for your architecture from
#      $PLATFORM_URL/downloads/.
#   2. Downloads SHA256SUMS.txt from the same origin and verifies the
#      binary's SHA-256 against it. Refuses to install if the hash
#      doesn't match (defence against in-flight tampering / a
#      compromised mirror serving a different file at the same URL).
#   3. On PiKVM/JetKVM: tries to log into the local kvmd with known
#      default passwords (admin/admin, kvmd/kvmd). Refuses to install
#      if the default is still set — a NAT-traversed device with the
#      kvmd default password is game-over, and we don't want our agent
#      papering over that.
#   4. Drops the binary at a path appropriate for the device type.
#   5. Writes the enrollment token (0600) + kvmd creds env-file (0600).
#   6. Installs a systemd unit (or BusyBox init script) with
#      filesystem + capability sandboxing — see the unit body for
#      specifics. NOT a privilege-unrestricted unit.
#   7. Starts the service. Waits up to 10s for enrollment to confirm.
#
# WHAT IT DOES NOT DO:
#   - Cosign-verify the binary's chain-of-custody to our GitHub
#     Actions identity. That requires the cosign CLI on the host. Run
#     `cosign verify-blob --certificate ... --signature ... <binary>`
#     manually if you need it. Phase C.v2 will wire this into the
#     script directly.
#   - Auto-update. The installed agent stays at the version you
#     downloaded today; re-run this script to upgrade. Auto-update is
#     on the roadmap (Phase C.v2) with staged-rollout + opt-out.
#
# Usage:
#   curl -sSL https://install.kvmfleet.io/agent | sh -s -- --token <enrollment-token>
#
# Or with env var:
#   KVMFLEET_TOKEN=ekvent_xxx curl -sSL https://install.kvmfleet.io/agent | sh
#
# Flags worth knowing about:
#   --dry-run                Print what would happen, exit without changing anything.
#   --force                  Overwrite an existing install. Default is to NO-OP.
#   --skip-kvmd-default-check Skip the kvmd default-password preflight (NOT
#                            recommended; some test harnesses need this).
#
# Supports:
#   - PiKVM   (Arch Linux, aarch64, systemd)           — verified
#   - Generic Linux (systemd, x86_64/aarch64/armv7l)   — verified
#   - BliKVM / TinyPilot / NanoKVM / JetKVM            — Experimental
#     (BliKVM proxies the same kvmd as PiKVM; the others are fronted by
#      the agent's raw reverse-proxy console mode — KVMFLEET_CONSOLE_MODE=proxy)
set -eu

PLATFORM_URL="${KVMFLEET_API:-https://app.kvmfleet.io}"
DOWNLOAD_BASE="${KVMFLEET_DOWNLOAD_URL:-${PLATFORM_URL}/downloads}"
VERSION="${KVMFLEET_AGENT_VERSION:-latest}"

# --- Parse args -----------------------------------------------------------

TOKEN="${KVMFLEET_TOKEN:-}"
DEVICE_NAME="${KVMFLEET_DEVICE_NAME:-}"
DEVICE_TAGS="${KVMFLEET_DEVICE_TAGS:-}"
KVMD_USER="${KVMFLEET_KVMD_USER:-admin}"
KVMD_PASS="${KVMFLEET_KVMD_PASS:-}"
# Explicit device-type override. Auto-detection covers the common cases,
# but operators can force a type when detection can't tell two boards
# apart (e.g. a BliKVM running stock PiKVM-OS). Empty = auto-detect.
DEVICE_OVERRIDE="${KVMFLEET_DEVICE:-}"
DRY_RUN=0
FORCE=0
SKIP_KVMD_DEFAULT_CHECK=0

while [ $# -gt 0 ]; do
    case "$1" in
        --token)     TOKEN="$2";       shift 2 ;;
        --name)      DEVICE_NAME="$2"; shift 2 ;;
        --tags)      DEVICE_TAGS="$2"; shift 2 ;;
        --api)       PLATFORM_URL="$2"; shift 2 ;;
        --kvmd-user) KVMD_USER="$2";   shift 2 ;;
        --kvmd-pass) KVMD_PASS="$2";   shift 2 ;;
        --device)    DEVICE_OVERRIDE="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=1;        shift ;;
        --force)     FORCE=1;          shift ;;
        --skip-kvmd-default-check) SKIP_KVMD_DEFAULT_CHECK=1; shift ;;
        --help|-h)
            echo "Usage: curl -sSL https://app.kvmfleet.io/install | sh -s -- --token <token> --kvmd-pass <pass>"
            echo ""
            echo "Options:"
            echo "  --token <token>           Enrollment token (required, or set KVMFLEET_TOKEN)"
            echo "  --name <name>             Device name (optional)"
            echo "  --tags <t1,t2>            Comma-separated tags (optional)"
            echo "  --api <url>               Platform URL (default: https://app.kvmfleet.io)"
            echo "  --kvmd-user <user>        Local kvmd username (default: admin)"
            echo "  --kvmd-pass <pass>        Local kvmd/console password (required for PiKVM/BliKVM)"
            echo "  --device <type>           Force device type: pikvm | blikvm | jetkvm |"
            echo "                            tinypilot | nanokvm | generic (default: auto-detect)"
            echo "  --dry-run                 Print steps without executing"
            echo "  --force                   Overwrite an existing install (default: no-op)"
            echo "  --skip-kvmd-default-check Skip kvmd default-password preflight"
            exit 0 ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

if [ -z "$TOKEN" ]; then
    echo "ERROR: enrollment token required."
    echo "  --token <token>  or  KVMFLEET_TOKEN=<token>"
    exit 1
fi

# --- Detect environment ----------------------------------------------------

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   BINARY_ARCH="amd64" ;;
    aarch64|arm64)   BINARY_ARCH="arm64" ;;
    armv7l|armhf)    BINARY_ARCH="arm" ;;
    *)               echo "ERROR: unsupported architecture: $ARCH"; exit 1 ;;
esac

detect_init_system() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        echo "systemd"
    elif [ -d /etc/init.d ]; then
        echo "busybox"
    else
        echo "unknown"
    fi
}

detect_device_type() {
    # Explicit override wins over auto-detection.
    if [ -n "$DEVICE_OVERRIDE" ]; then
        echo "$DEVICE_OVERRIDE"
        return
    fi
    # Specific non-kvmd boards first — their markers are unambiguous, and
    # they must be matched before the generic kvmd probe below.
    if [ -f /userdata/kvm_config.json ]; then
        echo "jetkvm"                          # JetKVM (BusyBox, /userdata)
    elif [ -d /opt/tinypilot ]; then
        echo "tinypilot"                        # TinyPilot (Flask app under /opt)
    elif [ -d /kvmapp ]; then
        echo "nanokvm"                          # Sipeed NanoKVM (/kvmapp firmware)
    elif command -v kvmd >/dev/null 2>&1 || [ -f /etc/kvmd/main.yaml ]; then
        # PiKVM and BliKVM both run stock kvmd and are indistinguishable
        # here. We report pikvm (full kvmd console works for both); pass
        # --device blikvm to stamp the BliKVM hw_kind label.
        echo "pikvm"
    else
        echo "generic"
    fi
}

INIT_SYSTEM=$(detect_init_system)
DEVICE_TYPE=$(detect_device_type)

# Console mode + hardware-kind label, derived from the device type. Boards
# that run kvmd (PiKVM, BliKVM) use the full kvmd console path; the rest are
# fronted by the agent's raw reverse-proxy console mode (Experimental).
case "$DEVICE_TYPE" in
    pikvm)     CONSOLE_MODE="kvmd";  HW_KIND="pikvm-v4" ;;
    blikvm)    CONSOLE_MODE="kvmd";  HW_KIND="blikvm" ;;
    jetkvm)    CONSOLE_MODE="proxy"; HW_KIND="jetkvm" ;;
    tinypilot) CONSOLE_MODE="proxy"; HW_KIND="tinypilot" ;;
    nanokvm)   CONSOLE_MODE="proxy"; HW_KIND="nanokvm" ;;
    generic)   CONSOLE_MODE="kvmd";  HW_KIND="generic" ;;
    *)
        echo "ERROR: unknown --device '$DEVICE_TYPE'."
        echo "Valid: pikvm | blikvm | jetkvm | tinypilot | nanokvm | generic"
        exit 1 ;;
esac
# Allow KVMFLEET_HW_KIND to win if the operator set a more specific label.
HW_KIND="${KVMFLEET_HW_KIND:-$HW_KIND}"

echo "=== KVM Fleet Agent Installer ==="
echo "  Platform:    $PLATFORM_URL"
echo "  Arch:        $ARCH → $BINARY_ARCH"
echo "  Init system: $INIT_SYSTEM"
echo "  Device type: $DEVICE_TYPE (console mode: $CONSOLE_MODE)"
case "$DEVICE_TYPE" in
    blikvm|jetkvm|tinypilot|nanokvm)
        echo "  Support:     Experimental" ;;
esac
echo ""

# --- Paths (vary by device type) -------------------------------------------

case "$DEVICE_TYPE" in
    jetkvm)
        INSTALL_DIR="/userdata/kvmfleet"
        AGENT_BIN="$INSTALL_DIR/agent"
        STATE_FILE="$INSTALL_DIR/state.json"
        TOKEN_FILE="$INSTALL_DIR/enrollment.token"
        ;;
    nanokvm)
        # NanoKVM firmware mounts / read-only-ish; /kvmapp is the writable
        # app partition where the vendor keeps state.
        INSTALL_DIR="/kvmapp/kvmfleet"
        AGENT_BIN="$INSTALL_DIR/agent"
        STATE_FILE="$INSTALL_DIR/state.json"
        TOKEN_FILE="$INSTALL_DIR/enrollment.token"
        ;;
    pikvm|blikvm|tinypilot)
        INSTALL_DIR="/var/lib/kvmfleet"
        AGENT_BIN="/usr/local/bin/kvmfleet-agent"
        STATE_FILE="$INSTALL_DIR/state.json"
        TOKEN_FILE="$INSTALL_DIR/enrollment.token"
        ;;
    *)
        INSTALL_DIR="/var/lib/kvmfleet"
        AGENT_BIN="/usr/local/bin/kvmfleet-agent"
        STATE_FILE="$INSTALL_DIR/state.json"
        TOKEN_FILE="$INSTALL_DIR/enrollment.token"
        ;;
esac

# --- Check if already enrolled ---------------------------------------------

if [ -f "$STATE_FILE" ] && [ "$FORCE" -ne 1 ]; then
    echo "Agent already enrolled (state file exists at $STATE_FILE)."
    echo "To re-enroll, either:"
    echo "  --force                        (overwrite this install in place)"
    echo "  rm $STATE_FILE && re-run       (full clean re-enrollment)"
    echo ""
    echo "Ensuring service is running..."
    case "$INIT_SYSTEM" in
        systemd)  systemctl start kvmfleet-agent 2>/dev/null || true ;;
        busybox)  "$INSTALL_DIR/init.sh" start 2>/dev/null || true ;;
    esac
    exit 0
fi

# --- Preflight: refuse to install on top of a kvmd default password --------
#
# A NAT-traversed PiKVM with admin/admin kvmd creds is game-over BEFORE our
# agent even matters. We try to log in with known defaults via the local
# kvmd HTTP endpoint; if any succeed, refuse to install so the operator
# fixes the host first.
#
# Why this is a check rather than a warning: the cost of a false positive
# (operator has to add --skip-kvmd-default-check for an unusual setup) is
# minuscule compared to the cost of installing onto a popped device and
# logging the false comfort of "fleet protected by KVM Fleet."
check_kvmd_default_password() {
    # Only the kvmd boards expose the /api/auth/login endpoint this probe
    # targets. Proxy-console devices (JetKVM/TinyPilot/NanoKVM) have their
    # own web-UI auth and are out of scope for this specific check.
    case "$DEVICE_TYPE" in
        pikvm|blikvm)  _kvmd_url="https://127.0.0.1" ;;
        *)             return 0 ;;
    esac
    if [ "$SKIP_KVMD_DEFAULT_CHECK" -eq 1 ]; then
        echo "(--skip-kvmd-default-check passed — not testing kvmd default password)"
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "(curl not available — cannot run kvmd default-password preflight; skipping)"
        return 0
    fi
    # Try each known default with a 3s timeout. kvmd's auth endpoint
    # returns 200 + a cookie on success, 4xx on bad creds.
    for _creds in "admin:admin" "kvmd:kvmd" "admin:" "root:root"; do
        _user="${_creds%%:*}"
        _pass="${_creds#*:}"
        _code=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 3 -X POST \
            -d "user=$_user&passwd=$_pass" \
            "$_kvmd_url/api/auth/login" 2>/dev/null || echo "000")
        if [ "$_code" = "200" ]; then
            cat <<EOM
ERROR: local kvmd accepts default credentials ($_user / $_pass).
Installing the agent on a host with default kvmd credentials leaves
the BMC exposed end-to-end. Fix the host first:

    kvmd-htpasswd set $_user      # PiKVM: prompts for a new password

Then re-run this installer. If you have a specific reason to
proceed anyway (e.g. an isolated test harness), pass
--skip-kvmd-default-check.
EOM
            exit 1
        fi
    done
    echo "(kvmd default-password preflight: ok)"
}

check_kvmd_default_password

# --- PiKVM: ensure filesystem is writable -----------------------------------

if [ "$DEVICE_TYPE" = "pikvm" ] || [ "$DEVICE_TYPE" = "blikvm" ]; then
    if mount | grep "on / " | grep -q "ro,\|ro)"; then
        echo "PiKVM/BliKVM filesystem is read-only. Making writable..."
        mount -o remount,rw / 2>/dev/null || true
        PIKVM_REMOUNT_RO=1
    fi
fi

# --- Download agent binary + verify SHA-256 ---------------------------------
#
# Two-file fetch: the binary, plus SHA256SUMS.txt that the platform serves
# alongside the binaries. We verify the binary's hash against the entry in
# SHA256SUMS.txt before installing. Catches:
#   - In-flight tampering on the binary download
#   - A different file being served at the same URL (mirror compromise)
#   - Corruption during download
#
# Does NOT catch a compromise that also rewrites SHA256SUMS.txt at the same
# origin — for that you need cosign-verified blobs from GitHub releases, a
# Phase C.v2 hardening step.

DOWNLOAD_URL="${DOWNLOAD_BASE}/kvmfleet-agent.linux-${BINARY_ARCH}"
SHA256SUMS_URL="${DOWNLOAD_BASE}/SHA256SUMS.txt"

if [ "$DRY_RUN" -eq 1 ]; then
    cat <<EOM
=== Dry-run mode — no changes will be made. ===

Would mkdir $INSTALL_DIR.

Would download:
  $DOWNLOAD_URL  →  $AGENT_BIN
  $SHA256SUMS_URL  (for SHA-256 verification)

Would verify the binary's SHA-256 against the entry for
'kvmfleet-agent.linux-${BINARY_ARCH}' in SHA256SUMS.txt.

Would write enrollment token to $TOKEN_FILE (mode 0600).

Would install systemd unit at /etc/systemd/system/kvmfleet-agent.service
with NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes,
PrivateTmp=yes, ReadWritePaths=$INSTALL_DIR, CapabilityBoundingSet=
(empty — agent needs no capabilities), and RestrictAddressFamilies=
AF_INET AF_INET6 AF_UNIX.

Would start the service and wait up to 10s for enrollment.
EOM
    exit 0
fi

mkdir -p "$INSTALL_DIR"

echo "Downloading agent from $DOWNLOAD_URL ..."

_fetch() {
    _url="$1"
    _dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$_url" -o "$_dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$_dest" "$_url"
    else
        echo "ERROR: neither curl nor wget available."
        exit 1
    fi
}

_fetch "$DOWNLOAD_URL" "$AGENT_BIN" || {
    echo "ERROR: agent binary download failed. Check URL + network."
    exit 1
}

# Fetch the sidecar hash file. If it doesn't exist we refuse to install —
# Phase C v1 makes hash verification mandatory. (To deploy older
# platform builds that don't ship SHA256SUMS.txt, downgrade install.sh
# first.)
SHA256SUMS_FILE="$INSTALL_DIR/SHA256SUMS.txt.tmp"
_fetch "$SHA256SUMS_URL" "$SHA256SUMS_FILE" || {
    rm -f "$AGENT_BIN" "$SHA256SUMS_FILE"
    cat <<EOM
ERROR: could not fetch $SHA256SUMS_URL — the platform's download
origin should serve a SHA256SUMS.txt sidecar containing one line per
binary in the form "<sha256>  kvmfleet-agent.linux-<arch>". Without
this file the installer cannot verify the binary it just downloaded
and refuses to proceed.

If you're testing against a platform that doesn't have the file yet,
the operator-managed download server needs to be updated. See
docs/host-requirements.md for the expected layout.
EOM
    exit 1
}

# Compute the binary's SHA-256, look up the expected hash, fail loud
# on mismatch. Uses sha256sum or shasum; one of those is on every
# distro we care about.
_compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        echo "ERROR: neither sha256sum nor shasum available — cannot verify download." >&2
        exit 1
    fi
}

ACTUAL_SHA=$(_compute_sha256 "$AGENT_BIN")
EXPECTED_SHA=$(grep "kvmfleet-agent\\.linux-${BINARY_ARCH}\$" "$SHA256SUMS_FILE" | head -1 | awk '{print $1}')

if [ -z "$EXPECTED_SHA" ]; then
    rm -f "$AGENT_BIN" "$SHA256SUMS_FILE"
    echo "ERROR: SHA256SUMS.txt does not contain an entry for kvmfleet-agent.linux-${BINARY_ARCH}."
    echo "Refusing to install an unverified binary."
    exit 1
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    rm -f "$AGENT_BIN" "$SHA256SUMS_FILE"
    cat <<EOM
ERROR: agent binary SHA-256 does not match SHA256SUMS.txt.
  expected: $EXPECTED_SHA
  got:      $ACTUAL_SHA

Either the download was tampered with in flight, the mirror is
serving a different file at the same URL, or the SHA256SUMS.txt is
out of date relative to the binary. Refusing to install.
EOM
    exit 1
fi

rm -f "$SHA256SUMS_FILE"
chmod +x "$AGENT_BIN"
echo "Agent binary installed at $AGENT_BIN (SHA-256 verified)"

# --- Write enrollment token -------------------------------------------------

echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

# --- Detect kvmd URL --------------------------------------------------------

KVMD_URL=""
case "$DEVICE_TYPE" in
    pikvm|blikvm)  KVMD_URL="https://127.0.0.1" ;;     # stock kvmd over TLS
    jetkvm)        KVMD_URL="http://127.0.0.1:80" ;;   # JetKVM web UI
    tinypilot)     KVMD_URL="http://127.0.0.1:80" ;;   # TinyPilot web UI
    nanokvm)       KVMD_URL="http://127.0.0.1:80" ;;   # NanoKVM web UI
esac
# Allow an explicit override (e.g. a non-default web-UI port).
KVMD_URL="${KVMFLEET_KVMD_URL:-$KVMD_URL}"

# A kvmd password is required on the boards that proxy through a real local
# kvmd (PiKVM, BliKVM) — that's the credential the agent uses to reach the
# console. The Experimental proxy devices (JetKVM/TinyPilot/NanoKVM) front
# their own web UI; a console password is optional there (used as HTTP Basic
# auth only if the device requires it).
case "$DEVICE_TYPE" in
    pikvm|blikvm)
        if [ -z "$KVMD_PASS" ]; then
            echo "ERROR: this device proxies through a local kvmd that requires a password."
            echo "Either:"
            echo "  1. Pass it on the command line:"
            echo "       curl -sSL https://app.kvmfleet.io/install | sh -s -- \\"
            echo "         --token $TOKEN --kvmd-pass <your-kvmd-password>"
            echo "  2. Or set the env var before piping:"
            echo "       KVMFLEET_TOKEN=... KVMFLEET_KVMD_PASS=<pass> \\"
            echo "         curl -sSL https://app.kvmfleet.io/install | sh"
            echo ""
            echo "If you haven't set a kvmd password yet, run on the device:"
            echo "       kvmd-htpasswd set admin"
            echo "(the default 'admin' password is rejected by the agent for safety)."
            exit 1
        fi
        ;;
esac

# Persist kvmd credentials to a 0600-mode env file separate from the unit
# file so they aren't world-readable in /etc/systemd/system/.
KVMD_ENV_DIR="/etc/kvmfleet"
KVMD_ENV_FILE="$KVMD_ENV_DIR/agent.env"
mkdir -p "$KVMD_ENV_DIR"
# Start fresh; we'll append serial detection below.
: > "$KVMD_ENV_FILE"
if [ -n "$KVMD_PASS" ]; then
    cat >> "$KVMD_ENV_FILE" <<KVMDENV
KVMFLEET_KVMD_USER=$KVMD_USER
KVMFLEET_KVMD_PASS=$KVMD_PASS
KVMDENV
fi

# Cascade 11: auto-detect a serial bridge device. Probe USB-CDC, FTDI,
# CH340, etc. first (most operator-wired adapters), then the Pi's
# built-in GPIO UART (/dev/ttyAMA0) as a fallback. If nothing matches
# the agent's /api/serial returns 404 with a hint, instead of a
# tunnel-level error. Operator can override by setting
# KVMFLEET_SERIAL_DEV in /etc/kvmfleet/agent.env after install.
SERIAL_DEV=""
for cand in /dev/ttyUSB0 /dev/ttyACM0; do
    if [ -e "$cand" ]; then
        SERIAL_DEV="$cand"
        break
    fi
done
# If no serial hardware is wired, the loopback bridge gives a real shell on a
# pty so the Serial button still works. That shell is reachable by whoever opens
# the channel (the platform), so we only auto-enable it for the experimental,
# console-less device kinds (JetKVM / TinyPilot / NanoKVM) that have no other
# terminal — and even then it runs UNPRIVILEGED (dropped to `nobody`) and behind
# an explicit allow flag the agent enforces. For every other device, no serial
# hardware means the Serial button is simply disabled; an operator who wants the
# loopback shell opts in deliberately (set KVMFLEET_SERIAL_DEV=loopback +
# KVMFLEET_ALLOW_LOOPBACK_SHELL=1 in the env file).
ALLOW_LOOPBACK_SHELL=0
if [ -z "$SERIAL_DEV" ]; then
    case "$DEVICE_TYPE" in
        jetkvm|tinypilot|nanokvm)
            SERIAL_DEV="loopback"
            ALLOW_LOOPBACK_SHELL=1
            ;;
        *)
            SERIAL_DEV=""  # Serial button disabled; opt in manually if wanted
            ;;
    esac
fi
cat >> "$KVMD_ENV_FILE" <<SERIALENV
KVMFLEET_SERIAL_DEV=$SERIAL_DEV
KVMFLEET_SERIAL_BAUD=${KVMFLEET_SERIAL_BAUD:-115200}
KVMFLEET_ALLOW_LOOPBACK_SHELL=$ALLOW_LOOPBACK_SHELL
KVMFLEET_LOOPBACK_SHELL_USER=${KVMFLEET_LOOPBACK_SHELL_USER:-nobody}
SERIALENV
if [ "$SERIAL_DEV" = "loopback" ]; then
    echo "  serial bridge: loopback mode (unprivileged /bin/bash on a pty as 'nobody' — no hardware wired)"
elif [ -n "$SERIAL_DEV" ]; then
    echo "  serial bridge: enabled on $SERIAL_DEV @ ${KVMFLEET_SERIAL_BAUD:-115200} baud"
else
    echo "  serial bridge: disabled (no serial hardware detected; set KVMFLEET_SERIAL_DEV + KVMFLEET_ALLOW_LOOPBACK_SHELL=1 to opt into a loopback shell)"
fi

chmod 600 "$KVMD_ENV_FILE"

# The agent normally runs with ZERO Linux capabilities. The loopback shell is
# the one feature that needs CAP_SETUID/CAP_SETGID — to drop the bridged shell
# to an unprivileged user. Grant them only when loopback is actually enabled.
if [ "$ALLOW_LOOPBACK_SHELL" = "1" ]; then
    CAP_BOUNDING="CAP_SETUID CAP_SETGID"
else
    CAP_BOUNDING=""
fi

# --- Set up service ---------------------------------------------------------

case "$INIT_SYSTEM" in
    systemd)
        # Phase C: systemd sandbox directives. Each one limits the
        # blast radius of a compromised agent. The agent itself is a
        # plain HTTP-over-WS client + a tiny kvmd reverse proxy — it
        # needs no capabilities, no extra address families, no access
        # to /home or the rest of /. Tested against the prod PiKVM
        # image (Arch + kvmd 4.x); if a future feature trips on these
        # sandboxes, RELAX with comments here rather than disabling
        # everything.
        cat > /etc/systemd/system/kvmfleet-agent.service <<UNIT
[Unit]
Description=KVM Fleet Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN run
Restart=always
RestartSec=5
Environment=KVMFLEET_API=$PLATFORM_URL
Environment=KVMFLEET_TOKEN_FILE=$TOKEN_FILE
Environment=KVMFLEET_STATE=$STATE_FILE
Environment=KVMFLEET_DEVICE_NAME=$DEVICE_NAME
Environment=KVMFLEET_DEVICE_TAGS=$DEVICE_TAGS
Environment=KVMFLEET_KVMD_URL=$KVMD_URL
Environment=KVMFLEET_CONSOLE_MODE=$CONSOLE_MODE
Environment=KVMFLEET_HW_KIND=$HW_KIND
Environment=KVMFLEET_CONSOLE_ADDR=off
EnvironmentFile=-$KVMD_ENV_FILE

# Phase C v1 sandboxing.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# The state dir is the only place we need to write — keep the rest of
# the FS read-only from this process's perspective.
ReadWritePaths=$INSTALL_DIR
# Empty CapabilityBoundingSet = no Linux capabilities at all. The
# agent runs as root for kvmd-socket access but never needs root-y
# powers; bounding-set zero stops it from gaining any post-exploit.
# EXCEPTION: when the loopback shell is enabled, the agent needs
# CAP_SETUID/CAP_SETGID so it can DROP the bridged shell to an
# unprivileged user — without these, a uid-0 process with an empty
# bounding set cannot setuid() and the drop fails. We grant them only
# on boxes that run the loopback shell; everyone else keeps zero caps.
CapabilityBoundingSet=$CAP_BOUNDING
AmbientCapabilities=
# Network: agent talks IPv4 + IPv6 over TCP/UDP, and AF_UNIX for the
# local kvmd socket on PiKVM. No other families needed.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# MemoryDenyWriteExecute=yes is intentionally omitted — pure-Go
# binaries occasionally mmap PROT_EXEC pages at runtime in ways
# this directive blocks, and we haven't field-tested against the
# specific Go 1.24 release we ship. Phase C.v2 will turn this on
# after a confirmed-clean test on a real PiKVM.
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable kvmfleet-agent
        systemctl start kvmfleet-agent
        echo "Service installed: systemctl status kvmfleet-agent"
        ;;

    busybox)
        INIT_SCRIPT="$INSTALL_DIR/init.sh"
        cat > "$INIT_SCRIPT" <<INITSCRIPT
#!/bin/sh
# KVM Fleet agent init script for BusyBox
PIDFILE="/var/run/kvmfleet-agent.pid"
AGENT="$AGENT_BIN"

export KVMFLEET_API="$PLATFORM_URL"
export KVMFLEET_TOKEN_FILE="$TOKEN_FILE"
export KVMFLEET_STATE="$STATE_FILE"
export KVMFLEET_DEVICE_NAME="$DEVICE_NAME"
export KVMFLEET_DEVICE_TAGS="$DEVICE_TAGS"
export KVMFLEET_KVMD_URL="$KVMD_URL"
export KVMFLEET_CONSOLE_MODE="$CONSOLE_MODE"
export KVMFLEET_HW_KIND="$HW_KIND"
export KVMFLEET_CONSOLE_ADDR="off"
[ -f "$KVMD_ENV_FILE" ] && . "$KVMD_ENV_FILE" && export KVMFLEET_KVMD_USER KVMFLEET_KVMD_PASS

case "\$1" in
    start)
        echo "Starting kvmfleet-agent..."
        start-stop-daemon -S -b -m -p "\$PIDFILE" -x "\$AGENT" -- run
        ;;
    stop)
        echo "Stopping kvmfleet-agent..."
        start-stop-daemon -K -p "\$PIDFILE" 2>/dev/null
        rm -f "\$PIDFILE"
        ;;
    restart)
        \$0 stop
        sleep 1
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
INITSCRIPT
        chmod +x "$INIT_SCRIPT"

        # Link into /etc/init.d/ for auto-start on boot
        ln -sf "$INIT_SCRIPT" /etc/init.d/S99kvmfleet 2>/dev/null || true

        "$INIT_SCRIPT" start
        echo "Service installed: $INIT_SCRIPT {start|stop|restart}"
        ;;

    *)
        echo "WARNING: unknown init system. Starting agent in foreground."
        echo "You may want to set up a service manually."
        KVMFLEET_API="$PLATFORM_URL" \
        KVMFLEET_TOKEN_FILE="$TOKEN_FILE" \
        KVMFLEET_STATE="$STATE_FILE" \
        KVMFLEET_DEVICE_NAME="$DEVICE_NAME" \
        KVMFLEET_DEVICE_TAGS="$DEVICE_TAGS" \
        KVMFLEET_KVMD_URL="$KVMD_URL" \
        KVMFLEET_CONSOLE_MODE="$CONSOLE_MODE" \
        KVMFLEET_HW_KIND="$HW_KIND" \
        KVMFLEET_CONSOLE_ADDR="off" \
            "$AGENT_BIN" run &
        ;;
esac

# --- PiKVM: remount read-only ----------------------------------------------

if [ "${PIKVM_REMOUNT_RO:-0}" = "1" ]; then
    mount -o remount,ro / 2>/dev/null || true
    echo "PiKVM filesystem remounted read-only."
fi

# --- Wait for enrollment ---------------------------------------------------

echo ""
echo "Waiting for agent to enroll..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$STATE_FILE" ]; then
        DEVICE_ID=$(cat "$STATE_FILE" | grep -o '"device_id":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo ""
        echo "=== Enrolled successfully ==="
        echo "  Device ID:  $DEVICE_ID"
        echo "  Dashboard:  $PLATFORM_URL"
        echo "  State file: $STATE_FILE"
        echo ""
        echo "Your device should appear in the fleet dashboard within seconds."
        exit 0
    fi
    sleep 1
done

echo ""
echo "Agent started but enrollment not confirmed yet."
echo "Check logs:"
case "$INIT_SYSTEM" in
    systemd) echo "  journalctl -u kvmfleet-agent -f" ;;
    busybox) echo "  cat /var/log/messages | grep kvmfleet" ;;
esac
echo ""
echo "If enrollment fails, verify:"
echo "  1. The token hasn't expired (30 min TTL)"
echo "  2. The device can reach $PLATFORM_URL"
echo "  3. DNS resolves correctly"
