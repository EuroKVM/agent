# Security policy

The KVM Fleet agent runs with privileged access on customer infrastructure
— it tunnels console sessions to BMC management interfaces and (on
PiKVM-class devices) talks to `kvmd` on the local network. We take its
security posture seriously and welcome reports of issues from anyone
who finds them.

## Reporting a vulnerability

Email **security@kvmfleet.io** with:

- A description of the issue and how to reproduce it.
- The version of the agent affected (`kvmfleet-agent --version`).
- Your name / handle if you want credit in the changelog (optional).

**Please do not file a public GitHub issue for security reports.** Use
the email above; we'll acknowledge within 48 hours and follow up with
a fix timeline.

If you'd prefer encrypted communication, request our PGP key in the
first email.

## Response SLA

- **Acknowledgement:** within 48 hours.
- **Initial assessment + severity classification:** within 5 business
  days.
- **Fix for critical / high severity:** target 14 days from
  acknowledgement; we'll communicate if a longer window is needed.
- **Public disclosure:** coordinated with you. Default: 90 days from
  acknowledgement OR fix availability, whichever is later.

## Scope

In scope:

- The agent binary (`agent/main.go` + companion files in this repo).
- `install.sh` — the install script.
- The agent's interaction with the platform's API
  (`/v1/agent/*` endpoints).
- The agent's interaction with `kvmd` on PiKVM-class devices.
- The systemd unit / init-script the installer drops.
- The cert lifecycle (issuance, renewal, revocation) handled by
  `cert.go` + `mtls.go`.

Out of scope:

- Issues in the kvmd / BMC firmware itself — those belong to PiKVM,
  Dell, HPE, Supermicro, Lenovo, etc. We'll happily forward
  responsibly-reported issues we receive on behalf of the relevant
  vendor.
- Issues in the platform's hosted control plane
  (`app.kvmfleet.io`) — those go to platform-side disclosure at
  https://kvmfleet.io/.well-known/security.txt instead.
- Denial-of-service via floods against your own agent — agent
  trust model assumes the host running it is yours.

## Trust model summary

The agent's threat model is documented at
https://kvmfleet.io/docs/threat-model. The short version:

- **What we verify on install:** SHA-256 of the binary against
  `SHA256SUMS.txt` fetched from the same origin. PiKVM kvmd default-
  password preflight (refuses to install if `admin/admin` or
  `kvmd/kvmd` still active).
- **What we don't verify yet:** cosign signature chain to our GitHub
  Actions identity. Phase C.v2 will wire `cosign verify-blob` into
  `install.sh`; today, you can run it manually after install.
- **What your security responsibilities are when running the agent:**
  treat the host the way you treat any other internet-connected
  Linux box. Keep the OS patched. Don't disable the systemd
  sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, empty
  capability set) that the installer configures.

## Credit

We're happy to credit reporters in the changelog and (with your
permission) on our security acknowledgements page. We do not have a
bug-bounty program at this stage — we're a small team and pre-revenue.
That may change as we grow.

## Why we wrote this

A closed-source installer that drops binaries from public download
URLs is the highest-trust-burning part of any agent. Anyone can audit
`agent/main.go` byte-by-byte but the installer is "trust this curl
pipe to sh." Open-sourcing the installer + documenting our security
posture closes that gap. If you find something we missed, please
tell us.
