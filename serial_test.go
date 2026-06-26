package main

import (
	"os"
	"testing"
)

// TestResolveDropCredential exercises the loopback-shell privilege-drop
// decision. The key safety property: when the agent runs as root, it MUST
// refuse to spawn the bridged shell as root (uid 0) or against an
// unresolvable user — it fails closed instead.
func TestResolveDropCredential(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root path: a valid non-root user drops; root / missing user refuse.
		cred, home, name, err := resolveDropCredential("nobody")
		if err != nil {
			t.Fatalf("nobody should resolve when running as root: %v", err)
		}
		if cred == nil || cred.Uid == 0 {
			t.Errorf("expected a non-root credential, got %+v", cred)
		}
		if name != "nobody" || home == "" {
			t.Errorf("unexpected name/home: %q %q", name, home)
		}

		if _, _, _, err := resolveDropCredential("root"); err == nil {
			t.Error("must REFUSE to drop to root (uid 0)")
		}
		if _, _, _, err := resolveDropCredential("definitely-not-a-real-user-zzq"); err == nil {
			t.Error("must REFUSE an unresolvable drop-user when running as root")
		}
	} else {
		// Non-root: inherit (nil credential) — already unprivileged.
		cred, _, _, err := resolveDropCredential("nobody")
		if err != nil {
			t.Fatalf("unexpected error on non-root path: %v", err)
		}
		if cred != nil {
			t.Errorf("non-root agent should inherit (nil credential), got %+v", cred)
		}
	}
}

func TestHomeOrTmp(t *testing.T) {
	if got := homeOrTmp("/nonexistent-zzq"); got != "/tmp" {
		t.Errorf("missing dir should fall back to /tmp, got %q", got)
	}
	if got := homeOrTmp(""); got != "/tmp" {
		t.Errorf("empty dir should fall back to /tmp, got %q", got)
	}
	if got := homeOrTmp("/tmp"); got != "/tmp" {
		t.Errorf("existing dir should be returned, got %q", got)
	}
}
