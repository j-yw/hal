package sandbox

import (
	"testing"
)

func TestShellConnectionFields(t *testing.T) {
	conn := ShellConnection{
		SandboxName: "test-sandbox",
		PtyHandle:   nil,
	}

	if conn.SandboxName != "test-sandbox" {
		t.Errorf("SandboxName = %q, want %q", conn.SandboxName, "test-sandbox")
	}

	if conn.PtyHandle != nil {
		t.Error("PtyHandle should be nil for unconnected shell")
	}
}
