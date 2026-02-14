package sandbox

import (
	"context"
	"strings"
	"testing"
)

func TestForwardShellIOResult_Fields(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      42,
		SessionClosed: true,
	}

	if result.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", result.ExitCode)
	}

	if !result.SessionClosed {
		t.Error("SessionClosed should be true")
	}
}

func TestForwardShellIO_NilPtyHandle(t *testing.T) {
	conn := &ShellConnection{
		SandboxName: "test",
		PtyHandle:   nil,
	}

	ctx := context.Background()
	_, err := ForwardShellIO(ctx, conn, strings.NewReader(""), nil)
	if err == nil {
		t.Fatal("expected error for nil PTY handle")
	}
	if !strings.Contains(err.Error(), "no PTY handle") {
		t.Errorf("error %q does not mention nil PTY handle", err.Error())
	}
}

func TestForwardShellIOResult_CleanDisconnect(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      0,
		SessionClosed: false,
	}

	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 for clean disconnect", result.ExitCode)
	}

	if result.SessionClosed {
		t.Error("SessionClosed should be false for clean disconnect")
	}
}

func TestForwardShellIOResult_SessionClosed(t *testing.T) {
	result := ForwardShellIOResult{
		ExitCode:      1,
		SessionClosed: true,
	}

	if result.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1 for session closed", result.ExitCode)
	}

	if !result.SessionClosed {
		t.Error("SessionClosed should be true when sandbox disconnects")
	}
}
