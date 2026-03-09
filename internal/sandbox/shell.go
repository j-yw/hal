package sandbox

import (
	"context"
	"fmt"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// ShellConnection holds the resources needed for an interactive shell session.
type ShellConnection struct {
	SandboxName string
	PtyHandle   *daytona.PtyHandle
}

// ConnectShell establishes a PTY connection to a running sandbox.
// Returns an error if the sandbox is not in the "started" state.
func ConnectShell(ctx context.Context, client *daytona.Client, nameOrID string) (*ShellConnection, error) {
	sb, err := client.Get(ctx, nameOrID)
	if err != nil {
		return nil, fmt.Errorf("getting sandbox %q: %w", nameOrID, err)
	}

	if string(sb.State) != "started" {
		return nil, fmt.Errorf("sandbox %q is not running (current state: %s) - start it with 'hal sandbox start'", nameOrID, sb.State)
	}

	pty, err := sb.Process.CreatePty(ctx, "hal-shell")
	if err != nil {
		return nil, fmt.Errorf("creating PTY session for sandbox %q: %w", nameOrID, err)
	}

	if err := pty.WaitForConnection(ctx); err != nil {
		return nil, fmt.Errorf("waiting for PTY connection to sandbox %q: %w", nameOrID, err)
	}

	return &ShellConnection{
		SandboxName: sb.Name,
		PtyHandle:   pty,
	}, nil
}
