package sandbox

import (
	"context"
	"fmt"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// ExecResult contains the result of executing a command in a sandbox.
type ExecResult struct {
	ExitCode int
	Output   string
}

// ExecCommand runs a non-interactive command in a Daytona sandbox and returns
// the output and exit code. Returns an error if the sandbox is not in the
// "started" state.
func ExecCommand(ctx context.Context, client *daytona.Client, nameOrID, command string) (*ExecResult, error) {
	sb, err := client.Get(ctx, nameOrID)
	if err != nil {
		return nil, fmt.Errorf("getting sandbox %q: %w", nameOrID, err)
	}

	if string(sb.State) != "started" {
		return nil, fmt.Errorf("sandbox %q is not running (current state: %s) - start it with 'hal sandbox start'", nameOrID, sb.State)
	}

	resp, err := sb.Process.ExecuteCommand(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("executing command in sandbox %q: %w", nameOrID, err)
	}

	return &ExecResult{
		ExitCode: resp.ExitCode,
		Output:   resp.Result,
	}, nil
}
