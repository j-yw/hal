package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// CreateSandboxResult holds the result of creating a sandbox.
type CreateSandboxResult struct {
	ID     string
	Name   string
	Status string
}

// CreateSandbox creates a Daytona sandbox from a snapshot.
// It waits for the sandbox to start and returns the sandbox ID, name, and status.
func CreateSandbox(ctx context.Context, client *daytona.Client, name, snapshotID string, out io.Writer) (*CreateSandboxResult, error) {
	params := types.SnapshotParams{
		Snapshot: snapshotID,
		SandboxBaseParams: types.SandboxBaseParams{
			Name: name,
		},
	}

	sb, err := client.Create(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("creating sandbox: %w", err)
	}

	return &CreateSandboxResult{
		ID:     sb.ID,
		Name:   sb.Name,
		Status: string(sb.State),
	}, nil
}
