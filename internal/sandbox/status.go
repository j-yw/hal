package sandbox

import (
	"context"
	"fmt"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// SandboxStatus holds the live status fetched from the Daytona API.
type SandboxStatus struct {
	Name   string
	Status string
}

// GetSandboxStatus fetches the current status of a sandbox by name or ID.
func GetSandboxStatus(ctx context.Context, client *daytona.Client, nameOrID string) (*SandboxStatus, error) {
	sb, err := client.Get(ctx, nameOrID)
	if err != nil {
		return nil, fmt.Errorf("getting sandbox %q: %w", nameOrID, err)
	}

	return &SandboxStatus{
		Name:   sb.Name,
		Status: string(sb.State),
	}, nil
}
