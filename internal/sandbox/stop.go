package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// StopSandbox stops a running Daytona sandbox by name or ID.
func StopSandbox(ctx context.Context, client *daytona.Client, nameOrID string, out io.Writer) error {
	sb, err := client.Get(ctx, nameOrID)
	if err != nil {
		return fmt.Errorf("getting sandbox %q: %w", nameOrID, err)
	}

	if err := sb.Stop(ctx); err != nil {
		return fmt.Errorf("stopping sandbox %q: %w", nameOrID, err)
	}

	return nil
}
