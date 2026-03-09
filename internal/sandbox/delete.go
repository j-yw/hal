package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
)

// DeleteSandbox permanently deletes a Daytona sandbox by name or ID.
func DeleteSandbox(ctx context.Context, client *daytona.Client, nameOrID string, out io.Writer) error {
	sb, err := client.Get(ctx, nameOrID)
	if err != nil {
		return fmt.Errorf("getting sandbox %q: %w", nameOrID, err)
	}

	if err := sb.Delete(ctx); err != nil {
		return fmt.Errorf("deleting sandbox %q: %w", nameOrID, err)
	}

	return nil
}
