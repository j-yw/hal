package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// CreateSnapshot creates a Daytona snapshot from Dockerfile content.
// It streams build logs to the provided writer and returns the snapshot ID on success.
func CreateSnapshot(ctx context.Context, client *daytona.Client, name, dockerfileContent string, out io.Writer) (string, error) {
	image := daytona.FromDockerfile(dockerfileContent)

	params := &types.CreateSnapshotParams{
		Name:  name,
		Image: image,
	}

	snapshot, logChan, err := client.Snapshot.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("creating snapshot: %w", err)
	}

	// Stream build logs
	for line := range logChan {
		fmt.Fprintln(out, line)
	}

	return snapshot.ID, nil
}

// DeleteSnapshot deletes a Daytona snapshot by ID.
func DeleteSnapshot(ctx context.Context, client *daytona.Client, snapshotID string) error {
	snapshot, err := client.Snapshot.Get(ctx, snapshotID)
	if err != nil {
		return fmt.Errorf("getting snapshot %q: %w", snapshotID, err)
	}

	if err := client.Snapshot.Delete(ctx, snapshot); err != nil {
		return fmt.Errorf("deleting snapshot %q: %w", snapshotID, err)
	}

	return nil
}

// ReadDockerfile reads the Dockerfile at the given path and returns its content.
// Returns a descriptive error if the file does not exist.
func ReadDockerfile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("Dockerfile not found at %s", path)
		}
		return "", fmt.Errorf("reading Dockerfile: %w", err)
	}
	return string(data), nil
}
