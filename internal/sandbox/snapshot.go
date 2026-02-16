package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

const snapshotStateActive = "active"

type snapshotCreateFn func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error)
type snapshotGetFn func(ctx context.Context, nameOrID string) (*types.Snapshot, error)

// CreateSnapshot creates a Daytona snapshot from a pre-built Docker image reference.
// The image must be pushed to a registry accessible by Daytona (e.g., Docker Hub, GHCR).
// It streams build logs to the provided writer and returns the snapshot ID on success.
func CreateSnapshot(ctx context.Context, client *daytona.Client, name, imageRef string, out io.Writer) (string, error) {
	return createSnapshot(
		ctx,
		name,
		imageRef,
		out,
		func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
			return client.Snapshot.Create(ctx, params)
		},
		func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
			return client.Snapshot.Get(ctx, nameOrID)
		},
	)
}

func createSnapshot(ctx context.Context, name, imageRef string, out io.Writer, createFn snapshotCreateFn, getFn snapshotGetFn) (string, error) {
	if out == nil {
		out = io.Discard
	}

	image := daytona.Base(imageRef)

	params := &types.CreateSnapshotParams{
		Name:  name,
		Image: image,
	}

	snapshot, logChan, err := createFn(ctx, params)
	if err != nil {
		return "", fmt.Errorf("creating snapshot: %w", err)
	}
	if snapshot == nil {
		return "", fmt.Errorf("creating snapshot: empty snapshot response")
	}

	// Stream build logs
	if logChan != nil {
		streaming := true
		for streaming {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("streaming snapshot %q logs: %w", snapshot.ID, ctx.Err())
			case line, ok := <-logChan:
				if !ok {
					streaming = false
					continue
				}
				fmt.Fprintln(out, line)
			}
		}
	}

	latestSnapshot, err := getFn(ctx, snapshot.ID)
	if err != nil {
		return "", fmt.Errorf("checking snapshot %q status: %w", snapshot.ID, err)
	}
	if latestSnapshot == nil {
		return "", fmt.Errorf("checking snapshot %q status: empty snapshot response", snapshot.ID)
	}
	if latestSnapshot.State != snapshotStateActive {
		if latestSnapshot.ErrorReason != nil && *latestSnapshot.ErrorReason != "" {
			return "", fmt.Errorf("snapshot %q finished in state %s: %s", latestSnapshot.ID, latestSnapshot.State, *latestSnapshot.ErrorReason)
		}
		return "", fmt.Errorf("snapshot %q finished in state %s", latestSnapshot.ID, latestSnapshot.State)
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
