package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	daytonaerrors "github.com/daytonaio/daytona/libs/sdk-go/pkg/errors"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	sandboxTemplateSnapshotName = "hal"
	defaultSandboxDockerfile    = "sandbox/Dockerfile"
	defaultSandboxContext       = "."
)

// snapshotFromDockerfileCreator creates a snapshot from a local Dockerfile/context.
type snapshotFromDockerfileCreator func(ctx context.Context, apiKey, serverURL, name, dockerfilePath, contextPath string, out io.Writer) (string, error)

func defaultSnapshotFromDockerfileCreator(ctx context.Context, apiKey, serverURL, name, dockerfilePath, contextPath string, out io.Writer) (string, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return "", fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSnapshotFromDockerfile(ctx, client, name, dockerfilePath, contextPath, out)
}

func resolveTemplateSnapshot(
	dir, apiKey, serverURL string,
	out io.Writer,
	lister snapshotLister,
	dockerfileCreator snapshotFromDockerfileCreator,
) (string, error) {
	if out == nil {
		out = io.Discard
	}
	if lister == nil {
		lister = defaultSnapshotLister
	}
	if dockerfileCreator == nil {
		dockerfileCreator = defaultSnapshotFromDockerfileCreator
	}

	ctx := context.Background()
	existing, err := findTemplateSnapshot(ctx, apiKey, serverURL, lister)
	if err != nil {
		return "", err
	}
	if existing != nil {
		if strings.EqualFold(existing.State, "active") {
			if strings.TrimSpace(existing.ID) == "" {
				return "", fmt.Errorf("template snapshot %q is active but has an empty ID; delete it in Daytona and retry", sandboxTemplateSnapshotName)
			}
			fmt.Fprintf(out, "Template snapshot %q is active; reusing %s.\n", sandboxTemplateSnapshotName, existing.ID)
			return existing.ID, nil
		}
		return "", templateSnapshotStateError(existing)
	}

	resolvedDockerfilePath, resolvedContextPath, err := resolveTemplatePaths(dir)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(out, "Template snapshot %q not found; creating from %s...\n", sandboxTemplateSnapshotName, defaultSandboxDockerfile)
	snapshotID, err := dockerfileCreator(ctx, apiKey, serverURL, sandboxTemplateSnapshotName, resolvedDockerfilePath, resolvedContextPath, out)
	if err == nil {
		return snapshotID, nil
	}
	if !isSnapshotConflictError(err) {
		return "", fmt.Errorf("creating template snapshot %q: %w", sandboxTemplateSnapshotName, err)
	}

	existing, listErr := findTemplateSnapshot(ctx, apiKey, serverURL, lister)
	if listErr != nil {
		return "", fmt.Errorf("template snapshot creation conflicted and listing snapshots failed: %w", listErr)
	}
	if existing == nil {
		return "", fmt.Errorf("template snapshot %q creation conflicted but no snapshot was found", sandboxTemplateSnapshotName)
	}
	if strings.EqualFold(existing.State, "active") {
		if strings.TrimSpace(existing.ID) == "" {
			return "", fmt.Errorf("template snapshot %q is active but has an empty ID; delete it in Daytona and retry", sandboxTemplateSnapshotName)
		}
		fmt.Fprintf(out, "Template snapshot %q was created concurrently; reusing %s.\n", sandboxTemplateSnapshotName, existing.ID)
		return existing.ID, nil
	}
	return "", templateSnapshotStateError(existing)
}

func resolveTemplatePaths(dir string) (dockerfilePath, contextPath string, err error) {
	rootDir, err := filepath.Abs(dir)
	if err != nil {
		return "", "", fmt.Errorf("resolving project directory: %w", err)
	}

	dockerfilePath = filepath.Join(rootDir, defaultSandboxDockerfile)
	dockerfileInfo, err := os.Stat(dockerfilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("template snapshot %q not found and Dockerfile %q is missing (expected at %s)", sandboxTemplateSnapshotName, defaultSandboxDockerfile, dockerfilePath)
		}
		return "", "", fmt.Errorf("checking Dockerfile %q: %w", defaultSandboxDockerfile, err)
	}
	if dockerfileInfo.IsDir() {
		return "", "", fmt.Errorf("template Dockerfile path %q points to a directory (expected a file)", defaultSandboxDockerfile)
	}

	contextPath = filepath.Join(rootDir, defaultSandboxContext)
	contextInfo, err := os.Stat(contextPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("template build context %q is missing (expected at %s)", defaultSandboxContext, contextPath)
		}
		return "", "", fmt.Errorf("checking template build context %q: %w", defaultSandboxContext, err)
	}
	if !contextInfo.IsDir() {
		return "", "", fmt.Errorf("template build context %q must be a directory", defaultSandboxContext)
	}

	return dockerfilePath, contextPath, nil
}

func findTemplateSnapshot(ctx context.Context, apiKey, serverURL string, lister snapshotLister) (*daytonatypes.Snapshot, error) {
	snapshots, err := lister(ctx, apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots failed: %w", err)
	}
	return latestSnapshotByName(snapshots, sandboxTemplateSnapshotName), nil
}

func templateSnapshotStateError(snapshot *daytonatypes.Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("template snapshot %q is in an invalid state", sandboxTemplateSnapshotName)
	}
	if strings.TrimSpace(snapshot.ID) == "" {
		return fmt.Errorf("template snapshot %q exists but is in state %s; delete it in Daytona and retry", sandboxTemplateSnapshotName, snapshot.State)
	}
	return fmt.Errorf("template snapshot %q exists but is in state %s; delete it with 'hal sandbox snapshot delete --id %s' and retry", sandboxTemplateSnapshotName, snapshot.State, snapshot.ID)
}

func latestSnapshotByName(snapshots []*daytonatypes.Snapshot, name string) *daytonatypes.Snapshot {
	var best *daytonatypes.Snapshot
	for _, snapshot := range snapshots {
		if snapshot == nil || snapshot.Name != name {
			continue
		}
		if best == nil || snapshot.UpdatedAt.After(best.UpdatedAt) {
			best = snapshot
		}
	}
	return best
}

func isSnapshotConflictError(err error) bool {
	if err == nil {
		return false
	}

	var daytonaErr *daytonaerrors.DaytonaError
	if errors.As(err, &daytonaErr) && daytonaErr.StatusCode == 409 {
		return true
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "status 409") || strings.Contains(errText, "409 conflict")
}
