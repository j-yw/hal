package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	daytonaerrors "github.com/daytonaio/daytona/libs/sdk-go/pkg/errors"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

const (
	defaultSandboxDockerfile = "sandbox/Dockerfile"
	defaultSandboxContext    = "."
)

var sandboxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Create and start a sandbox",
	Args:  noArgsValidation(),
	Long: `Create and start a Daytona sandbox.

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.
Use --snapshot to start from an existing snapshot.
Use --image to create a snapshot from an image and start immediately.
When neither --snapshot nor --image is set, hal will create a snapshot from sandbox/Dockerfile and start from it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		snapshot, _ := cmd.Flags().GetString("snapshot")
		image, _ := cmd.Flags().GetString("image")
		snapshotName, _ := cmd.Flags().GetString("snapshot-name")
		dockerfilePath, _ := cmd.Flags().GetString("dockerfile")
		contextPath, _ := cmd.Flags().GetString("context")

		return runSandboxStartWithDeps(
			".",
			name,
			snapshot,
			image,
			snapshotName,
			dockerfilePath,
			contextPath,
			os.Stdout,
			nil,
			nil,
			nil,
			nil,
			nil,
		)
	},
}

func init() {
	sandboxStartCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to current git branch)")
	sandboxStartCmd.Flags().String("snapshot", "", "snapshot ID or name to provision from")
	sandboxStartCmd.Flags().String("image", "", "Docker image reference to create a snapshot from (alternative to --snapshot)")
	sandboxStartCmd.Flags().String("snapshot-name", "", "snapshot name when creating from --image or --dockerfile (defaults to derived name)")
	sandboxStartCmd.Flags().String("dockerfile", defaultSandboxDockerfile, "Dockerfile path used when neither --snapshot nor --image is provided")
	sandboxStartCmd.Flags().String("context", defaultSandboxContext, "build context path used with --dockerfile auto-snapshot mode")

	sandboxCmd.AddCommand(sandboxStartCmd)
}

// sandboxStarter is a function that creates a Daytona client and creates a sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxStarter func(ctx context.Context, apiKey, serverURL, name, snapshotID string, out io.Writer) (*sandbox.CreateSandboxResult, error)

// snapshotFromDockerfileCreator creates a snapshot from a local Dockerfile/context.
type snapshotFromDockerfileCreator func(ctx context.Context, apiKey, serverURL, name, dockerfilePath, contextPath string, out io.Writer) (string, error)

// defaultSandboxStarter creates a real Daytona client and calls CreateSandbox.
func defaultSandboxStarter(ctx context.Context, apiKey, serverURL, name, snapshotID string, out io.Writer) (*sandbox.CreateSandboxResult, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSandbox(ctx, client, name, snapshotID, out)
}

func defaultSnapshotFromDockerfileCreator(ctx context.Context, apiKey, serverURL, name, dockerfilePath, contextPath string, out io.Writer) (string, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return "", fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSnapshotFromDockerfile(ctx, client, name, dockerfilePath, contextPath, out)
}

// branchResolver is a function that returns the current git branch name.
// Injected in tests to avoid depending on actual git state.
type branchResolver func() (string, error)

// runSandboxStart contains the legacy testable logic for starting from a snapshot.
func runSandboxStart(dir, name, snapshotID string, out io.Writer, starter sandboxStarter, getBranch branchResolver) error {
	return runSandboxStartWithDeps(
		dir,
		name,
		snapshotID,
		"",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		out,
		starter,
		getBranch,
		nil,
		nil,
		nil,
	)
}

// runSandboxStartWithDeps contains the testable logic for the sandbox start command.
// dir is the project root directory (containing .hal/).
// If starter is nil, the real SDK client is used.
// If getBranch is nil, compound.CurrentBranch is used.
// If imageCreator is nil and --image is used, the real snapshot creator is used.
// If dockerfileCreator is nil and dockerfile mode is used, the real dockerfile snapshot creator is used.
// If lister is nil, conflict fallback uses the real snapshot lister.
func runSandboxStartWithDeps(
	dir, name, snapshotID, imageRef, snapshotName, dockerfilePath, contextPath string,
	out io.Writer,
	starter sandboxStarter,
	getBranch branchResolver,
	imageCreator snapshotCreator,
	dockerfileCreator snapshotFromDockerfileCreator,
	lister snapshotLister,
) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := sandbox.EnsureAuth(cfg.APIKey, func() error {
		return runSandboxAutoSetup(dir, out)
	}, func() (string, error) {
		reloaded, err := compound.LoadDaytonaConfig(dir)
		if err != nil {
			return "", err
		}
		return reloaded.APIKey, nil
	}); err != nil {
		return err
	}

	// Re-read config in case EnsureAuth triggered setup
	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("reloading config: %w", err)
	}

	// Resolve sandbox name from git branch if not provided
	if name == "" {
		if getBranch == nil {
			getBranch = compound.CurrentBranch
		}
		branch, err := getBranch()
		if err != nil {
			return fmt.Errorf("could not determine sandbox name from git branch: %w\n  use --name to specify a name", err)
		}
		name = sandbox.SandboxNameFromBranch(branch)
	}

	snapshotID = strings.TrimSpace(snapshotID)
	imageRef = strings.TrimSpace(imageRef)
	snapshotName = strings.TrimSpace(snapshotName)
	dockerfilePath = strings.TrimSpace(dockerfilePath)
	contextPath = strings.TrimSpace(contextPath)

	if dockerfilePath == "" {
		dockerfilePath = defaultSandboxDockerfile
	}
	if contextPath == "" {
		contextPath = defaultSandboxContext
	}

	if snapshotID != "" && imageRef != "" {
		return fmt.Errorf("use either --snapshot or --image, not both")
	}

	// If no snapshot was provided, create one first.
	if snapshotID == "" {
		ctx := context.Background()

		if imageRef != "" {
			if snapshotName == "" {
				snapshotName = imageNameFromRef(imageRef)
				if snapshotName == "" {
					snapshotName = "hal-sandbox"
				}
			}

			if imageCreator == nil {
				imageCreator = defaultSnapshotCreator
			}

			fmt.Fprintf(out, "No snapshot provided; creating snapshot %q from image %s...\n", snapshotName, imageRef)
			createdSnapshotID, reused, err := createSnapshotWithConflictReuse(ctx, cfg.APIKey, cfg.ServerURL, snapshotName, out, lister, func(ctx context.Context, apiKey, serverURL, name string, out io.Writer) (string, error) {
				return imageCreator(ctx, apiKey, serverURL, name, imageRef, out)
			})
			if err != nil {
				return fmt.Errorf("snapshot creation failed: %w", err)
			}
			snapshotID = createdSnapshotID
			if !reused {
				fmt.Fprintf(out, "Snapshot created: %s\n", snapshotID)
			}
		} else {
			resolvedDockerfilePath := dockerfilePath
			if !filepath.IsAbs(resolvedDockerfilePath) {
				resolvedDockerfilePath = filepath.Join(dir, dockerfilePath)
			}
			if _, err := os.Stat(resolvedDockerfilePath); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("either --snapshot or --image flag is required (or add %s)", dockerfilePath)
				}
				return fmt.Errorf("checking dockerfile %q: %w", dockerfilePath, err)
			}

			if snapshotName == "" {
				snapshotName = name + "-snapshot"
			}

			if dockerfileCreator == nil {
				dockerfileCreator = defaultSnapshotFromDockerfileCreator
			}

			fmt.Fprintf(out, "No snapshot/image provided; creating snapshot %q from Dockerfile %s...\n", snapshotName, dockerfilePath)
			createdSnapshotID, reused, err := createSnapshotWithConflictReuse(ctx, cfg.APIKey, cfg.ServerURL, snapshotName, out, lister, func(ctx context.Context, apiKey, serverURL, name string, out io.Writer) (string, error) {
				return dockerfileCreator(ctx, apiKey, serverURL, name, resolvedDockerfilePath, contextPath, out)
			})
			if err != nil {
				return fmt.Errorf("snapshot creation failed: %w", err)
			}
			snapshotID = createdSnapshotID
			if !reused {
				fmt.Fprintf(out, "Snapshot created: %s\n", snapshotID)
			}
		}
	}

	fmt.Fprintf(out, "Starting sandbox %q from snapshot %q...\n", name, snapshotID)

	if starter == nil {
		starter = defaultSandboxStarter
	}

	ctx := context.Background()
	result, err := starter(ctx, cfg.APIKey, cfg.ServerURL, name, snapshotID, out)
	if err != nil {
		return fmt.Errorf("sandbox creation failed: %w", err)
	}

	// Save state
	state := &sandbox.SandboxState{
		Name:        result.Name,
		SnapshotID:  snapshotID,
		WorkspaceID: result.ID,
		Status:      result.Status,
		CreatedAt:   time.Now(),
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		return fmt.Errorf("saving sandbox state: %w", err)
	}

	fmt.Fprintf(out, "Sandbox started: %s (status: %s)\n", result.Name, result.Status)
	return nil
}

type startSnapshotCreateFn func(ctx context.Context, apiKey, serverURL, snapshotName string, out io.Writer) (string, error)

type snapshotConflictResolution struct {
	ReuseSnapshotID string
	RetryName       string
}

func createSnapshotWithConflictReuse(
	ctx context.Context,
	apiKey, serverURL, snapshotName string,
	out io.Writer,
	lister snapshotLister,
	createFn startSnapshotCreateFn,
) (snapshotID string, reused bool, err error) {
	snapshotID, err = createFn(ctx, apiKey, serverURL, snapshotName, out)
	if err == nil {
		return snapshotID, false, nil
	}

	resolution, resolveErr := resolveSnapshotConflict(ctx, err, apiKey, serverURL, snapshotName, out, lister)
	if resolveErr != nil {
		return "", false, resolveErr
	}
	if resolution == nil {
		return "", false, err
	}

	if resolution.ReuseSnapshotID != "" {
		return resolution.ReuseSnapshotID, true, nil
	}
	if resolution.RetryName == "" {
		return "", false, err
	}

	retrySnapshotID, retryErr := createFn(ctx, apiKey, serverURL, resolution.RetryName, out)
	if retryErr != nil {
		return "", false, fmt.Errorf("creating replacement snapshot %q failed: %w", resolution.RetryName, retryErr)
	}
	return retrySnapshotID, false, nil
}

func resolveSnapshotConflict(
	ctx context.Context,
	createErr error,
	apiKey, serverURL, snapshotName string,
	out io.Writer,
	lister snapshotLister,
) (*snapshotConflictResolution, error) {
	if !isSnapshotConflictError(createErr) {
		return nil, nil
	}

	if lister == nil {
		lister = defaultSnapshotLister
	}

	snapshots, err := lister(ctx, apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("snapshot already exists, but listing snapshots failed: %w", err)
	}

	match := latestSnapshotByName(snapshots, snapshotName)
	if match == nil {
		return nil, fmt.Errorf("snapshot %q already exists, but could not find it via snapshot list", snapshotName)
	}

	if strings.EqualFold(match.State, "active") {
		fmt.Fprintf(out, "Snapshot %q already exists; reusing %s.\n", snapshotName, match.ID)
		return &snapshotConflictResolution{ReuseSnapshotID: match.ID}, nil
	}

	if isFailedSnapshotState(match.State) {
		retryName := replacementSnapshotName(snapshotName)
		fmt.Fprintf(out, "Snapshot %q exists in state %s; creating replacement snapshot %q.\n", snapshotName, match.State, retryName)
		return &snapshotConflictResolution{RetryName: retryName}, nil
	}

	return nil, fmt.Errorf("snapshot %q already exists but is in state %s; wait for it to become active or pass --snapshot explicitly", snapshotName, match.State)
}

func isSnapshotConflictError(err error) bool {
	var daytonaErr *daytonaerrors.DaytonaError
	if errors.As(err, &daytonaErr) && daytonaErr.StatusCode == 409 {
		return true
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "status 409") || strings.Contains(errText, "409 conflict")
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

func isFailedSnapshotState(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	return s == "build_failed" || s == "error"
}

func replacementSnapshotName(base string) string {
	ts := time.Now().UTC().Format("20060102150405")
	return fmt.Sprintf("%s-%s", base, ts)
}
