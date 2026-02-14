package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

const defaultDockerfilePath = "sandbox/Dockerfile"

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Manage sandbox snapshots",
	Long:  `Create and manage Daytona sandbox snapshots from Dockerfiles.`,
}

var snapshotDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a snapshot",
	Long: `Delete a Daytona sandbox snapshot.

Requires --id flag specifying the snapshot ID to delete.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		return runSnapshotDelete(".", id, os.Stdout, nil)
	},
}

var snapshotCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a snapshot from a Dockerfile",
	Long: `Build a Daytona snapshot from a Dockerfile.

By default reads sandbox/Dockerfile. Use --dockerfile to specify a different path.
The snapshot name defaults to the Dockerfile directory name.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dockerfile, _ := cmd.Flags().GetString("dockerfile")
		name, _ := cmd.Flags().GetString("name")
		return runSnapshotCreate(".", dockerfile, name, os.Stdout, nil)
	},
}

func init() {
	snapshotCreateCmd.Flags().String("dockerfile", defaultDockerfilePath, "path to the Dockerfile")
	snapshotCreateCmd.Flags().String("name", "", "snapshot name (defaults to directory name)")

	snapshotDeleteCmd.Flags().String("id", "", "snapshot ID to delete (required)")

	snapshotCmd.AddCommand(snapshotCreateCmd)
	snapshotCmd.AddCommand(snapshotDeleteCmd)
	sandboxCmd.AddCommand(snapshotCmd)
}

// snapshotClientCreator is a function that creates a Daytona client and calls CreateSnapshot.
// Injected in tests to avoid real SDK calls.
type snapshotCreator func(ctx context.Context, apiKey, serverURL, name, dockerfileContent string, out io.Writer) (string, error)

// defaultSnapshotCreator creates a real Daytona client and calls CreateSnapshot.
func defaultSnapshotCreator(ctx context.Context, apiKey, serverURL, name, dockerfileContent string, out io.Writer) (string, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return "", fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSnapshot(ctx, client, name, dockerfileContent, out)
}

// runSnapshotCreate contains the testable logic for the snapshot create command.
// dir is the project root directory (containing .hal/).
// If creator is nil, the real SDK client is used.
func runSnapshotCreate(dir, dockerfile, name string, out io.Writer, creator snapshotCreator) error {
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
		return runSandboxSetup(dir, os.Stdin, out, readPasswordFromTerminal)
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

	// Resolve Dockerfile path
	if dockerfile == "" {
		dockerfile = defaultDockerfilePath
	}
	dockerfilePath := filepath.Join(dir, dockerfile)

	// Read Dockerfile
	content, err := sandbox.ReadDockerfile(dockerfilePath)
	if err != nil {
		return err
	}

	// Resolve snapshot name
	if name == "" {
		name = filepath.Base(filepath.Dir(dockerfilePath))
	}

	fmt.Fprintf(out, "Creating snapshot %q from %s...\n", name, dockerfile)

	// Create snapshot
	if creator == nil {
		creator = defaultSnapshotCreator
	}

	ctx := context.Background()
	snapshotID, err := creator(ctx, cfg.APIKey, cfg.ServerURL, name, content, out)
	if err != nil {
		return fmt.Errorf("snapshot creation failed: %w", err)
	}

	fmt.Fprintf(out, "Snapshot created: %s\n", snapshotID)
	return nil
}

// snapshotDeleter is a function that deletes a Daytona snapshot by ID.
// Injected in tests to avoid real SDK calls.
type snapshotDeleter func(ctx context.Context, apiKey, serverURL, snapshotID string) error

// defaultSnapshotDeleter creates a real Daytona client and calls DeleteSnapshot.
func defaultSnapshotDeleter(ctx context.Context, apiKey, serverURL, snapshotID string) error {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.DeleteSnapshot(ctx, client, snapshotID)
}

// runSnapshotDelete contains the testable logic for the snapshot delete command.
// dir is the project root directory (containing .hal/).
// If deleter is nil, the real SDK client is used.
func runSnapshotDelete(dir, snapshotID string, out io.Writer, deleter snapshotDeleter) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	if snapshotID == "" {
		return fmt.Errorf("snapshot ID is required - use --id flag")
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := sandbox.EnsureAuth(cfg.APIKey, func() error {
		return runSandboxSetup(dir, os.Stdin, out, readPasswordFromTerminal)
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

	fmt.Fprintf(out, "Deleting snapshot %q...\n", snapshotID)

	if deleter == nil {
		deleter = defaultSnapshotDeleter
	}

	ctx := context.Background()
	if err := deleter(ctx, cfg.APIKey, cfg.ServerURL, snapshotID); err != nil {
		return fmt.Errorf("snapshot deletion failed: %w", err)
	}

	fmt.Fprintf(out, "Snapshot %q deleted.\n", snapshotID)
	return nil
}
