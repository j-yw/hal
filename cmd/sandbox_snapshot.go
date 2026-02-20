package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Manage sandbox snapshots",
	Long:  `Create and manage Daytona sandbox snapshots from Docker images.`,
}

var snapshotListCmd = &cobra.Command{
	Use:   "list",
	Short: "List snapshots",
	Long:  `List Daytona snapshots available to the configured account.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSnapshotList(".", os.Stdout, nil)
	},
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
	Short: "Create a snapshot from a Docker image",
	Long: `Create a Daytona snapshot from a Docker image reference.

Examples:
  hal sandbox snapshot create --image ubuntu:22.04 --name base-ubuntu
  hal sandbox snapshot create --image ghcr.io/org/hal-sandbox:latest --name hal-dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		imageRef, _ := cmd.Flags().GetString("image")
		name, _ := cmd.Flags().GetString("name")
		return runSnapshotCreate(".", imageRef, name, os.Stdout, nil)
	},
}

func init() {
	snapshotCreateCmd.Flags().String("image", "", "Docker image reference (required, e.g., ghcr.io/org/image:tag)")
	snapshotCreateCmd.Flags().String("name", "", "snapshot name (defaults to image name)")
	_ = snapshotCreateCmd.MarkFlagRequired("image")

	snapshotDeleteCmd.Flags().String("id", "", "snapshot ID to delete (required)")

	snapshotCmd.AddCommand(snapshotListCmd)
	snapshotCmd.AddCommand(snapshotCreateCmd)
	snapshotCmd.AddCommand(snapshotDeleteCmd)
	sandboxCmd.AddCommand(snapshotCmd)
}

// snapshotCreator is a function that creates a Daytona snapshot from a Docker image reference.
// Injected in tests to avoid real SDK calls.
type snapshotCreator func(ctx context.Context, apiKey, serverURL, name, imageRef string, out io.Writer) (string, error)

// snapshotLister is a function that lists Daytona snapshots.
// Injected in tests to avoid real SDK calls.
type snapshotLister func(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error)

// defaultSnapshotCreator creates a real Daytona client and calls CreateSnapshot.
func defaultSnapshotCreator(ctx context.Context, apiKey, serverURL, name, imageRef string, out io.Writer) (string, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return "", fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSnapshot(ctx, client, name, imageRef, out)
}

// defaultSnapshotLister creates a real Daytona client and lists snapshots.
func defaultSnapshotLister(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.ListSnapshots(ctx, client)
}

// runSnapshotCreate contains the testable logic for the snapshot create command.
// dir is the project root directory (containing .hal/).
// If creator is nil, the real SDK client is used.
func runSnapshotCreate(dir, imageRef, name string, out io.Writer, creator snapshotCreator) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return fmt.Errorf("image reference is required - use --image <image>")
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

	// Resolve snapshot name from image reference if not provided
	if name == "" {
		// Use image name without registry prefix and tag
		// e.g., "ghcr.io/jywlabs/hal-sandbox:latest" -> "hal-sandbox"
		name = imageNameFromRef(imageRef)
	}

	fmt.Fprintf(out, "Creating snapshot %q from image %s...\n", name, imageRef)

	// Create snapshot
	if creator == nil {
		creator = defaultSnapshotCreator
	}

	ctx := context.Background()
	snapshotID, err := creator(ctx, cfg.APIKey, cfg.ServerURL, name, imageRef, out)
	if err != nil {
		return fmt.Errorf("snapshot creation failed: %w", err)
	}

	fmt.Fprintf(out, "Snapshot created: %s\n", snapshotID)
	return nil
}

// runSnapshotList contains the testable logic for listing snapshots.
// dir is the project root directory (containing .hal/).
// If lister is nil, the real SDK client is used.
func runSnapshotList(dir string, out io.Writer, lister snapshotLister) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

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

	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("reloading config: %w", err)
	}

	if lister == nil {
		lister = defaultSnapshotLister
	}

	ctx := context.Background()
	snapshots, err := lister(ctx, cfg.APIKey, cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("listing snapshots failed: %w", err)
	}

	if len(snapshots) == 0 {
		fmt.Fprintln(out, "No snapshots found.")
		return nil
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].UpdatedAt.Equal(snapshots[j].UpdatedAt) {
			return snapshots[i].Name < snapshots[j].Name
		}
		return snapshots[i].UpdatedAt.After(snapshots[j].UpdatedAt)
	})

	fmt.Fprintln(out, "ID\tNAME\tSTATE\tUPDATED")
	for _, snap := range snapshots {
		updated := "-"
		if !snap.UpdatedAt.IsZero() {
			updated = snap.UpdatedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", snap.ID, snap.Name, snap.State, updated)
	}

	return nil
}

// imageNameFromRef extracts a short name from a Docker image reference.
// e.g., "ghcr.io/jywlabs/hal-sandbox:latest" -> "hal-sandbox"
// e.g., "hal-sandbox:0.1" -> "hal-sandbox"
// e.g., "ubuntu:22.04" -> "ubuntu"
func imageNameFromRef(ref string) string {
	// Strip digest.
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	// Take last path component.
	if idx := strings.LastIndex(ref, "/"); idx != -1 {
		ref = ref[idx+1:]
	}
	// Strip tag from image component only.
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		ref = ref[:idx]
	}
	return ref
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
