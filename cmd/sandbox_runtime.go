package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type sandboxRuntimeDeps struct {
	list   func(context.Context, sandboxRuntimeListRequest, io.Writer) error
	status func(context.Context, sandboxRuntimeStatusRequest, io.Writer) error
}

type sandboxRuntimeListRequest struct {
	HostID string
	Live   bool
	JSON   bool
}

type sandboxRuntimeStatusRequest struct {
	HostID    string
	RuntimeID string
	Live      bool
	JSON      bool
}

var sandboxRuntimeCmd = newSandboxRuntimeCommand(defaultSandboxRuntimeDeps())

func init() {
	sandboxCmd.AddCommand(sandboxRuntimeCmd)
}

func defaultSandboxRuntimeDeps() sandboxRuntimeDeps {
	return sandboxRuntimeDeps{}
}

func newSandboxRuntimeCommand(deps sandboxRuntimeDeps) *cobra.Command {
	deps = normalizeSandboxRuntimeDeps(deps)

	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Inspect sandbox runtime metadata",
		Long: `Inspect sandbox runtime metadata for registered sandbox hosts.

Runtime inspection is read-only. These commands report cached durable metadata by
default and only attempt live worker inspection when a supported --live flag is
explicitly requested. Output avoids raw socket paths, hostnames, credentials,
URL query strings, temp paths, and sensitive endpoint details.`,
		Example: `  hal sandbox runtime list local-worker
  hal sandbox runtime list local-worker --json
  hal sandbox runtime list local-worker --live
  hal sandbox runtime status local-worker rootless_podman
  hal sandbox runtime status local-worker rootless_podman --json`,
		Args: noArgsValidation(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newSandboxRuntimeListCommand(deps))
	cmd.AddCommand(newSandboxRuntimeStatusCommand(deps))

	return cmd
}

func newSandboxRuntimeListCommand(deps sandboxRuntimeDeps) *cobra.Command {
	flags := struct {
		live bool
		json bool
	}{}
	cmd := &cobra.Command{
		Use:   "list HOST_ID",
		Short: "List sandbox runtimes for a host",
		Long: `List sandbox runtimes for a registered sandbox host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported worker refresh in later runtime inspection phases. Use
--json for machine-readable output following the sandbox-runtime-list-v1
contract.`,
		Example: `  hal sandbox runtime list local-worker
  hal sandbox runtime list local-worker --json
  hal sandbox runtime list local-worker --live
  hal sandbox runtime list local-worker --live --json`,
		Args: exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxRuntimeListRequest{
				HostID: strings.TrimSpace(args[0]),
				Live:   flags.live,
				JSON:   flags.json,
			}
			return runSandboxRuntimeCobra(cmd, "Sandbox Runtime List failed", func(ctx context.Context, out io.Writer) error {
				return deps.list(ctx, req, out)
			})
		},
	}
	cmd.Flags().BoolVar(&flags.live, "live", false, "Refresh runtime metadata from a supported local worker")
	cmd.Flags().BoolVar(&flags.json, "json", false, "Output machine-readable JSON (sandbox-runtime-list-v1 contract)")
	return cmd
}

func newSandboxRuntimeStatusCommand(deps sandboxRuntimeDeps) *cobra.Command {
	flags := struct {
		live bool
		json bool
	}{}
	cmd := &cobra.Command{
		Use:   "status HOST_ID RUNTIME_ID",
		Short: "Show sandbox runtime status",
		Long: `Show sandbox runtime status for one runtime on a registered host.

Cached mode is the default and reads only durable host metadata. Use --live to
request a supported worker refresh in later runtime inspection phases. Use
--json for machine-readable output following the sandbox-runtime-status-v1
contract.`,
		Example: `  hal sandbox runtime status local-worker rootless_podman
  hal sandbox runtime status local-worker rootless_podman --json
  hal sandbox runtime status local-worker rootless_podman --live
  hal sandbox runtime status local-worker rootless_podman --live --json`,
		Args: exactArgsValidation(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxRuntimeStatusRequest{
				HostID:    strings.TrimSpace(args[0]),
				RuntimeID: strings.TrimSpace(args[1]),
				Live:      flags.live,
				JSON:      flags.json,
			}
			return runSandboxRuntimeCobra(cmd, "Sandbox Runtime Status failed", func(ctx context.Context, out io.Writer) error {
				return deps.status(ctx, req, out)
			})
		},
	}
	cmd.Flags().BoolVar(&flags.live, "live", false, "Refresh runtime metadata from a supported local worker")
	cmd.Flags().BoolVar(&flags.json, "json", false, "Output machine-readable JSON (sandbox-runtime-status-v1 contract)")
	return cmd
}

func normalizeSandboxRuntimeDeps(deps sandboxRuntimeDeps) sandboxRuntimeDeps {
	if deps.list == nil {
		deps.list = runSandboxRuntimeList
	}
	if deps.status == nil {
		deps.status = runSandboxRuntimeStatus
	}
	return deps
}

func runSandboxRuntimeCobra(cmd *cobra.Command, title string, run func(context.Context, io.Writer) error) error {
	ctx := context.Background()
	out := io.Writer(os.Stdout)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
	}

	if err := run(ctx, out); err != nil {
		return renderSandboxCobraError(cmd, title, err)
	}
	return nil
}

func runSandboxRuntimeList(context.Context, sandboxRuntimeListRequest, io.Writer) error {
	return fmt.Errorf("sandbox runtime list is not implemented yet")
}

func runSandboxRuntimeStatus(context.Context, sandboxRuntimeStatusRequest, io.Writer) error {
	return fmt.Errorf("sandbox runtime status is not implemented yet")
}
