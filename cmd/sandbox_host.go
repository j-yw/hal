package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type sandboxHostDeps struct {
	registerWorker func(context.Context, sandboxHostRegisterWorkerRequest, io.Writer) error
	list           func(context.Context, sandboxHostListRequest, io.Writer) error
	status         func(context.Context, sandboxHostStatusRequest, io.Writer) error
	delete         func(context.Context, sandboxHostDeleteRequest, io.Writer) error
}

type sandboxHostRegisterWorkerRequest struct {
	WorkerID   string
	SocketPath string
}

type sandboxHostListRequest struct{}

type sandboxHostStatusRequest struct {
	HostID string
}

type sandboxHostDeleteRequest struct {
	HostID string
}

type sandboxHostRegisterWorkerFlags struct {
	socketPath string
}

var sandboxHostCmd = newSandboxHostCommand(defaultSandboxHostDeps())

func init() {
	sandboxCmd.AddCommand(sandboxHostCmd)
}

func defaultSandboxHostDeps() sandboxHostDeps {
	return sandboxHostDeps{}
}

func newSandboxHostCommand(deps sandboxHostDeps) *cobra.Command {
	deps = normalizeSandboxHostDeps(deps)

	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage sandbox host records",
		Long: `Manage durable sandbox host records.

Worker host records describe local sandbox worker daemon endpoints and cached
capability metadata. These commands operate on the durable host registry only;
they do not provision, start, stop, or delete runtime targets.`,
		Example: `  hal sandbox host list
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host status local-worker
  hal sandbox host delete local-worker`,
		Args: noArgsValidation(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newSandboxHostRegisterCommand(deps))
	cmd.AddCommand(newSandboxHostListCommand(deps))
	cmd.AddCommand(newSandboxHostStatusCommand(deps))
	cmd.AddCommand(newSandboxHostDeleteCommand(deps))

	return cmd
}

func newSandboxHostRegisterCommand(deps sandboxHostDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a sandbox host",
		Long: `Register a sandbox host in the durable host registry.

Registration stores host metadata for later listing and status inspection. The
worker subcommand registers local sandbox worker daemon endpoints without
changing sandbox runtime selection defaults.`,
		Example: `  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock`,
		Args:    noArgsValidation(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newSandboxHostRegisterWorkerCommand(deps))
	return cmd
}

func newSandboxHostRegisterWorkerCommand(deps sandboxHostDeps) *cobra.Command {
	flags := sandboxHostRegisterWorkerFlags{}
	cmd := &cobra.Command{
		Use:   "worker ID",
		Short: "Register a sandbox worker host",
		Long: `Register a sandbox worker host in the durable host registry.

The command accepts a worker identity and local socket endpoint. Worker host
records describe sandbox daemon endpoints without changing sandbox runtime
selection defaults.`,
		Example: `  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock`,
		Args:    exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxHostRegisterWorkerRequest{
				WorkerID:   strings.TrimSpace(args[0]),
				SocketPath: strings.TrimSpace(flags.socketPath),
			}
			return runSandboxHostCobra(cmd, "Sandbox Host Register failed", func(ctx context.Context, out io.Writer) error {
				return deps.registerWorker(ctx, req, out)
			})
		},
	}
	cmd.Flags().StringVar(&flags.socketPath, "socket", "", "Local Unix socket path for the sandbox worker")
	return cmd
}

func newSandboxHostListCommand(deps sandboxHostDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sandbox host records",
		Long: `List durable sandbox host records.

The command renders host registry metadata in stable human-readable output. It
does not contact worker daemons or runtime providers.`,
		Example: `  hal sandbox host list`,
		Args:    noArgsValidation(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSandboxHostCobra(cmd, "Sandbox Host List failed", func(ctx context.Context, out io.Writer) error {
				return deps.list(ctx, sandboxHostListRequest{}, out)
			})
		},
	}
	return cmd
}

func newSandboxHostStatusCommand(deps sandboxHostDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status ID",
		Short: "Show sandbox host status",
		Long: `Show cached durable sandbox host status.

The command renders cached host registry metadata. It does not contact worker
daemons unless live refresh is explicitly requested by a supported flag.`,
		Example: `  hal sandbox host status local-worker`,
		Args:    exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxHostStatusRequest{HostID: strings.TrimSpace(args[0])}
			return runSandboxHostCobra(cmd, "Sandbox Host Status failed", func(ctx context.Context, out io.Writer) error {
				return deps.status(ctx, req, out)
			})
		},
	}
	return cmd
}

func newSandboxHostDeleteCommand(deps sandboxHostDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a sandbox host record",
		Long: `Delete a durable sandbox host record.

The command removes only host registry metadata. It does not stop worker
daemons or mutate runtime targets.`,
		Example: `  hal sandbox host delete local-worker`,
		Args:    exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxHostDeleteRequest{HostID: strings.TrimSpace(args[0])}
			return runSandboxHostCobra(cmd, "Sandbox Host Delete failed", func(ctx context.Context, out io.Writer) error {
				return deps.delete(ctx, req, out)
			})
		},
	}
	return cmd
}

func normalizeSandboxHostDeps(deps sandboxHostDeps) sandboxHostDeps {
	if deps.registerWorker == nil {
		deps.registerWorker = func(context.Context, sandboxHostRegisterWorkerRequest, io.Writer) error {
			return sandboxHostNotImplementedError("sandbox host register worker")
		}
	}
	if deps.list == nil {
		deps.list = func(context.Context, sandboxHostListRequest, io.Writer) error {
			return sandboxHostNotImplementedError("sandbox host list")
		}
	}
	if deps.status == nil {
		deps.status = func(context.Context, sandboxHostStatusRequest, io.Writer) error {
			return sandboxHostNotImplementedError("sandbox host status")
		}
	}
	if deps.delete == nil {
		deps.delete = func(context.Context, sandboxHostDeleteRequest, io.Writer) error {
			return sandboxHostNotImplementedError("sandbox host delete")
		}
	}
	return deps
}

func sandboxHostNotImplementedError(command string) error {
	return fmt.Errorf("%s is not implemented yet", command)
}

func runSandboxHostCobra(cmd *cobra.Command, title string, run func(context.Context, io.Writer) error) error {
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
