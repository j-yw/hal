package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

type sandboxHostDeps struct {
	registerWorker  func(context.Context, sandboxHostRegisterWorkerRequest, io.Writer) error
	list            func(context.Context, sandboxHostListRequest, io.Writer) error
	status          func(context.Context, sandboxHostStatusRequest, io.Writer) error
	delete          func(context.Context, sandboxHostDeleteRequest, io.Writer) error
	saveHost        func(*sandbox.SandboxHost) error
	newWorkerClient func(string) (sandboxHostWorkerClient, error)
	now             func() time.Time
}

type sandboxHostWorkerClient interface {
	Status(context.Context) (*sandboxworker.Status, error)
	Capabilities(context.Context) (*sandboxworker.Capabilities, error)
}

type sandboxHostRegisterWorkerRequest struct {
	WorkerID   string
	SocketPath string
	Live       bool
}

type sandboxHostListRequest struct {
	JSON bool
}

type sandboxHostStatusRequest struct {
	HostID string
}

type sandboxHostDeleteRequest struct {
	HostID string
}

type sandboxHostRegisterWorkerFlags struct {
	socketPath string
	live       bool
}

var sandboxHostCmd = newSandboxHostCommand(defaultSandboxHostDeps())

func init() {
	sandboxCmd.AddCommand(sandboxHostCmd)
}

func defaultSandboxHostDeps() sandboxHostDeps {
	return sandboxHostDeps{
		saveHost:        sandbox.SaveHost,
		newWorkerClient: newSandboxHostWorkerClient,
		now:             time.Now,
	}
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
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live
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
		Example: `  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live`,
		Args: noArgsValidation(),
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
		Example: `  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock
  hal sandbox host register worker local-worker --socket /tmp/hal-sandboxd.sock --live`,
		Args: exactArgsValidation(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := sandboxHostRegisterWorkerRequest{
				WorkerID:   strings.TrimSpace(args[0]),
				SocketPath: strings.TrimSpace(flags.socketPath),
				Live:       flags.live,
			}
			return runSandboxHostCobra(cmd, "Sandbox Host Register failed", func(ctx context.Context, out io.Writer) error {
				return deps.registerWorker(ctx, req, out)
			})
		},
	}
	cmd.Flags().StringVar(&flags.socketPath, "socket", "", "Local Unix socket path for the sandbox worker")
	cmd.Flags().BoolVar(&flags.live, "live", false, "Query the worker daemon once and persist live metadata")
	return cmd
}

func newSandboxHostListCommand(deps sandboxHostDeps) *cobra.Command {
	flags := struct {
		json bool
	}{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sandbox host records",
		Long: `List durable sandbox host records.

The command renders host registry metadata in stable human-readable output. It
sorts records by host name, then id, and does not contact worker daemons or
runtime providers. Use --json for machine-readable output following the
sandbox-host-list-v1 contract.`,
		Example: `  hal sandbox host list
  hal sandbox host list --json`,
		Args: noArgsValidation(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			jsonMode := flags.json
			if cmd != nil {
				if f := cmd.Flags().Lookup("json"); f != nil {
					v, err := cmd.Flags().GetBool("json")
					if err == nil {
						jsonMode = v
					}
				}
			}
			return runSandboxHostCobra(cmd, "Sandbox Host List failed", func(ctx context.Context, out io.Writer) error {
				return deps.list(ctx, sandboxHostListRequest{JSON: jsonMode}, out)
			})
		},
	}
	cmd.Flags().BoolVar(&flags.json, "json", false, "Output machine-readable JSON (sandbox-host-list-v1 contract)")
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
	if deps.saveHost == nil {
		deps.saveHost = sandbox.SaveHost
	}
	if deps.newWorkerClient == nil {
		deps.newWorkerClient = newSandboxHostWorkerClient
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.registerWorker == nil {
		saveHost := deps.saveHost
		newWorkerClient := deps.newWorkerClient
		now := deps.now
		deps.registerWorker = func(ctx context.Context, req sandboxHostRegisterWorkerRequest, out io.Writer) error {
			return runSandboxHostRegisterWorker(ctx, req, out, saveHost, newWorkerClient, now)
		}
	}
	if deps.list == nil {
		deps.list = runSandboxHostList
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

func runSandboxHostRegisterWorker(ctx context.Context, req sandboxHostRegisterWorkerRequest, out io.Writer, saveHost func(*sandbox.SandboxHost) error, newWorkerClient func(string) (sandboxHostWorkerClient, error), now func() time.Time) error {
	if strings.TrimSpace(req.WorkerID) == "" {
		return fmt.Errorf("worker id is required")
	}
	if strings.TrimSpace(req.SocketPath) == "" {
		return fmt.Errorf("worker socket path is required")
	}
	if saveHost == nil {
		saveHost = sandbox.SaveHost
	}
	if newWorkerClient == nil {
		newWorkerClient = newSandboxHostWorkerClient
	}
	if now == nil {
		now = time.Now
	}

	metadataReq := sandboxHostWorkerMetadataRequest{
		WorkerID:   req.WorkerID,
		SocketPath: req.SocketPath,
	}
	mode := "offline"
	if req.Live {
		status, capabilities, err := querySandboxHostWorkerMetadata(ctx, req.SocketPath, newWorkerClient)
		if err != nil {
			return err
		}
		metadataReq.Status = status
		metadataReq.Capabilities = capabilities
		metadataReq.CheckedAt = now()
		mode = "live"
	}

	host, err := sandboxHostFromWorkerMetadata(metadataReq)
	if err != nil {
		return err
	}
	if err := saveHost(host); err != nil {
		return err
	}
	if out != nil {
		fmt.Fprintf(out, "Registered worker host %s (%s; endpoint: local Unix socket", host.ID, mode)
		if req.Live && host.Health != nil && strings.TrimSpace(host.Health.Status) != "" {
			fmt.Fprintf(out, "; health: %s", host.Health.Status)
		}
		if req.Live && len(host.SupportedRuntimes) > 0 {
			fmt.Fprintf(out, "; runtimes: %s", strings.Join(host.SupportedRuntimes, ", "))
		}
		fmt.Fprintln(out, ").")
	}
	return nil
}

func runSandboxHostList(_ context.Context, req sandboxHostListRequest, out io.Writer) error {
	hosts, err := sandbox.ListHosts()
	if err != nil {
		return err
	}
	if req.JSON {
		return renderSandboxHostListJSON(out, hosts)
	}
	return renderSandboxHostList(out, hosts)
}

func renderSandboxHostListJSON(out io.Writer, hosts []*sandbox.SandboxHost) error {
	if out == nil {
		return nil
	}
	resp := newSandboxHostListResponse(hosts)
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox host list: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func renderSandboxHostList(out io.Writer, hosts []*sandbox.SandboxHost) error {
	if out == nil {
		return nil
	}
	if len(hosts) == 0 {
		_, err := fmt.Fprintln(out, "No sandbox hosts registered.")
		return err
	}

	if _, err := fmt.Fprintln(out, "Sandbox hosts (sorted by name, then id):"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tID\tKIND\tENDPOINT\tHEALTH\tRUNTIMES\tCAPACITY"); err != nil {
		return err
	}
	for _, host := range hosts {
		if host == nil {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sandboxHostDisplayValue(host.Name, host.ID),
			sandboxHostDisplayValue(host.ID, "-"),
			sandboxHostDisplayValue(host.Kind, "unknown"),
			sandboxHostEndpointSummary(host.Endpoint),
			sandboxHostHealthSummary(host.Health),
			sandboxHostRuntimesSummary(host.SupportedRuntimes),
			sandboxHostCapacitySummary(host.Capacity),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func sandboxHostDisplayValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func sandboxHostEndpointSummary(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "none"
	}
	lowerEndpoint := strings.ToLower(endpoint)
	if strings.HasPrefix(lowerEndpoint, "unix://") || strings.HasPrefix(lowerEndpoint, "unix:") {
		return "local Unix socket"
	}
	if index := strings.Index(endpoint, ":"); index > 0 {
		scheme := strings.ToLower(strings.TrimSpace(endpoint[:index]))
		if scheme != "" {
			return scheme + " endpoint"
		}
	}
	return "configured"
}

func sandboxHostHealthSummary(health *sandbox.HostHealth) string {
	if health == nil {
		return sandboxworker.HealthStatusUnknown
	}
	return sandboxHostDisplayValue(health.Status, sandboxworker.HealthStatusUnknown)
}

func sandboxHostRuntimesSummary(runtimes []string) string {
	runtimes = sortedUniqueStrings(runtimes)
	if len(runtimes) == 0 {
		return "none"
	}
	return strings.Join(runtimes, ",")
}

func sandboxHostCapacitySummary(capacity *sandbox.HostCapacity) string {
	if capacity == nil {
		return "unknown"
	}
	parts := make([]string, 0, 4)
	if capacity.MaxConcurrentSandboxes > 0 {
		parts = append(parts, fmt.Sprintf("max %d sandboxes", capacity.MaxConcurrentSandboxes))
	}
	if capacity.CPUCores > 0 {
		parts = append(parts, fmt.Sprintf("%d CPU", capacity.CPUCores))
	}
	if capacity.MemoryMB > 0 {
		parts = append(parts, fmt.Sprintf("%d MiB", capacity.MemoryMB))
	}
	if capacity.DiskGB > 0 {
		parts = append(parts, fmt.Sprintf("%d GiB disk", capacity.DiskGB))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func querySandboxHostWorkerMetadata(ctx context.Context, socketPath string, newWorkerClient func(string) (sandboxHostWorkerClient, error)) (*sandboxworker.Status, *sandboxworker.Capabilities, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := newWorkerClient(sandboxHostWorkerClientSocketPath(socketPath))
	if err != nil {
		return nil, nil, sandboxHostWorkerClientError("connect", err)
	}
	if client == nil {
		return nil, nil, sandboxHostWorkerClientError("connect", fmt.Errorf("worker client is not configured"))
	}

	status, err := client.Status(ctx)
	if err != nil {
		return nil, nil, sandboxHostWorkerClientError(sandboxworker.OperationStatus, err)
	}
	if status == nil {
		return nil, nil, sandboxHostWorkerClientError(sandboxworker.OperationStatus, fmt.Errorf("worker status response did not include status payload"))
	}

	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return nil, nil, sandboxHostWorkerClientError(sandboxworker.OperationCapabilities, err)
	}
	if capabilities == nil {
		return nil, nil, sandboxHostWorkerClientError(sandboxworker.OperationCapabilities, fmt.Errorf("worker capabilities response did not include capabilities payload"))
	}

	return status, capabilities, nil
}

func newSandboxHostWorkerClient(socketPath string) (sandboxHostWorkerClient, error) {
	return sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: strings.TrimSpace(socketPath)})
}

func sandboxHostWorkerClientSocketPath(socketPath string) string {
	socketPath = strings.TrimSpace(socketPath)
	socketPath = strings.TrimPrefix(socketPath, "unix://")
	socketPath = strings.TrimPrefix(socketPath, "unix:")
	return socketPath
}

func sandboxHostWorkerClientError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &sandboxworker.ClientError{
		Operation: operation,
		Err:       err,
	}
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
