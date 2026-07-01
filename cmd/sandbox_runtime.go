package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
)

type sandboxRuntimeDeps struct {
	list            func(context.Context, sandboxRuntimeListRequest, io.Writer) error
	status          func(context.Context, sandboxRuntimeStatusRequest, io.Writer) error
	loadHost        func(string) (*sandbox.SandboxHost, error)
	newWorkerClient func(string) (sandboxHostWorkerClient, error)
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
	return sandboxRuntimeDeps{
		loadHost:        sandbox.LoadHost,
		newWorkerClient: newSandboxHostWorkerClient,
	}
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
	if deps.loadHost == nil {
		deps.loadHost = sandbox.LoadHost
	}
	if deps.newWorkerClient == nil {
		deps.newWorkerClient = newSandboxHostWorkerClient
	}
	if deps.list == nil {
		loadHost := deps.loadHost
		newWorkerClient := deps.newWorkerClient
		deps.list = func(ctx context.Context, req sandboxRuntimeListRequest, out io.Writer) error {
			return runSandboxRuntimeList(ctx, req, out, loadHost, newWorkerClient)
		}
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

func runSandboxRuntimeList(_ context.Context, req sandboxRuntimeListRequest, out io.Writer, loadHost func(string) (*sandbox.SandboxHost, error), _ func(string) (sandboxHostWorkerClient, error)) error {
	hostID := strings.TrimSpace(req.HostID)
	if hostID == "" {
		return fmt.Errorf("host id is required")
	}
	if req.Live {
		return fmt.Errorf("live sandbox runtime list is not implemented yet")
	}
	if loadHost == nil {
		loadHost = sandbox.LoadHost
	}

	host, err := loadHost(hostID)
	if err != nil {
		return err
	}
	if req.JSON {
		return renderSandboxRuntimeListJSON(out, host)
	}
	return renderSandboxRuntimeList(out, host)
}

func runSandboxRuntimeStatus(context.Context, sandboxRuntimeStatusRequest, io.Writer) error {
	return fmt.Errorf("sandbox runtime status is not implemented yet")
}

func renderSandboxRuntimeListJSON(out io.Writer, host *sandbox.SandboxHost) error {
	if out == nil {
		return nil
	}
	resp := newSandboxRuntimeListCachedResponse(host)
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox runtime list: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func renderSandboxRuntimeList(out io.Writer, host *sandbox.SandboxHost) error {
	if out == nil || host == nil {
		return nil
	}

	if _, err := fmt.Fprintf(out, "Sandbox runtimes for %s (cached)\n", sandboxHostDisplayValue(host.Name, host.ID)); err != nil {
		return err
	}
	type runtimeLine struct {
		label string
		value string
	}
	lines := []runtimeLine{
		{"Source", "cached durable runtime metadata"},
		{"Host ID", sandboxHostDisplayValue(host.ID, "-")},
		{"Host kind", sandboxHostDisplayValue(host.Kind, "unknown")},
		{"Endpoint", sandboxHostEndpointSummary(host.Endpoint)},
		{"Capacity", sandboxHostCapacitySummary(host.Capacity)},
		{"Security", sandboxRuntimeSecurityHumanSummary(host.Security)},
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, line := range lines {
		if _, err := fmt.Fprintf(tw, "%s:\t%s\n", line.label, line.value); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	runtimes := sortedUniqueStrings(host.SupportedRuntimes)
	if len(runtimes) == 0 {
		_, err := fmt.Fprintln(out, "No cached runtime metadata is available.")
		return err
	}
	if _, err := fmt.Fprintln(out, "Runtimes (sorted by runtime id):"); err != nil {
		return err
	}
	runtimeTable := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(runtimeTable, "ID\tHOST KIND\tISOLATION\tOPERATIONS"); err != nil {
		return err
	}
	for _, runtimeID := range runtimes {
		if _, err := fmt.Fprintf(runtimeTable, "%s\tunknown\tunknown\tunknown\n", runtimeID); err != nil {
			return err
		}
	}
	return runtimeTable.Flush()
}

func sandboxRuntimeSecurityHumanSummary(security *sandbox.SandboxSecurity) string {
	if security == nil {
		return "unknown"
	}
	parts := make([]string, 0, 4)
	if security.Network != nil {
		if policy := strings.TrimSpace(security.Network.PolicyRequested); policy != "" {
			parts = append(parts, "requested network "+policy)
		}
		if policy := strings.TrimSpace(security.Network.PolicyEnforced); policy != "" {
			enforced := "enforced network " + policy
			if mode := strings.TrimSpace(security.Network.EnforcementMode); mode != "" {
				enforced += " via " + mode
			}
			parts = append(parts, enforced)
		} else if mode := strings.TrimSpace(security.Network.EnforcementMode); mode != "" {
			parts = append(parts, "network enforcement "+mode)
		}
	}
	if security.Secrets != nil {
		if requested := sandboxRuntimeHumanList(security.Secrets.RequestedModes); requested != "" {
			parts = append(parts, "requested credentials "+requested)
		}
		if active := sandboxRuntimeHumanList(security.Secrets.ActiveModes); active != "" {
			parts = append(parts, "active credentials "+active)
		}
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "; ")
}

func sandboxRuntimeHumanList(values []string) string {
	values = sortedUniqueStrings(values)
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}
