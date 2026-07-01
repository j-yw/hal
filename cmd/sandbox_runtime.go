package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

type sandboxRuntimeDeps struct {
	list            func(context.Context, sandboxRuntimeListRequest, io.Writer) error
	status          func(context.Context, sandboxRuntimeStatusRequest, io.Writer) error
	loadHost        func(string) (*sandbox.SandboxHost, error)
	newWorkerClient func(string) (sandboxHostWorkerClient, error)
	now             func() time.Time
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

type sandboxRuntimeStatusCommandError struct {
	message string
}

func (err sandboxRuntimeStatusCommandError) Error() string {
	if strings.TrimSpace(err.message) == "" {
		return "sandbox runtime status failed"
	}
	return err.message
}

var sandboxRuntimeCmd = newSandboxRuntimeCommand(defaultSandboxRuntimeDeps())

func init() {
	sandboxCmd.AddCommand(sandboxRuntimeCmd)
}

func defaultSandboxRuntimeDeps() sandboxRuntimeDeps {
	return sandboxRuntimeDeps{
		loadHost:        sandbox.LoadHost,
		newWorkerClient: newSandboxHostWorkerClient,
		now:             time.Now,
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
request a supported local worker capability refresh for this response. Use --json
for machine-readable output following the sandbox-runtime-list-v1 contract.`,
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
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.list == nil {
		loadHost := deps.loadHost
		newWorkerClient := deps.newWorkerClient
		now := deps.now
		deps.list = func(ctx context.Context, req sandboxRuntimeListRequest, out io.Writer) error {
			return runSandboxRuntimeList(ctx, req, out, loadHost, newWorkerClient, now)
		}
	}
	if deps.status == nil {
		loadHost := deps.loadHost
		deps.status = func(ctx context.Context, req sandboxRuntimeStatusRequest, out io.Writer) error {
			return runSandboxRuntimeStatus(ctx, req, out, loadHost)
		}
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

func runSandboxRuntimeList(ctx context.Context, req sandboxRuntimeListRequest, out io.Writer, loadHost func(string) (*sandbox.SandboxHost, error), newWorkerClient func(string) (sandboxHostWorkerClient, error), now func() time.Time) error {
	hostID := strings.TrimSpace(req.HostID)
	if hostID == "" {
		return fmt.Errorf("host id is required")
	}
	if loadHost == nil {
		loadHost = sandbox.LoadHost
	}
	if newWorkerClient == nil {
		newWorkerClient = newSandboxHostWorkerClient
	}
	if now == nil {
		now = time.Now
	}

	host, err := loadHost(hostID)
	if err != nil {
		return err
	}
	if req.Live {
		if strings.TrimSpace(host.Kind) != sandbox.SandboxHostKindWorker {
			resp := newSandboxRuntimeListUnsupportedLiveResponse(host)
			if req.JSON {
				return renderSandboxRuntimeListResponseJSON(out, resp)
			}
			return renderSandboxRuntimeListResponse(out, resp)
		}
		status, capabilities, err := querySandboxRuntimeListLiveMetadata(ctx, host, newWorkerClient)
		if err != nil {
			return err
		}
		refreshedAt := now()
		resp := newSandboxRuntimeListLiveResponse(host, status, capabilities, refreshedAt)
		if req.JSON {
			return renderSandboxRuntimeListResponseJSON(out, resp)
		}
		return renderSandboxRuntimeListResponse(out, resp)
	}
	if req.JSON {
		return renderSandboxRuntimeListJSON(out, host)
	}
	return renderSandboxRuntimeList(out, host)
}

func runSandboxRuntimeStatus(_ context.Context, req sandboxRuntimeStatusRequest, out io.Writer, loadHost func(string) (*sandbox.SandboxHost, error)) error {
	hostID := strings.TrimSpace(req.HostID)
	if hostID == "" {
		return fmt.Errorf("host id is required")
	}
	runtimeID := strings.TrimSpace(req.RuntimeID)
	if runtimeID == "" {
		return fmt.Errorf("runtime id is required")
	}
	if req.Live {
		return fmt.Errorf("live sandbox runtime status is not implemented yet")
	}
	if loadHost == nil {
		loadHost = sandbox.LoadHost
	}

	host, err := loadHost(hostID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			statusErr := sandboxRuntimeStatusCommandError{
				message: fmt.Sprintf("host %q was not found", hostID),
			}
			if req.JSON {
				resp := newSandboxRuntimeStatusHostNotFoundResponse(hostID, runtimeID)
				if renderErr := renderSandboxRuntimeStatusResponseJSON(out, resp); renderErr != nil {
					return renderErr
				}
			}
			return statusErr
		}
		return err
	}

	if !sandboxRuntimeHostSupportsRuntime(host, runtimeID) {
		statusErr := sandboxRuntimeStatusCommandError{
			message: fmt.Sprintf("runtime %q is not registered for this host", runtimeID),
		}
		if req.JSON {
			resp := newSandboxRuntimeStatusRuntimeNotFoundResponse(host, runtimeID)
			if renderErr := renderSandboxRuntimeStatusResponseJSON(out, resp); renderErr != nil {
				return renderErr
			}
		}
		return statusErr
	}

	resp := newSandboxRuntimeStatusCachedResponse(host, runtimeID)
	if req.JSON {
		return renderSandboxRuntimeStatusResponseJSON(out, resp)
	}
	return renderSandboxRuntimeStatusResponse(out, resp)
}

func renderSandboxRuntimeListJSON(out io.Writer, host *sandbox.SandboxHost) error {
	return renderSandboxRuntimeListResponseJSON(out, newSandboxRuntimeListCachedResponse(host))
}

func renderSandboxRuntimeListResponseJSON(out io.Writer, resp SandboxRuntimeListResponse) error {
	if out == nil {
		return nil
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox runtime list: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func renderSandboxRuntimeStatusResponseJSON(out io.Writer, resp SandboxRuntimeStatusResponse) error {
	if out == nil {
		return nil
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox runtime status: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func renderSandboxRuntimeList(out io.Writer, host *sandbox.SandboxHost) error {
	return renderSandboxRuntimeListResponse(out, newSandboxRuntimeListCachedResponse(host))
}

func renderSandboxRuntimeListResponse(out io.Writer, resp SandboxRuntimeListResponse) error {
	if out == nil {
		return nil
	}

	hostName := sandboxHostDisplayValue(resp.Host.Name, resp.Host.ID)
	if hostName == "" {
		hostName = "unknown"
	}
	sourceMode := sandboxHostDisplayValue(resp.Source.Mode, SandboxRuntimeSourceCached)
	if _, err := fmt.Fprintf(out, "Sandbox runtimes for %s (%s)\n", hostName, sourceMode); err != nil {
		return err
	}
	type runtimeLine struct {
		label string
		value string
	}
	lines := []runtimeLine{
		{"Source", sandboxHostDisplayValue(resp.Source.Summary, sourceMode)},
		{"Host ID", sandboxHostDisplayValue(resp.Host.ID, "-")},
		{"Host kind", sandboxHostDisplayValue(resp.Host.Kind, "unknown")},
		{"Endpoint", sandboxHostDisplayValue(resp.Host.Endpoint.Summary, "unknown")},
		{"Capacity", sandboxHostDisplayValue(resp.Capacity.Summary, "unknown")},
		{"Security", sandboxRuntimeSecuritySummaryHuman(resp.Security)},
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

	if len(resp.Runtimes) == 0 {
		noMetadataMessage := "No runtime metadata is available."
		if resp.Source.Mode == SandboxRuntimeSourceCached {
			noMetadataMessage = "No cached runtime metadata is available."
		}
		_, err := fmt.Fprintln(out, noMetadataMessage)
		return err
	}
	if _, err := fmt.Fprintln(out, "Runtimes (sorted by runtime id):"); err != nil {
		return err
	}
	runtimeTable := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(runtimeTable, "ID\tHOST KIND\tISOLATION\tOPERATIONS"); err != nil {
		return err
	}
	for _, runtimeEntry := range resp.Runtimes {
		hostKind := sandboxRuntimeStringPtrValue(runtimeEntry.HostKind, "unknown")
		isolationLevel := sandboxRuntimeStringPtrValue(runtimeEntry.IsolationLevel, "unknown")
		operations := sandboxRuntimeHumanList(runtimeEntry.SupportedOperations)
		if operations == "" {
			operations = "unknown"
		}
		if _, err := fmt.Fprintf(runtimeTable, "%s\t%s\t%s\t%s\n", runtimeEntry.ID, hostKind, isolationLevel, operations); err != nil {
			return err
		}
	}
	return runtimeTable.Flush()
}

func renderSandboxRuntimeStatusResponse(out io.Writer, resp SandboxRuntimeStatusResponse) error {
	if out == nil {
		return nil
	}

	hostName := sandboxHostDisplayValue(resp.Host.Name, resp.Host.ID)
	if hostName == "" {
		hostName = "unknown"
	}
	sourceMode := sandboxHostDisplayValue(resp.Source.Mode, SandboxRuntimeSourceCached)
	if _, err := fmt.Fprintf(out, "Sandbox runtime %s on %s (%s)\n", sandboxHostDisplayValue(resp.Runtime.ID, "unknown"), hostName, sourceMode); err != nil {
		return err
	}

	readiness := sandboxHostDisplayValue(resp.Readiness.Status, SandboxRuntimeReadinessUnknown)
	if summary := strings.TrimSpace(resp.Readiness.Summary); summary != "" {
		readiness += " (" + summary + ")"
	}
	operations := sandboxRuntimeHumanList(resp.SupportedOperations)
	if operations == "" {
		operations = "unknown"
	}

	lines := []struct {
		label string
		value string
	}{
		{"Source", sandboxHostDisplayValue(resp.Source.Summary, sourceMode)},
		{"Host ID", sandboxHostDisplayValue(resp.Host.ID, "-")},
		{"Host kind", sandboxHostDisplayValue(resp.Host.Kind, "unknown")},
		{"Endpoint", sandboxHostDisplayValue(resp.Host.Endpoint.Summary, "unknown")},
		{"Runtime ID", sandboxHostDisplayValue(resp.Runtime.ID, "unknown")},
		{"Runtime host kind", sandboxRuntimeStringPtrValue(resp.Runtime.HostKind, "unknown")},
		{"Runtime isolation", sandboxRuntimeStringPtrValue(resp.Runtime.IsolationLevel, "unknown")},
		{"Readiness", readiness},
		{"Supported operations", operations},
		{"Capacity", sandboxHostDisplayValue(resp.Capacity.Summary, "unknown")},
		{"Security", sandboxRuntimeSecuritySummaryHuman(resp.Security)},
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, line := range lines {
		if _, err := fmt.Fprintf(tw, "%s:\t%s\n", line.label, line.value); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func sandboxRuntimeHostSupportsRuntime(host *sandbox.SandboxHost, runtimeID string) bool {
	runtimeID = strings.TrimSpace(runtimeID)
	if host == nil || runtimeID == "" {
		return false
	}
	for _, cachedRuntimeID := range sortedUniqueStrings(host.SupportedRuntimes) {
		if cachedRuntimeID == runtimeID {
			return true
		}
	}
	return false
}

func querySandboxRuntimeListLiveMetadata(ctx context.Context, host *sandbox.SandboxHost, newWorkerClient func(string) (sandboxHostWorkerClient, error)) (*sandboxworker.Status, *sandboxworker.Capabilities, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if host == nil {
		return nil, nil, fmt.Errorf("sandbox host is required")
	}
	if strings.TrimSpace(host.Kind) != sandbox.SandboxHostKindWorker {
		return nil, nil, fmt.Errorf("live sandbox runtime list is only supported for worker hosts")
	}
	socketPath, err := sandboxHostLocalWorkerSocketPath(host.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	if newWorkerClient == nil {
		newWorkerClient = newSandboxHostWorkerClient
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

	if err := validateSandboxHostWorkerPayloads(host.ID, status, capabilities); err != nil {
		return nil, nil, err
	}
	return status, capabilities, nil
}

func sandboxRuntimeSecuritySummaryHuman(security SandboxRuntimeSecuritySummary) string {
	parts := make([]string, 0, 8)
	if networkPolicy := sandboxRuntimeStringPtrValue(security.Requested.NetworkPolicy, ""); networkPolicy != "" {
		parts = append(parts, "requested network "+networkPolicy)
	}
	if networkPolicy := sandboxRuntimeStringPtrValue(security.Enforced.NetworkPolicy, ""); networkPolicy != "" {
		enforced := "enforced network " + networkPolicy
		if mode := sandboxRuntimeStringPtrValue(security.Enforced.NetworkEnforcement, ""); mode != "" {
			enforced += " via " + mode
		}
		parts = append(parts, enforced)
	} else if mode := sandboxRuntimeStringPtrValue(security.Enforced.NetworkEnforcement, ""); mode != "" {
		parts = append(parts, "network enforcement "+mode)
	}
	if requested := sandboxRuntimeHumanList(security.Requested.CredentialModes); requested != "" {
		parts = append(parts, "requested credentials "+requested)
	}
	if active := sandboxRuntimeHumanList(security.Enforced.CredentialModes); active != "" {
		parts = append(parts, "active credentials "+active)
	}
	if isolationLevel := sandboxRuntimeStringPtrValue(security.Requested.IsolationLevel, ""); isolationLevel != "" {
		parts = append(parts, "requested isolation "+isolationLevel)
	}
	if isolationLevel := sandboxRuntimeStringPtrValue(security.Enforced.IsolationLevel, ""); isolationLevel != "" {
		parts = append(parts, "enforced isolation "+isolationLevel)
	}
	if security.Requested.CredentialProxyMode != nil {
		parts = append(parts, fmt.Sprintf("requested credential proxy %t", *security.Requested.CredentialProxyMode))
	}
	if security.Enforced.CredentialProxyMode != nil {
		parts = append(parts, fmt.Sprintf("enforced credential proxy %t", *security.Enforced.CredentialProxyMode))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "; ")
}

func sandboxRuntimeStringPtrValue(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return sandboxHostDisplayValue(*value, fallback)
}

func sandboxRuntimeHumanList(values []string) string {
	values = sortedUniqueStrings(values)
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}
