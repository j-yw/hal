package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

const sandboxdDefaultSocketName = "hal-sandboxd.sock"

type sandboxdServer interface {
	ListenAndServe(context.Context) error
}

type sandboxdDeps struct {
	newService              func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error)
	newServer               func(sandboxworker.ServerOptions) (sandboxdServer, error)
	rootlessPodmanAvailable func(context.Context, string) error
	newRootlessPodmanDriver func(string) sandboxruntime.Driver
	workerID                func() string
}

type sandboxdFlags struct {
	socketPath    string
	workerID      string
	drivers       []string
	podmanPath    string
	maxConcurrent int
	json          bool
}

type sandboxdRequest struct {
	SocketPath    string
	WorkerID      string
	Drivers       []string
	PodmanPath    string
	MaxConcurrent int
	JSON          bool
}

type sandboxdStartedOutput struct {
	Status     string   `json:"status"`
	WorkerID   string   `json:"workerId"`
	SocketPath string   `json:"socketPath"`
	Drivers    []string `json:"drivers"`
}

var sandboxdCmd = newSandboxdCommand(defaultSandboxdDeps())

func init() {
	rootCmd.AddCommand(sandboxdCmd)
}

func newSandboxdCommand(deps sandboxdDeps) *cobra.Command {
	flags := defaultSandboxdFlags()
	cmd := &cobra.Command{
		Use:   "sandboxd",
		Short: "Start the local sandbox worker daemon",
		Args:  noArgsValidation(),
		Long: `Start the local sandbox worker daemon.

The daemon serves the sandboxworker-v1 protocol over a local Unix socket. The
command only parses flags, wires worker service/server dependencies, registers
selected runtime drivers, and reports startup or serve errors. Existing
hal sandbox subcommands continue to manage durable sandbox records separately.`,
		Example: `  hal sandboxd
  hal sandboxd --socket /tmp/hal-sandboxd.sock
  hal sandboxd --driver rootless_podman --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxdCommand(cmd, args, flags, deps)
		},
	}
	cmd.Flags().StringVar(&flags.socketPath, "socket", flags.socketPath, "Unix socket path for the sandbox worker daemon")
	cmd.Flags().StringVar(&flags.workerID, "worker-id", flags.workerID, "worker identifier to report in daemon status")
	cmd.Flags().StringSliceVar(&flags.drivers, "driver", flags.drivers, "runtime driver to register with the worker daemon")
	cmd.Flags().StringVar(&flags.podmanPath, "podman", flags.podmanPath, "podman executable for the rootless_podman driver")
	cmd.Flags().IntVar(&flags.maxConcurrent, "max-concurrent", flags.maxConcurrent, "maximum concurrent sandboxes reported by daemon capacity")
	cmd.Flags().BoolVar(&flags.json, "json", flags.json, "Output machine-readable daemon startup status")
	return cmd
}

func defaultSandboxdFlags() sandboxdFlags {
	return sandboxdFlags{
		socketPath:    defaultSandboxdSocketPath(),
		drivers:       []string{sandboxruntime.DriverRootlessPodman},
		podmanPath:    rootlesspodman.DefaultPodmanExecutable,
		maxConcurrent: 1,
	}
}

func defaultSandboxdDeps() sandboxdDeps {
	return sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			return sandboxworker.NewService(options)
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxworker.NewServer(options)
		},
		rootlessPodmanAvailable: defaultSandboxdRootlessPodmanAvailable,
		newRootlessPodmanDriver: defaultSandboxdRootlessPodmanDriver,
		workerID:                defaultSandboxdWorkerID,
	}
}

func defaultSandboxdRootlessPodmanAvailable(ctx context.Context, podmanPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	podmanPath = strings.TrimSpace(podmanPath)
	if podmanPath == "" {
		podmanPath = rootlesspodman.DefaultPodmanExecutable
	}
	_, err := exec.LookPath(podmanPath)
	return err
}

func defaultSandboxdRootlessPodmanDriver(podmanPath string) sandboxruntime.Driver {
	runner := rootlesspodman.DefaultCommandRunner{}
	return rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		ExecRunner:      runner,
		CopyRunner:      runner,
		PodmanPath:      podmanPath,
	})
}

func runSandboxdCommand(cmd *cobra.Command, _ []string, flags sandboxdFlags, deps sandboxdDeps) error {
	req, err := sandboxdRequestFromCommand(cmd, flags, deps)
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runSandboxdWithDeps(ctx, req, out, deps); err != nil {
		return renderSandboxdCobraError(cmd, err)
	}
	return nil
}

func sandboxdRequestFromCommand(cmd *cobra.Command, flags sandboxdFlags, deps sandboxdDeps) (sandboxdRequest, error) {
	req := sandboxdRequest{
		SocketPath:    flags.socketPath,
		WorkerID:      flags.workerID,
		Drivers:       cloneSandboxdStringSlice(flags.drivers),
		PodmanPath:    flags.podmanPath,
		MaxConcurrent: flags.maxConcurrent,
		JSON:          flags.json,
	}
	if cmd != nil {
		var err error
		if req.SocketPath, err = cmd.Flags().GetString("socket"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.WorkerID, err = cmd.Flags().GetString("worker-id"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.Drivers, err = cmd.Flags().GetStringSlice("driver"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.PodmanPath, err = cmd.Flags().GetString("podman"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.MaxConcurrent, err = cmd.Flags().GetInt("max-concurrent"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.JSON, err = cmd.Flags().GetBool("json"); err != nil {
			return sandboxdRequest{}, err
		}
	}

	req.SocketPath = strings.TrimSpace(req.SocketPath)
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	req.PodmanPath = strings.TrimSpace(req.PodmanPath)
	req.Drivers = normalizedSandboxdDrivers(req.Drivers)

	if req.SocketPath == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --socket is required")
	}
	if req.WorkerID == "" {
		deps = normalizeSandboxdDeps(deps)
		req.WorkerID = strings.TrimSpace(deps.workerID())
	}
	if req.WorkerID == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd worker ID is required")
	}
	if len(req.Drivers) == 0 {
		return sandboxdRequest{}, fmt.Errorf("sandboxd requires at least one --driver")
	}
	for _, driverID := range req.Drivers {
		if driverID != sandboxruntime.DriverRootlessPodman {
			return sandboxdRequest{}, fmt.Errorf("sandboxd driver %q is unsupported", driverID)
		}
	}
	if req.MaxConcurrent <= 0 {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --max-concurrent must be greater than zero")
	}
	return req, nil
}

func runSandboxdWithDeps(ctx context.Context, req sandboxdRequest, out io.Writer, deps sandboxdDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	deps = normalizeSandboxdDeps(deps)

	registry, driverIDs, err := sandboxdDriverRegistry(ctx, req, deps)
	if err != nil {
		return err
	}
	service, err := deps.newService(sandboxworker.ServiceOptions{
		WorkerID:   req.WorkerID,
		HostKind:   sandboxworker.HostKindLocal,
		SocketPath: req.SocketPath,
		Registry:   registry,
		Capacity: sandboxworker.WorkerCapacity{
			MaxConcurrentSandboxes: req.MaxConcurrent,
		},
	})
	if err != nil {
		return fmt.Errorf("create sandboxd worker service: %w", err)
	}

	server, err := deps.newServer(sandboxworker.ServerOptions{
		SocketPath: req.SocketPath,
		Handler:    service,
	})
	if err != nil {
		return fmt.Errorf("create sandboxd worker server: %w", err)
	}

	if err := writeSandboxdStarted(out, req, driverIDs); err != nil {
		return err
	}
	return server.ListenAndServe(ctx)
}

func normalizeSandboxdDeps(deps sandboxdDeps) sandboxdDeps {
	defaults := defaultSandboxdDeps()
	if deps.newService == nil {
		deps.newService = defaults.newService
	}
	if deps.newServer == nil {
		deps.newServer = defaults.newServer
	}
	if deps.rootlessPodmanAvailable == nil {
		deps.rootlessPodmanAvailable = defaults.rootlessPodmanAvailable
	}
	if deps.newRootlessPodmanDriver == nil {
		deps.newRootlessPodmanDriver = defaults.newRootlessPodmanDriver
	}
	if deps.workerID == nil {
		deps.workerID = defaults.workerID
	}
	return deps
}

func sandboxdDriverRegistry(ctx context.Context, req sandboxdRequest, deps sandboxdDeps) (*sandboxworker.DriverRegistry, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	registry := &sandboxworker.DriverRegistry{}
	driverIDs := make([]string, 0, len(req.Drivers))
	seen := map[string]bool{}
	for _, driverID := range req.Drivers {
		switch driverID {
		case sandboxruntime.DriverRootlessPodman:
			if seen[driverID] {
				return nil, nil, fmt.Errorf("sandboxd driver %q is registered more than once", driverID)
			}
			if err := deps.rootlessPodmanAvailable(ctx, req.PodmanPath); err != nil {
				return nil, nil, sandboxdRuntimeUnavailableError{driverID: driverID, err: err}
			}
			driver := deps.newRootlessPodmanDriver(req.PodmanPath)
			if err := registry.Register(driver); err != nil {
				return nil, nil, fmt.Errorf("register sandboxd driver %q: %w", driverID, err)
			}
			seen[driverID] = true
			driverIDs = append(driverIDs, driverID)
		default:
			return nil, nil, fmt.Errorf("sandboxd driver %q is unsupported", driverID)
		}
	}
	return registry, driverIDs, nil
}

type sandboxdRuntimeUnavailableError struct {
	driverID string
	err      error
}

func (e sandboxdRuntimeUnavailableError) Error() string {
	driverID := strings.TrimSpace(e.driverID)
	if driverID == "" {
		driverID = "unknown"
	}
	return fmt.Sprintf("runtime_unavailable: sandboxd driver %q is unavailable; install Podman or pass --podman with an available executable", driverID)
}

func (e sandboxdRuntimeUnavailableError) Unwrap() error {
	return e.err
}

func writeSandboxdStarted(out io.Writer, req sandboxdRequest, driverIDs []string) error {
	if req.JSON {
		return json.NewEncoder(out).Encode(sandboxdStartedOutput{
			Status:     "listening",
			WorkerID:   req.WorkerID,
			SocketPath: req.SocketPath,
			Drivers:    cloneSandboxdStringSlice(driverIDs),
		})
	}
	_, err := fmt.Fprintf(out, "sandboxd listening on %s (worker %s, drivers: %s)\n", req.SocketPath, req.WorkerID, strings.Join(driverIDs, ", "))
	return err
}

func renderSandboxdCobraError(cmd *cobra.Command, err error) error {
	out := io.Writer(os.Stderr)
	if cmd != nil {
		out = cmd.ErrOrStderr()
	}
	if out != nil {
		display.NewDisplay(out).ShowCommandError("Sandboxd failed", []display.ValidationIssue{{Message: err.Error()}}, nil)
	}
	return exitWithCode(cmd, ExitCodeExpectedNonZero, nil)
}

func defaultSandboxdSocketPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), sandboxdDefaultSocketName)
	}
	return filepath.Join("/tmp", sandboxdDefaultSocketName)
}

func defaultSandboxdWorkerID() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "local"
	}
	return fmt.Sprintf("local-%s-%d", safeSandboxdWorkerIDPart(hostname), os.Getpid())
}

func safeSandboxdWorkerIDPart(value string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(value) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "local"
	}
	return b.String()
}

func normalizedSandboxdDrivers(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return normalized
}

func cloneSandboxdStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}
