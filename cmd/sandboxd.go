package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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

type sandboxdServiceCloser interface {
	Close()
}

type sandboxdDeps struct {
	newService              func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error)
	newServer               func(sandboxworker.ServerOptions) (sandboxdServer, error)
	rootlessPodmanAvailable func(context.Context, sandboxdRootlessPodmanConfig) error
	newRootlessPodmanDriver func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver
	workerID                func(string) string
}

type sandboxdFlags struct {
	socketPath                       string
	jobStateDir                      string
	workerID                         string
	drivers                          []string
	podmanPath                       string
	podmanImage                      string
	podmanImageJobExecutionSupported bool
	maxConcurrent                    int
	json                             bool
}

type sandboxdRootlessPodmanConfig struct {
	PodmanPath            string
	Image                 string
	JobExecutionSupported bool
}

type sandboxdRequest struct {
	SocketPath                       string
	JobStateDir                      string
	WorkerID                         string
	Drivers                          []string
	PodmanPath                       string
	PodmanImage                      string
	PodmanImageJobExecutionSupported bool
	MaxConcurrent                    int
	JSON                             bool
	defaultSocket                    bool
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
hal sandbox subcommands continue to manage durable sandbox records separately.

Custom rootless Podman images do not accept daemon-owned jobs unless the operator
passes --image-job-execution-supported to attest the image has the required shell
and process-supervision utilities. This is not image verification and does not
upgrade container isolation, network enforcement, or credential protection.`,
		Example: `  hal sandboxd
  hal sandboxd --socket /tmp/hal-sandboxd.sock
  hal sandboxd --driver rootless_podman --json
  hal sandboxd --driver rootless_podman --image localhost/hal-agent:custom --image-job-execution-supported`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxdCommand(cmd, args, flags, deps)
		},
	}
	cmd.Flags().StringVar(&flags.socketPath, "socket", flags.socketPath, "Unix socket path for the sandbox worker daemon")
	cmd.Flags().StringVar(&flags.jobStateDir, "job-state-dir", flags.jobStateDir, "private state directory for durable worker jobs")
	cmd.Flags().StringVar(&flags.workerID, "worker-id", flags.workerID, "worker identifier to report in daemon status")
	cmd.Flags().StringSliceVar(&flags.drivers, "driver", flags.drivers, "runtime driver to register with the worker daemon")
	cmd.Flags().StringVar(&flags.podmanPath, "podman", flags.podmanPath, "podman executable for the rootless_podman driver")
	cmd.Flags().StringVar(&flags.podmanImage, "image", flags.podmanImage, "container image for the rootless_podman driver")
	cmd.Flags().BoolVar(&flags.podmanImageJobExecutionSupported, "image-job-execution-supported", false, "operator attestation that the rootless_podman image supports daemon-owned jobs; does not verify the image or strengthen security")
	cmd.Flags().IntVar(&flags.maxConcurrent, "max-concurrent", flags.maxConcurrent, "maximum concurrent sandboxes reported by daemon capacity")
	cmd.Flags().BoolVar(&flags.json, "json", flags.json, "Output machine-readable daemon startup status")
	return cmd
}

func defaultSandboxdFlags() sandboxdFlags {
	runtimePaths := defaultSandboxdRuntimePaths()
	return sandboxdFlags{
		socketPath:    runtimePaths.socketPath,
		jobStateDir:   runtimePaths.jobStateDir,
		drivers:       []string{sandboxruntime.DriverRootlessPodman},
		podmanPath:    rootlesspodman.DefaultPodmanExecutable,
		podmanImage:   rootlesspodman.DefaultImage,
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

func defaultSandboxdRootlessPodmanAvailable(ctx context.Context, config sandboxdRootlessPodmanConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	podmanPath := strings.TrimSpace(config.PodmanPath)
	if podmanPath == "" {
		podmanPath = rootlesspodman.DefaultPodmanExecutable
	}
	resolvedPath, err := exec.LookPath(podmanPath)
	if err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, resolvedPath, "info", "--format", "json").Run(); err != nil {
		return fmt.Errorf("podman service is unavailable: %w", err)
	}
	image := strings.TrimSpace(config.Image)
	if image == "" {
		return fmt.Errorf("podman image is required")
	}
	if err := exec.CommandContext(ctx, resolvedPath, "image", "exists", image).Run(); err != nil {
		return fmt.Errorf("podman image is unavailable: %w", err)
	}
	return nil
}

func defaultSandboxdRootlessPodmanDriver(config sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
	runner := rootlesspodman.DefaultCommandRunner{}
	return rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner:       runner,
		ExecRunner:            runner,
		CopyRunner:            runner,
		PodmanPath:            config.PodmanPath,
		Image:                 config.Image,
		JobExecutionSupported: config.JobExecutionSupported,
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
	jobStateDirExplicit := false
	socketExplicit := false
	req := sandboxdRequest{
		SocketPath:                       flags.socketPath,
		JobStateDir:                      flags.jobStateDir,
		WorkerID:                         flags.workerID,
		Drivers:                          cloneSandboxdStringSlice(flags.drivers),
		PodmanPath:                       flags.podmanPath,
		PodmanImage:                      flags.podmanImage,
		PodmanImageJobExecutionSupported: flags.podmanImageJobExecutionSupported,
		MaxConcurrent:                    flags.maxConcurrent,
		JSON:                             flags.json,
		defaultSocket:                    cmd == nil,
	}
	if cmd != nil {
		var err error
		jobStateDirExplicit = cmd.Flags().Changed("job-state-dir")
		socketExplicit = cmd.Flags().Changed("socket")
		req.defaultSocket = !socketExplicit
		if req.SocketPath, err = cmd.Flags().GetString("socket"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.JobStateDir, err = cmd.Flags().GetString("job-state-dir"); err != nil {
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
		if req.PodmanImage, err = cmd.Flags().GetString("image"); err != nil {
			return sandboxdRequest{}, err
		}
		if req.PodmanImageJobExecutionSupported, err = cmd.Flags().GetBool("image-job-execution-supported"); err != nil {
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
	if !jobStateDirExplicit && socketExplicit && req.SocketPath != "" {
		req.JobStateDir = req.SocketPath + ".jobs"
	}
	req.JobStateDir = strings.TrimSpace(req.JobStateDir)
	if req.JobStateDir != "" {
		req.JobStateDir = filepath.Clean(req.JobStateDir)
	}
	req.WorkerID = strings.TrimSpace(req.WorkerID)
	req.PodmanPath = strings.TrimSpace(req.PodmanPath)
	req.PodmanImage = strings.TrimSpace(req.PodmanImage)
	req.Drivers = normalizedSandboxdDrivers(req.Drivers)

	if req.SocketPath == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --socket is required")
	}
	if req.JobStateDir == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --job-state-dir is required")
	}
	if sandboxdPathHasControl(req.JobStateDir) || sandboxdPathHasUnsafeDetail(req.JobStateDir) {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --job-state-dir is invalid")
	}
	if !filepath.IsAbs(req.JobStateDir) {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --job-state-dir must be an absolute path")
	}
	if sandboxdFilesystemRoot(req.JobStateDir) {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --job-state-dir must not be the filesystem root")
	}
	if req.WorkerID == "" {
		deps = normalizeSandboxdDeps(deps)
		req.WorkerID = strings.TrimSpace(deps.workerID(req.JobStateDir))
	}
	if req.WorkerID == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd worker ID is required")
	}
	if len(req.Drivers) == 0 {
		return sandboxdRequest{}, fmt.Errorf("sandboxd requires at least one --driver")
	}
	if sandboxdDriverRequested(req.Drivers, sandboxruntime.DriverRootlessPodman) && req.PodmanImage == "" {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --image is required for --driver rootless_podman")
	}
	if (req.PodmanImageJobExecutionSupported || (cmd != nil && cmd.Flags().Changed("image-job-execution-supported"))) &&
		!sandboxdDriverRequested(req.Drivers, sandboxruntime.DriverRootlessPodman) {
		return sandboxdRequest{}, fmt.Errorf("sandboxd --image-job-execution-supported requires --driver rootless_podman")
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
	if req.defaultSocket {
		if err := prepareSandboxdDefaultRuntime(req.SocketPath); err != nil {
			return err
		}
	}
	serviceOptions := sandboxworker.ServiceOptions{
		WorkerID:    req.WorkerID,
		HostKind:    sandboxworker.HostKindLocal,
		SocketPath:  req.SocketPath,
		Registry:    registry,
		JobContext:  ctx,
		JobStateDir: req.JobStateDir,
		Capacity: sandboxworker.WorkerCapacity{
			MaxConcurrentSandboxes: req.MaxConcurrent,
		},
	}
	service, err := deps.newService(serviceOptions)
	if err != nil {
		if req.defaultSocket {
			return fmt.Errorf("create sandboxd worker service: private runtime state is unavailable")
		}
		return fmt.Errorf("create sandboxd worker service: %w", err)
	}
	if closer, ok := service.(sandboxdServiceCloser); ok {
		defer closer.Close()
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
			config := sandboxdRootlessPodmanConfig{PodmanPath: req.PodmanPath, Image: req.PodmanImage, JobExecutionSupported: req.PodmanImageJobExecutionSupported}
			if err := deps.rootlessPodmanAvailable(ctx, config); err != nil {
				return nil, nil, sandboxdRuntimeUnavailableError{driverID: driverID, err: err}
			}
			driver := deps.newRootlessPodmanDriver(config)
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

func sandboxdDriverRequested(drivers []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, driver := range drivers {
		if strings.TrimSpace(driver) == want {
			return true
		}
	}
	return false
}

func sandboxdPathHasControl(path string) bool {
	for _, r := range path {
		if r == 0 || r == '\n' || r == '\r' || r == '\t' {
			return true
		}
	}
	return false
}

func sandboxdPathHasUnsafeDetail(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "://") || strings.ContainsAny(lower, "?#") {
		return true
	}
	for _, marker := range []string{
		"token=",
		"secret=",
		"password=",
		"credential=",
		"authorization=",
		"bearer ",
		"ghp_",
		"sk-",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sandboxdFilesystemRoot(path string) bool {
	volumeName := filepath.VolumeName(path)
	withoutVolume := strings.TrimPrefix(path, volumeName)
	return withoutVolume == string(filepath.Separator)
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

func defaultSandboxdWorkerID(jobStateDir string) string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "local"
	}
	safeHostname := safeSandboxdWorkerIDPart(hostname)
	if len(safeHostname) > 128 {
		safeHostname = safeHostname[:128]
	}
	stateIdentity := sha256.Sum256([]byte(filepath.Clean(strings.TrimSpace(jobStateDir))))
	return fmt.Sprintf("local-%s-%x", safeHostname, stateIdentity[:8])
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
