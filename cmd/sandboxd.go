package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

const sandboxdDefaultSocketName = "hal-sandboxd.sock"

type sandboxdServer interface {
	ListenAndServe(context.Context) error
}

type sandboxdDeps struct {
	newService                      func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error)
	newServer                       func(sandboxworker.ServerOptions) (sandboxdServer, error)
	rootlessPodmanAvailable         func(context.Context, string) error
	newRootlessPodmanDriver         func(string) sandboxruntime.Driver
	newMicroVMDriver                func(sandboxdMicroVMConfig) (sandboxruntime.Driver, error)
	validateMicroVMConfig           func(sandboxdMicroVMConfig) error
	microVMGuestReadinessConfigured bool
	workerID                        func() string
}

type sandboxdFlags struct {
	socketPath    string
	workerID      string
	drivers       []string
	podmanPath    string
	microVM       sandboxdMicroVMFlags
	maxConcurrent int
	json          bool
}

type sandboxdMicroVMFlags struct {
	firecrackerExecutablePath  string
	kernelImagePath            string
	rootfsImagePath            string
	initrdPath                 string
	jailerPath                 string
	stateDir                   string
	cpuCount                   int
	memoryMiB                  int
	diskSizeMiB                int
	guestWorkDir               string
	bootAcceptanceTimeout      time.Duration
	bootAcceptancePollInterval time.Duration
	guestReadinessTimeout      time.Duration
	guestReadinessPollInterval time.Duration
	guestAgentEndpoint         string
}

type sandboxdMicroVMConfig struct {
	Config                        microvm.Config
	StateDir                      string
	BootAcceptanceTimeout         time.Duration
	BootAcceptancePollInterval    time.Duration
	GuestReadinessTimeout         time.Duration
	GuestReadinessPollInterval    time.Duration
	GuestReadinessProbeConfigured bool
	GuestAgentEndpoint            string
}

type sandboxdRequest struct {
	SocketPath    string
	WorkerID      string
	Drivers       []string
	PodmanPath    string
	MicroVM       sandboxdMicroVMConfig
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
	registerSandboxdMicroVMFlags(cmd, &flags, deps)
	cmd.Flags().IntVar(&flags.maxConcurrent, "max-concurrent", flags.maxConcurrent, "maximum concurrent sandboxes reported by daemon capacity")
	cmd.Flags().BoolVar(&flags.json, "json", flags.json, "Output machine-readable daemon startup status")
	return cmd
}

func defaultSandboxdFlags() sandboxdFlags {
	return sandboxdFlags{
		socketPath:    defaultSandboxdSocketPath(),
		drivers:       []string{sandboxruntime.DriverRootlessPodman},
		podmanPath:    rootlesspodman.DefaultPodmanExecutable,
		microVM:       defaultSandboxdMicroVMFlags(),
		maxConcurrent: 1,
	}
}

func defaultSandboxdMicroVMFlags() sandboxdMicroVMFlags {
	defaultConfig := microvm.DefaultConfig()
	return sandboxdMicroVMFlags{
		cpuCount:     defaultConfig.CPUCount,
		memoryMiB:    defaultConfig.MemoryMiB,
		diskSizeMiB:  defaultConfig.DiskSizeMiB,
		guestWorkDir: defaultConfig.GuestWorkDir,
	}
}

func registerSandboxdMicroVMFlags(cmd *cobra.Command, flags *sandboxdFlags, deps sandboxdDeps) {
	cmd.Flags().StringVar(&flags.microVM.firecrackerExecutablePath, "firecracker-executable", flags.microVM.firecrackerExecutablePath, "Firecracker executable path for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.kernelImagePath, "firecracker-kernel", flags.microVM.kernelImagePath, "kernel image path for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.rootfsImagePath, "firecracker-rootfs", flags.microVM.rootfsImagePath, "rootfs image path for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.initrdPath, "firecracker-initrd", flags.microVM.initrdPath, "optional initrd image path for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.jailerPath, "firecracker-jailer", flags.microVM.jailerPath, "optional Firecracker jailer executable path for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.stateDir, "firecracker-state-dir", flags.microVM.stateDir, "state directory for the microvm driver")
	cmd.Flags().IntVar(&flags.microVM.cpuCount, "microvm-cpu-count", flags.microVM.cpuCount, "CPU count for the microvm driver")
	cmd.Flags().IntVar(&flags.microVM.memoryMiB, "microvm-memory-mib", flags.microVM.memoryMiB, "memory size in MiB for the microvm driver")
	cmd.Flags().IntVar(&flags.microVM.diskSizeMiB, "microvm-disk-mib", flags.microVM.diskSizeMiB, "disk size in MiB for the microvm driver")
	cmd.Flags().StringVar(&flags.microVM.guestWorkDir, "microvm-guest-workdir", flags.microVM.guestWorkDir, "guest workdir for the microvm driver")
	cmd.Flags().DurationVar(&flags.microVM.bootAcceptanceTimeout, "firecracker-boot-timeout", flags.microVM.bootAcceptanceTimeout, "host-side Firecracker boot acceptance timeout; 0 uses the live driver default")
	cmd.Flags().DurationVar(&flags.microVM.bootAcceptancePollInterval, "firecracker-boot-poll-interval", flags.microVM.bootAcceptancePollInterval, "host-side Firecracker boot acceptance poll interval; 0 uses the live driver default")
	cmd.Flags().StringVar(&flags.microVM.guestAgentEndpoint, "firecracker-guest-agent-endpoint", flags.microVM.guestAgentEndpoint, "optional local Unix socket endpoint for Firecracker guest-agent readiness, exec, and copy transport")
	if deps.microVMGuestReadinessConfigured {
		cmd.Flags().DurationVar(&flags.microVM.guestReadinessTimeout, "firecracker-guest-readiness-timeout", flags.microVM.guestReadinessTimeout, "guest readiness timeout for configured microvm readiness probes; 0 uses the live driver default")
		cmd.Flags().DurationVar(&flags.microVM.guestReadinessPollInterval, "firecracker-guest-readiness-poll-interval", flags.microVM.guestReadinessPollInterval, "guest readiness poll interval for configured microvm readiness probes; 0 uses the live driver default")
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
		newMicroVMDriver:        defaultSandboxdMicroVMDriver,
		validateMicroVMConfig:   defaultSandboxdMicroVMConfigValidator,
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
		MicroVM:       sandboxdMicroVMConfigFromFlags(flags.microVM, deps),
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
		req.MicroVM, err = sandboxdMicroVMConfigFromCommand(cmd, flags.microVM, deps)
		if err != nil {
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
	req.MicroVM = sanitizeSandboxdMicroVMConfig(req.MicroVM)

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
	if sandboxdDriverRequested(req.Drivers, sandboxruntime.DriverMicroVM) {
		if missing := sandboxdMissingMicroVMConfigFlags(req.MicroVM); len(missing) > 0 {
			return sandboxdRequest{}, fmt.Errorf("sandboxd --driver microvm requires %s", sandboxdJoinFlagList(missing))
		}
		resolvedMicroVM, err := resolveSandboxdMicroVMLaunchAssets(req.MicroVM)
		if err != nil {
			return sandboxdRequest{}, err
		}
		req.MicroVM = resolvedMicroVM
		if err := validateSandboxdMicroVMConfig(req.MicroVM); err != nil {
			return sandboxdRequest{}, err
		}
		validateLiveConfig := deps.validateMicroVMConfig
		if validateLiveConfig == nil {
			validateLiveConfig = defaultSandboxdMicroVMConfigValidator
		}
		if err := validateLiveConfig(req.MicroVM); err != nil {
			return sandboxdRequest{}, err
		}
	}
	for _, driverID := range req.Drivers {
		if !sandboxdDriverSupportedByDeps(driverID, deps) {
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
	serviceOptions := sandboxworker.ServiceOptions{
		WorkerID:   req.WorkerID,
		HostKind:   sandboxworker.HostKindLocal,
		SocketPath: req.SocketPath,
		Registry:   registry,
		Capacity: sandboxworker.WorkerCapacity{
			MaxConcurrentSandboxes: req.MaxConcurrent,
		},
		RuntimeDrivers: sandboxdRuntimeDriverDescriptors(req),
	}
	service, err := deps.newService(serviceOptions)
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
	if deps.validateMicroVMConfig == nil {
		deps.validateMicroVMConfig = defaults.validateMicroVMConfig
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
		case sandboxruntime.DriverMicroVM:
			if seen[driverID] {
				return nil, nil, fmt.Errorf("sandboxd driver %q is registered more than once", driverID)
			}
			if deps.newMicroVMDriver == nil {
				return nil, nil, fmt.Errorf("sandboxd driver %q is unsupported", driverID)
			}
			if err := validateSandboxdMicroVMConfig(req.MicroVM); err != nil {
				return nil, nil, err
			}
			if deps.validateMicroVMConfig != nil {
				if err := deps.validateMicroVMConfig(req.MicroVM); err != nil {
					return nil, nil, err
				}
			}
			driver, err := deps.newMicroVMDriver(req.MicroVM)
			if err != nil {
				return nil, nil, fmt.Errorf("create sandboxd driver %q: %w", driverID, err)
			}
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

func sandboxdDriverSupportedByDeps(driverID string, deps sandboxdDeps) bool {
	switch strings.TrimSpace(driverID) {
	case sandboxruntime.DriverRootlessPodman:
		return true
	case sandboxruntime.DriverMicroVM:
		return deps.newMicroVMDriver != nil
	default:
		return false
	}
}

func sandboxdMicroVMConfigFromCommand(cmd *cobra.Command, fallback sandboxdMicroVMFlags, deps sandboxdDeps) (sandboxdMicroVMConfig, error) {
	flags := fallback
	var err error
	if flags.firecrackerExecutablePath, err = cmd.Flags().GetString("firecracker-executable"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.kernelImagePath, err = cmd.Flags().GetString("firecracker-kernel"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.rootfsImagePath, err = cmd.Flags().GetString("firecracker-rootfs"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.initrdPath, err = cmd.Flags().GetString("firecracker-initrd"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.jailerPath, err = cmd.Flags().GetString("firecracker-jailer"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.stateDir, err = cmd.Flags().GetString("firecracker-state-dir"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.cpuCount, err = cmd.Flags().GetInt("microvm-cpu-count"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.memoryMiB, err = cmd.Flags().GetInt("microvm-memory-mib"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.diskSizeMiB, err = cmd.Flags().GetInt("microvm-disk-mib"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.guestWorkDir, err = cmd.Flags().GetString("microvm-guest-workdir"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.bootAcceptanceTimeout, err = cmd.Flags().GetDuration("firecracker-boot-timeout"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.bootAcceptancePollInterval, err = cmd.Flags().GetDuration("firecracker-boot-poll-interval"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if flags.guestAgentEndpoint, err = cmd.Flags().GetString("firecracker-guest-agent-endpoint"); err != nil {
		return sandboxdMicroVMConfig{}, err
	}
	if cmd.Flags().Lookup("firecracker-guest-readiness-timeout") != nil {
		if flags.guestReadinessTimeout, err = cmd.Flags().GetDuration("firecracker-guest-readiness-timeout"); err != nil {
			return sandboxdMicroVMConfig{}, err
		}
	}
	if cmd.Flags().Lookup("firecracker-guest-readiness-poll-interval") != nil {
		if flags.guestReadinessPollInterval, err = cmd.Flags().GetDuration("firecracker-guest-readiness-poll-interval"); err != nil {
			return sandboxdMicroVMConfig{}, err
		}
	}
	return sandboxdMicroVMConfigFromFlags(flags, deps), nil
}

func sandboxdMicroVMConfigFromFlags(flags sandboxdMicroVMFlags, deps sandboxdDeps) sandboxdMicroVMConfig {
	return sandboxdMicroVMConfig{
		Config: microvm.Config{
			HypervisorPath:  flags.firecrackerExecutablePath,
			KernelImagePath: flags.kernelImagePath,
			RootfsPath:      flags.rootfsImagePath,
			InitrdPath:      flags.initrdPath,
			JailerPath:      flags.jailerPath,
			CPUCount:        flags.cpuCount,
			MemoryMiB:       flags.memoryMiB,
			DiskSizeMiB:     flags.diskSizeMiB,
			GuestWorkDir:    flags.guestWorkDir,
			NetworkMode:     microvm.DefaultNetworkMode,
		},
		StateDir:                      flags.stateDir,
		BootAcceptanceTimeout:         flags.bootAcceptanceTimeout,
		BootAcceptancePollInterval:    flags.bootAcceptancePollInterval,
		GuestReadinessTimeout:         flags.guestReadinessTimeout,
		GuestReadinessPollInterval:    flags.guestReadinessPollInterval,
		GuestReadinessProbeConfigured: deps.microVMGuestReadinessConfigured,
		GuestAgentEndpoint:            flags.guestAgentEndpoint,
	}
}

func sanitizeSandboxdMicroVMConfig(config sandboxdMicroVMConfig) sandboxdMicroVMConfig {
	config.Config.HypervisorPath = strings.TrimSpace(config.Config.HypervisorPath)
	config.Config.KernelImagePath = strings.TrimSpace(config.Config.KernelImagePath)
	config.Config.RootfsPath = strings.TrimSpace(config.Config.RootfsPath)
	config.Config.InitrdPath = strings.TrimSpace(config.Config.InitrdPath)
	config.Config.JailerPath = strings.TrimSpace(config.Config.JailerPath)
	config.Config.GuestWorkDir = strings.TrimSpace(config.Config.GuestWorkDir)
	config.Config.NetworkMode = microvm.NetworkMode(strings.TrimSpace(string(config.Config.NetworkMode)))
	if config.Config.NetworkMode == "" {
		config.Config.NetworkMode = microvm.DefaultNetworkMode
	}
	config.StateDir = strings.TrimSpace(config.StateDir)
	if config.StateDir != "" {
		config.StateDir = filepath.Clean(config.StateDir)
	}
	config.GuestAgentEndpoint = strings.TrimSpace(config.GuestAgentEndpoint)
	return config
}

func validateSandboxdMicroVMConfig(config sandboxdMicroVMConfig) error {
	missing := sandboxdMissingMicroVMConfigFlags(config)
	if len(missing) > 0 {
		return fmt.Errorf("sandboxd --driver microvm requires %s", sandboxdJoinFlagList(missing))
	}
	for _, value := range []struct {
		flag string
		path string
	}{
		{flag: "--firecracker-executable", path: config.Config.HypervisorPath},
		{flag: "--firecracker-jailer", path: config.Config.JailerPath},
	} {
		if err := validateSandboxdMicroVMPathFlag(value.flag, value.path); err != nil {
			return err
		}
	}
	if config.Config.LaunchDescriptor == nil {
		for _, value := range []struct {
			flag string
			path string
		}{
			{flag: "--firecracker-kernel", path: config.Config.KernelImagePath},
			{flag: "--firecracker-rootfs", path: config.Config.RootfsPath},
			{flag: "--firecracker-initrd", path: config.Config.InitrdPath},
		} {
			if err := validateSandboxdMicroVMPathFlag(value.flag, value.path); err != nil {
				return err
			}
		}
	}
	if sandboxdPathHasControl(config.StateDir) {
		return fmt.Errorf("sandboxd --firecracker-state-dir is invalid")
	}
	if sandboxdPathHasUnsafeDetail(config.StateDir) {
		return fmt.Errorf("sandboxd --firecracker-state-dir is invalid")
	}
	if !filepath.IsAbs(config.StateDir) {
		return fmt.Errorf("sandboxd --firecracker-state-dir must be an absolute path")
	}
	if sandboxdFilesystemRoot(config.StateDir) {
		return fmt.Errorf("sandboxd --firecracker-state-dir must not be the filesystem root")
	}
	if config.BootAcceptanceTimeout < 0 {
		return fmt.Errorf("sandboxd --firecracker-boot-timeout must be greater than or equal to zero")
	}
	if config.BootAcceptancePollInterval < 0 {
		return fmt.Errorf("sandboxd --firecracker-boot-poll-interval must be greater than or equal to zero")
	}
	if config.GuestReadinessProbeConfigured {
		if config.GuestReadinessTimeout < 0 {
			return fmt.Errorf("sandboxd --firecracker-guest-readiness-timeout must be greater than or equal to zero")
		}
		if config.GuestReadinessPollInterval < 0 {
			return fmt.Errorf("sandboxd --firecracker-guest-readiness-poll-interval must be greater than or equal to zero")
		}
	}
	if err := microvm.ValidateConfig(config.Config); err != nil {
		return fmt.Errorf("sandboxd --driver microvm config is invalid: %w", err)
	}
	return nil
}

func resolveSandboxdMicroVMLaunchAssets(config sandboxdMicroVMConfig) (sandboxdMicroVMConfig, error) {
	request := localresolver.ResolveRequest{
		ID:                 "sandboxd-firecracker-launch",
		Labels:             []assets.SafeLabel{"sandboxd", "firecracker"},
		LockedAtUnixMillis: time.Now().UTC().UnixMilli(),
		Assets: []localresolver.AssetRequest{
			{
				ID:   "kernel",
				Role: assets.AssetRoleKernel,
				Kind: assets.AssetKindKernelImage,
				Path: config.Config.KernelImagePath,
			},
			{
				ID:   "rootfs",
				Role: assets.AssetRoleRootfs,
				Kind: assets.AssetKindRootfsImage,
				Path: config.Config.RootfsPath,
			},
		},
	}
	if strings.TrimSpace(config.Config.InitrdPath) != "" {
		request.Assets = append(request.Assets, localresolver.AssetRequest{
			ID:   "initrd",
			Role: assets.AssetRoleInitrd,
			Kind: assets.AssetKindInitrdImage,
			Path: config.Config.InitrdPath,
		})
	}

	descriptor, err := localresolver.Resolve(request)
	if err != nil {
		return sandboxdMicroVMConfig{}, sandboxdMicroVMLaunchAssetResolveError(err)
	}
	config.Config.LaunchDescriptor = &descriptor
	return config, nil
}

func sandboxdMicroVMLaunchAssetResolveError(err error) error {
	var resolverErr *localresolver.Error
	if errors.As(err, &resolverErr) {
		if flag := sandboxdMicroVMAssetFlag(resolverErr.Role); flag != "" {
			return fmt.Errorf("sandboxd %s is invalid: %w", flag, err)
		}
	}
	return fmt.Errorf("sandboxd microvm launch assets are invalid: %w", err)
}

func sandboxdMicroVMAssetFlag(role assets.AssetRole) string {
	switch role {
	case assets.AssetRoleKernel:
		return "--firecracker-kernel"
	case assets.AssetRoleRootfs:
		return "--firecracker-rootfs"
	case assets.AssetRoleInitrd:
		return "--firecracker-initrd"
	default:
		return ""
	}
}

func sandboxdRuntimeDriverDescriptors(req sandboxdRequest) map[string]sandboxworker.RuntimeDriver {
	if !sandboxdDriverRequested(req.Drivers, sandboxruntime.DriverMicroVM) || strings.TrimSpace(req.MicroVM.GuestAgentEndpoint) == "" {
		return nil
	}
	return map[string]sandboxworker.RuntimeDriver{
		sandboxruntime.DriverMicroVM: sandboxdMicroVMRuntimeDriverDescriptor(sandboxdMicroVMOperationsWithGuestAgent()),
	}
}

func sandboxdMicroVMRuntimeDriverDescriptor(operations []string) sandboxworker.RuntimeDriver {
	return sandboxworker.RuntimeDriver{
		ID:             sandboxruntime.DriverMicroVM,
		HostKind:       sandboxworker.HostKindLocal,
		IsolationLevel: sandboxworker.IsolationLevelVM,
		Operations:     cloneSandboxdStringSlice(operations),
		Security: sandboxworker.SecurityPolicy{
			Requested: sandboxworker.SecurityControls{
				NetworkPolicy:       sandboxworker.NetworkPolicyBestEffort,
				NetworkEnforcement:  sandboxworker.NetworkEnforcementNone,
				IsolationLevel:      sandboxworker.IsolationLevelVM,
				CredentialProxyMode: false,
			},
			Enforced: sandboxworker.SecurityControls{
				NetworkPolicy:       sandboxworker.NetworkPolicyBestEffort,
				NetworkEnforcement:  sandboxworker.NetworkEnforcementNone,
				IsolationLevel:      sandboxworker.IsolationLevelVM,
				CredentialProxyMode: false,
			},
		},
	}
}

func sandboxdMicroVMOperationsWithGuestAgent() []string {
	return []string{
		sandboxworker.OperationCreate,
		sandboxworker.OperationStart,
		sandboxworker.OperationStop,
		sandboxworker.OperationDelete,
		sandboxworker.OperationInspect,
		sandboxworker.OperationExec,
		sandboxworker.OperationCopyIn,
		sandboxworker.OperationCopyOut,
	}
}

func validateSandboxdMicroVMPathFlag(flag, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if sandboxdPathHasControl(path) || sandboxdPathHasUnsafeDetail(path) {
		return fmt.Errorf("sandboxd %s is invalid", flag)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("sandboxd %s must be an absolute path", flag)
	}
	if sandboxdFilesystemRoot(path) {
		return fmt.Errorf("sandboxd %s must not be the filesystem root", flag)
	}
	return nil
}

func sandboxdMissingMicroVMConfigFlags(config sandboxdMicroVMConfig) []string {
	var missing []string
	if strings.TrimSpace(config.Config.HypervisorPath) == "" {
		missing = append(missing, "--firecracker-executable")
	}
	if strings.TrimSpace(config.Config.KernelImagePath) == "" {
		missing = append(missing, "--firecracker-kernel")
	}
	if strings.TrimSpace(config.Config.RootfsPath) == "" {
		missing = append(missing, "--firecracker-rootfs")
	}
	if strings.TrimSpace(config.StateDir) == "" {
		missing = append(missing, "--firecracker-state-dir")
	}
	return missing
}

func sandboxdJoinFlagList(flags []string) string {
	switch len(flags) {
	case 0:
		return ""
	case 1:
		return flags[0]
	case 2:
		return flags[0] + " and " + flags[1]
	default:
		return strings.Join(flags[:len(flags)-1], ", ") + ", and " + flags[len(flags)-1]
	}
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
