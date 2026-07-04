package firecrackerhost

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const liveDriverConstructionOperation = "firecracker_live_driver"

// LiveDriverOptions is the explicit opt-in construction surface for a
// live-start-capable Firecracker microVM driver. Config.HypervisorPath carries
// the Firecracker executable path through the existing microVM config contract.
type LiveDriverOptions struct {
	Config                 microvm.Config
	BaseStateDir           string
	CapabilityDetector     microvm.CapabilityDetector
	NetworkEnforcement     *microvm.NetworkEnforcementPlanning
	NetworkEnforcementLive *microvm.NetworkEnforcementLiveOptions
	HostProcessRunner      HostProcessRunner
	BootAcceptancePoller   BootAcceptancePoller
	GuestReadinessProbe    GuestReadinessProbe
	GuestTransport         firecracker.GuestTransport
	Clock                  Clock
	Sleeper                Sleeper
	BootTimeout            time.Duration
	BootPollInterval       time.Duration
	GuestTimeout           time.Duration
	GuestPollInterval      time.Duration
	CleanupFilesystem      CleanupFilesystem
}

// NewLiveDriver constructs an explicitly live-start-capable Firecracker
// microVM driver. Default command, factory, worker, scheduler, sandboxexec, and
// sandboxd paths should not call this constructor.
func NewLiveDriver(options LiveDriverOptions) (*microvm.Driver, error) {
	config, backendOptions, err := newLiveBackendOptions(options)
	if err != nil {
		return nil, err
	}
	return microvm.NewDriver(microvm.DriverOptions{
		Config:             config,
		CapabilityDetector: options.CapabilityDetector,
		Backend:            firecracker.NewBackend(backendOptions),
		NetworkEnforcement: liveDriverNetworkEnforcement(options),
	}), nil
}

// NewLiveBackendOptions returns the explicit Firecracker backend options used
// by NewLiveDriver. Tests and future worker configuration can inspect or reuse
// these options without importing command or factory packages.
func NewLiveBackendOptions(options LiveDriverOptions) (firecracker.BackendOptions, error) {
	_, backendOptions, err := newLiveBackendOptions(options)
	return backendOptions, err
}

func newLiveBackendOptions(options LiveDriverOptions) (microvm.Config, firecracker.BackendOptions, error) {
	config, err := validatedLiveDriverConfig(options.Config)
	if err != nil {
		return microvm.Config{}, firecracker.BackendOptions{}, err
	}
	baseStateDir, err := validatedLiveDriverBaseStateDir(options.BaseStateDir)
	if err != nil {
		return microvm.Config{}, firecracker.BackendOptions{}, err
	}
	if options.BootAcceptancePoller == nil {
		return microvm.Config{}, firecracker.BackendOptions{}, newLiveDriverConfigError("bootAcceptancePoller", "boot acceptance poller is required")
	}

	lifecycle := NewProcessLifecycleManager(liveDriverHostProcessRunner(options), liveDriverLifecycleOptions(options)...)
	adapter := NewAdapter(liveDriverAdapterOptions(options, lifecycle)...)

	backendOptions := firecracker.BackendOptions{
		BaseStateDir:         baseStateDir,
		ProcessAdapter:       firecracker.ProcessLaunchAdapter{Starter: adapter},
		BootAcceptanceWaiter: adapter,
		LiveProcessManager:   adapter,
		LiveStart:            true,
		GuestTransport:       options.GuestTransport,
	}
	if options.GuestReadinessProbe != nil {
		backendOptions.GuestReadinessWaiter = adapter
	}
	return config, backendOptions, nil
}

func validatedLiveDriverConfig(config microvm.Config) (microvm.Config, error) {
	config = microvm.ApplyDefaults(config)
	if _, err := firecracker.BackendConfigFromMicroVMConfig(config); err != nil {
		return microvm.Config{}, err
	}
	return config, nil
}

func validatedLiveDriverBaseStateDir(baseStateDir string) (string, error) {
	baseStateDir = strings.TrimSpace(baseStateDir)
	if _, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID:    "fc-live-driver-validation",
		BaseStateDir: baseStateDir,
	}); err != nil {
		return "", err
	}
	return baseStateDir, nil
}

func liveDriverHostProcessRunner(options LiveDriverOptions) HostProcessRunner {
	if options.HostProcessRunner != nil {
		return options.HostProcessRunner
	}
	return NewOSExecProcessRunner()
}

func liveDriverNetworkEnforcement(options LiveDriverOptions) *microvm.NetworkEnforcementPlanning {
	if options.NetworkEnforcement != nil {
		return options.NetworkEnforcement
	}
	if options.NetworkEnforcementLive == nil {
		return nil
	}
	liveOptions := *options.NetworkEnforcementLive
	return microvm.NewLiveNetworkEnforcementPlanning(liveOptions)
}

func liveDriverLifecycleOptions(options LiveDriverOptions) []ProcessLifecycleOption {
	if options.CleanupFilesystem == nil {
		return nil
	}
	return []ProcessLifecycleOption{WithProcessLifecycleCleanupFilesystem(options.CleanupFilesystem)}
}

func liveDriverAdapterOptions(options LiveDriverOptions, lifecycle *ProcessLifecycleManager) []Option {
	adapterOptions := []Option{
		WithProcessRunner(lifecycle),
		WithBootAcceptancePoller(options.BootAcceptancePoller),
		WithLiveProcessCleanup(lifecycle),
	}
	if options.Clock != nil {
		adapterOptions = append(adapterOptions, WithClock(options.Clock))
	}
	if options.Sleeper != nil {
		adapterOptions = append(adapterOptions, WithSleeper(options.Sleeper))
	}
	if options.BootTimeout > 0 {
		adapterOptions = append(adapterOptions, WithBootAcceptanceTimeout(options.BootTimeout))
	}
	if options.BootPollInterval > 0 {
		adapterOptions = append(adapterOptions, WithBootAcceptancePollInterval(options.BootPollInterval))
	}
	if options.GuestReadinessProbe != nil {
		adapterOptions = append(adapterOptions, WithGuestReadinessProbe(options.GuestReadinessProbe))
	}
	if options.GuestTimeout > 0 {
		adapterOptions = append(adapterOptions, WithGuestReadinessTimeout(options.GuestTimeout))
	}
	if options.GuestPollInterval > 0 {
		adapterOptions = append(adapterOptions, WithGuestReadinessPollInterval(options.GuestPollInterval))
	}
	return adapterOptions
}

func newLiveDriverConfigError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(liveDriverConstructionOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}
