package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

// ErrDependencyNotConfigured is returned when an adapter method is called
// before the matching host dependency has been injected.
var ErrDependencyNotConfigured = errors.New("firecracker host adapter dependency is not configured")

// ProcessRunner starts a prepared Firecracker host process request.
type ProcessRunner interface {
	StartProcess(context.Context, firecracker.ProcessRunnerStartRequest) (firecracker.ProcessHandleMetadata, error)
}

// BootAcceptancePoller checks whether a live-started host process and API
// socket have reached the Phase 34 acceptance boundary.
type BootAcceptancePoller interface {
	PollBootAcceptance(context.Context, firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error)
}

// Clock is the injectable time source used by later deterministic polling
// behavior.
type Clock interface {
	Now() time.Time
}

// Sleeper is the injectable delay boundary used by later deterministic polling
// behavior.
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

// LiveProcessCleanup owns host-side cleanup operations for live Firecracker
// process handles and state paths.
type LiveProcessCleanup interface {
	CleanupLiveProcess(context.Context, firecracker.LiveProcessRequest) error
	StopLiveProcess(context.Context, firecracker.LiveProcessRequest) error
	DeleteLiveProcess(context.Context, firecracker.LiveProcessRequest) error
}

// Adapter satisfies the Phase 34 Firecracker live-boot injection interfaces by
// delegating host behavior to explicitly configured dependencies.
type Adapter struct {
	processRunner ProcessRunner
	poller        BootAcceptancePoller
	clock         Clock
	sleeper       Sleeper
	bootTimeout   time.Duration
	bootInterval  time.Duration
	cleanup       LiveProcessCleanup
}

// Option configures a host adapter dependency.
type Option func(*Adapter)

// NewAdapter constructs a Firecracker host adapter. The zero-option adapter is
// inert: live methods return ErrDependencyNotConfigured until their matching
// dependencies are injected.
func NewAdapter(options ...Option) *Adapter {
	adapter := &Adapter{
		clock:        systemClock{},
		sleeper:      contextSleeper{},
		bootTimeout:  defaultBootAcceptanceTimeout,
		bootInterval: defaultBootAcceptancePollInterval,
	}
	for _, option := range options {
		if option != nil {
			option(adapter)
		}
	}
	return adapter
}

// WithProcessRunner injects the host process runner used by StartProcess.
func WithProcessRunner(runner ProcessRunner) Option {
	return func(adapter *Adapter) {
		adapter.processRunner = runner
	}
}

// WithBootAcceptancePoller injects the host acceptance poller used by
// WaitForBootAcceptance.
func WithBootAcceptancePoller(poller BootAcceptancePoller) Option {
	return func(adapter *Adapter) {
		adapter.poller = poller
	}
}

// WithClock injects the adapter clock for deterministic polling behavior.
func WithClock(clock Clock) Option {
	return func(adapter *Adapter) {
		if clock != nil {
			adapter.clock = clock
		}
	}
}

// WithSleeper injects the adapter sleeper for deterministic polling behavior.
func WithSleeper(sleeper Sleeper) Option {
	return func(adapter *Adapter) {
		if sleeper != nil {
			adapter.sleeper = sleeper
		}
	}
}

// WithBootAcceptanceTimeout injects the maximum host-side wait duration used
// by WaitForBootAcceptance.
func WithBootAcceptanceTimeout(timeout time.Duration) Option {
	return func(adapter *Adapter) {
		if timeout > 0 {
			adapter.bootTimeout = timeout
		}
	}
}

// WithBootAcceptancePollInterval injects the delay between deterministic
// host-side acceptance polls.
func WithBootAcceptancePollInterval(interval time.Duration) Option {
	return func(adapter *Adapter) {
		if interval > 0 {
			adapter.bootInterval = interval
		}
	}
}

// WithLiveProcessCleanup injects the host cleanup manager used by cleanup,
// stop, and delete operations.
func WithLiveProcessCleanup(cleanup LiveProcessCleanup) Option {
	return func(adapter *Adapter) {
		adapter.cleanup = cleanup
	}
}

// StartProcess delegates the prepared Firecracker runner request to the
// injected process runner.
func (adapter *Adapter) StartProcess(ctx context.Context, req firecracker.ProcessRunnerStartRequest) (firecracker.ProcessHandleMetadata, error) {
	if adapter == nil || adapter.processRunner == nil {
		return firecracker.ProcessHandleMetadata{}, dependencyNotConfigured("processRunner")
	}
	return adapter.processRunner.StartProcess(nonNilContext(ctx), req)
}

// WaitForBootAcceptance polls host-side process and API socket acceptance
// through injected dependencies.
func (adapter *Adapter) WaitForBootAcceptance(ctx context.Context, req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	if adapter == nil || adapter.poller == nil {
		return firecracker.BootAcceptanceResult{}, dependencyNotConfigured("bootAcceptancePoller")
	}
	return adapter.waitForBootAcceptance(nonNilContext(ctx), req)
}

// CleanupLiveProcess delegates cleanup of a live Firecracker process to the
// injected cleanup dependency.
func (adapter *Adapter) CleanupLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	if adapter == nil || adapter.cleanup == nil {
		return dependencyNotConfigured("liveProcessCleanup")
	}
	return adapter.cleanup.CleanupLiveProcess(nonNilContext(ctx), req)
}

// StopLiveProcess delegates graceful stop of a live Firecracker process to the
// injected cleanup dependency.
func (adapter *Adapter) StopLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	if adapter == nil || adapter.cleanup == nil {
		return dependencyNotConfigured("liveProcessCleanup")
	}
	return adapter.cleanup.StopLiveProcess(nonNilContext(ctx), req)
}

// DeleteLiveProcess delegates deletion of a live Firecracker process and owned
// state to the injected cleanup dependency.
func (adapter *Adapter) DeleteLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	if adapter == nil || adapter.cleanup == nil {
		return dependencyNotConfigured("liveProcessCleanup")
	}
	return adapter.cleanup.DeleteLiveProcess(nonNilContext(ctx), req)
}

func dependencyNotConfigured(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "dependency"
	}
	return fmt.Errorf("%s: %w", name, ErrDependencyNotConfigured)
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

type contextSleeper struct{}

func (contextSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	ctx = nonNilContext(ctx)
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
