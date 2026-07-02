package microvm

import (
	"context"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	RuntimeFamilyMicroVM = "microvm"
)

const (
	DriverReasonAvailable             DriverReasonCode = "available"
	DriverReasonCapabilityUnavailable DriverReasonCode = "capability_unavailable"
	DriverReasonBackendNotConfigured  DriverReasonCode = "backend_not_configured"
)

// DriverReasonCode explains the runtime driver availability state without
// exposing host paths, endpoints, or backend implementation details.
type DriverReasonCode string

// Backend is the injectable microVM backend boundary used once host capability
// checks and backend-specific prerequisites are satisfied.
type Backend interface {
	sandboxruntime.LifecycleDriver
	sandboxruntime.ExecDriver
	sandboxruntime.FileTransport
}

// DriverOptions configures the microVM runtime shell. Config is durable
// backend-neutral input; Detector and Backend are live dependencies.
type DriverOptions struct {
	Config             Config
	CapabilityDetector CapabilityDetector
	Backend            Backend
}

// RuntimeMetadata identifies the driver posture before target-specific
// metadata is available.
type RuntimeMetadata struct {
	DriverID             string
	RuntimeFamily        string
	IsolationLevel       string
	UsesHostDockerSocket bool
	Capability           CapabilityReport
	BackendConfigured    bool
	Availability         CapabilityAvailability
	ReasonCode           DriverReasonCode
}

// Driver is the microVM runtime adapter shell. It exposes the sandboxruntime
// boundary while keeping real backend lifecycle behavior behind Backend.
type Driver struct {
	backend  Backend
	metadata RuntimeMetadata
}

// New creates the default production microVM driver. Without a configured
// backend it is intentionally unavailable even on hosts with microVM capability.
func New() *Driver {
	return NewDriver(DriverOptions{})
}

// NewDriver creates a microVM driver shell with injectable capability detection
// and backend dependencies for tests and later backend implementations.
func NewDriver(options DriverOptions) *Driver {
	config := ApplyDefaults(options.Config)
	detector := options.CapabilityDetector
	if detector == nil {
		detector = HostCapabilityDetector{}
	}

	report := detector.DetectMicroVMCapability(CapabilityDetectionRequest{Config: config})
	metadata := metadataFromCapability(report, options.Backend != nil)

	return &Driver{
		backend:  options.Backend,
		metadata: metadata,
	}
}

func (d *Driver) ID() string {
	return sandboxruntime.DriverMicroVM
}

func (d *Driver) Metadata() RuntimeMetadata {
	if d == nil {
		return metadataFromCapability(CapabilityReport{
			Availability: CapabilityAvailabilityUnavailable,
			Error:        NewUnavailableCapabilityError("metadata", ErrUnavailableCapability),
		}, false)
	}
	metadata := d.metadata
	metadata.Capability = cloneCapabilityReport(metadata.Capability)
	return metadata
}

func (d *Driver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	backend, err := d.backendFor("create")
	if err != nil {
		return nil, err
	}
	target, err := backend.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return applyRuntimeMetadata(target), nil
}

func (d *Driver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	backend, err := d.backendFor("start")
	if err != nil {
		return nil, err
	}
	target, err := backend.Start(ctx, req)
	if err != nil {
		return nil, err
	}
	return applyRuntimeMetadata(target), nil
}

func (d *Driver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	backend, err := d.backendFor("stop")
	if err != nil {
		return nil, err
	}
	target, err := backend.Stop(ctx, req)
	if err != nil {
		return nil, err
	}
	return applyRuntimeMetadata(target), nil
}

func (d *Driver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	backend, err := d.backendFor("delete")
	if err != nil {
		return err
	}
	return backend.Delete(ctx, req)
}

func (d *Driver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	backend, err := d.backendFor("inspect")
	if err != nil {
		return nil, err
	}
	target, err := backend.Inspect(ctx, req)
	if err != nil {
		return nil, err
	}
	return applyRuntimeMetadata(target), nil
}

func (d *Driver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	backend, err := d.backendFor("exec")
	if err != nil {
		return nil, err
	}
	return backend.Exec(ctx, req)
}

func (d *Driver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	backend, err := d.backendFor("copy_in")
	if err != nil {
		return err
	}
	return backend.CopyIn(ctx, req)
}

func (d *Driver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	backend, err := d.backendFor("copy_out")
	if err != nil {
		return err
	}
	return backend.CopyOut(ctx, req)
}

func (d *Driver) backendFor(operation string) (Backend, error) {
	if d == nil {
		return nil, NewBackendNotConfiguredError(operation)
	}
	metadata := d.Metadata()
	if metadata.Capability.Availability != CapabilityAvailabilityAvailable {
		cause := ErrUnavailableCapability
		if metadata.Capability.Error != nil {
			cause = metadata.Capability.Error
		}
		return nil, NewUnavailableCapabilityError(operation, cause)
	}
	if d.backend == nil {
		return nil, NewBackendNotConfiguredError(operation)
	}
	return d.backend, nil
}

func metadataFromCapability(report CapabilityReport, backendConfigured bool) RuntimeMetadata {
	report = cloneCapabilityReport(report)
	metadata := RuntimeMetadata{
		DriverID:             sandboxruntime.DriverMicroVM,
		RuntimeFamily:        RuntimeFamilyMicroVM,
		IsolationLevel:       sandbox.SandboxIsolationLevelVM,
		UsesHostDockerSocket: false,
		Capability:           report,
		BackendConfigured:    backendConfigured,
		Availability:         CapabilityAvailabilityUnavailable,
		ReasonCode:           DriverReasonCapabilityUnavailable,
	}
	if report.Availability == CapabilityAvailabilityAvailable {
		if backendConfigured {
			metadata.Availability = CapabilityAvailabilityAvailable
			metadata.ReasonCode = DriverReasonAvailable
			return metadata
		}
		metadata.ReasonCode = DriverReasonBackendNotConfigured
	}
	return metadata
}

func applyRuntimeMetadata(target *sandboxruntime.Target) *sandboxruntime.Target {
	if target == nil {
		return nil
	}
	copied := *target
	copied.Runtime.Driver = sandboxruntime.DriverMicroVM
	copied.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
	return &copied
}

func cloneCapabilityReport(report CapabilityReport) CapabilityReport {
	if report.KVMReadable != nil {
		readable := *report.KVMReadable
		report.KVMReadable = &readable
	}
	if report.HypervisorExecutableAvailable != nil {
		available := *report.HypervisorExecutableAvailable
		report.HypervisorExecutableAvailable = &available
	}
	if report.Error != nil {
		err := *report.Error
		report.Error = &err
	}
	return report
}
