package microvm

import (
	"context"
	"errors"
	"strings"

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
	config   Config
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
		config:   config,
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
	backend, config, err := d.backendFor(OperationCreate)
	if err != nil {
		return nil, err
	}
	backendReq := backendCreateRequest(config, req)
	if err := validateCreateRequest(backendReq); err != nil {
		return nil, err
	}
	target, err := backend.Create(ctx, backendReq)
	if err != nil {
		return nil, wrapBackendOperationError(OperationCreate, err)
	}
	return applyRuntimeMetadata(target), nil
}

func (d *Driver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	controller, config, target, err := d.controllerFor(ctx, OperationStart, req.Target)
	if err != nil {
		return nil, err
	}
	started, err := controller.Start(ctx, ControllerLifecycleRequest{
		Operation: OperationStart,
		Config:    config,
		Target:    target,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	})
	if err != nil {
		return nil, wrapBackendOperationError(OperationStart, err)
	}
	return applyRuntimeMetadata(started), nil
}

func (d *Driver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	controller, config, target, err := d.controllerFor(ctx, OperationStop, req.Target)
	if err != nil {
		return nil, err
	}
	stopped, err := controller.Stop(ctx, ControllerLifecycleRequest{
		Operation: OperationStop,
		Config:    config,
		Target:    target,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	})
	if err != nil {
		return nil, wrapBackendOperationError(OperationStop, err)
	}
	return applyRuntimeMetadata(stopped), nil
}

func (d *Driver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	controller, config, target, err := d.controllerFor(ctx, OperationDelete, req.Target)
	if err != nil {
		return err
	}
	return wrapBackendOperationError(OperationDelete, controller.Delete(ctx, ControllerLifecycleRequest{
		Operation: OperationDelete,
		Config:    config,
		Target:    target,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	}))
}

func (d *Driver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	controller, config, target, err := d.controllerFor(ctx, OperationInspect, req.Target)
	if err != nil {
		return nil, err
	}
	inspected, err := controller.Inspect(ctx, ControllerInspectRequest{
		Operation: OperationInspect,
		Config:    config,
		Target:    target,
	})
	if err != nil {
		return nil, wrapBackendOperationError(OperationInspect, err)
	}
	return applyRuntimeMetadata(inspected), nil
}

func (d *Driver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	controller, config, target, err := d.controllerFor(ctx, OperationExec, req.Target)
	if err != nil {
		return nil, err
	}
	result, err := controller.Exec(ctx, ControllerExecRequest{
		Operation: OperationExec,
		Config:    config,
		Target:    target,
		Args:      cloneStringSlice(req.Args),
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
		Stdin:     req.Stdin,
		Env:       cloneStringMap(req.Env),
		WorkDir:   strings.TrimSpace(req.WorkDir),
	})
	if err != nil {
		return nil, wrapBackendOperationError(OperationExec, err)
	}
	return result, nil
}

func (d *Driver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	controller, config, target, err := d.controllerFor(ctx, OperationCopyIn, req.Target)
	if err != nil {
		return err
	}
	copyReq, err := controllerCopyRequest(OperationCopyIn, config, target, req)
	if err != nil {
		return err
	}
	return wrapBackendOperationError(OperationCopyIn, controller.CopyIn(ctx, copyReq))
}

func (d *Driver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	controller, config, target, err := d.controllerFor(ctx, OperationCopyOut, req.Target)
	if err != nil {
		return err
	}
	copyReq, err := controllerCopyRequest(OperationCopyOut, config, target, req)
	if err != nil {
		return err
	}
	return wrapBackendOperationError(OperationCopyOut, controller.CopyOut(ctx, copyReq))
}

func (d *Driver) backendFor(operation string) (Backend, Config, error) {
	if d == nil {
		return nil, Config{}, NewBackendNotConfiguredError(operation)
	}
	metadata := d.Metadata()
	if metadata.Capability.Availability != CapabilityAvailabilityAvailable {
		cause := ErrUnavailableCapability
		if metadata.Capability.Error != nil {
			cause = metadata.Capability.Error
		}
		return nil, Config{}, NewUnavailableCapabilityError(operation, cause)
	}
	if d.backend == nil {
		return nil, Config{}, NewBackendNotConfiguredError(operation)
	}
	config := ApplyDefaults(d.config)
	if err := ValidateConfig(config); err != nil {
		return nil, Config{}, operationInvalidConfigError(operation, err)
	}
	return d.backend, config, nil
}

func (d *Driver) controllerFor(ctx context.Context, operation string, target sandboxruntime.Target) (Controller, Config, sandboxruntime.Target, error) {
	backend, config, err := d.backendFor(operation)
	if err != nil {
		return nil, Config{}, sandboxruntime.Target{}, err
	}
	target = sanitizeTarget(target)
	if err := validateTarget(operation, target); err != nil {
		return nil, Config{}, sandboxruntime.Target{}, err
	}
	controller, err := backend.Controller(ctx, ControllerRequest{
		Operation: operation,
		Config:    config,
		Target:    target,
	})
	if err != nil {
		return nil, Config{}, sandboxruntime.Target{}, wrapBackendOperationError(operation, err)
	}
	if controller == nil {
		return nil, Config{}, sandboxruntime.Target{}, NewBackendNotConfiguredError(operation)
	}
	return controller, config, target, nil
}

func backendCreateRequest(config Config, req sandboxruntime.CreateRequest) BackendCreateRequest {
	return BackendCreateRequest{
		Operation: OperationCreate,
		Config:    config,
		Name:      strings.TrimSpace(req.Name),
		Env:       cloneStringMap(req.Env),
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	}
}

func validateCreateRequest(req BackendCreateRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return NewTargetNameRequiredError(OperationCreate)
	}
	return nil
}

func validateTarget(operation string, target sandboxruntime.Target) error {
	if strings.TrimSpace(target.ID) == "" &&
		strings.TrimSpace(target.Name) == "" &&
		strings.TrimSpace(target.Runtime.RuntimeID) == "" {
		return NewTargetRequiredError(operation)
	}
	return nil
}

func controllerCopyRequest(operation string, config Config, target sandboxruntime.Target, req sandboxruntime.CopyRequest) (ControllerCopyRequest, error) {
	copyReq := ControllerCopyRequest{
		Operation:       operation,
		Config:          config,
		Target:          target,
		SourcePath:      strings.TrimSpace(req.SourcePath),
		DestinationPath: strings.TrimSpace(req.DestinationPath),
	}
	if copyReq.SourcePath == "" {
		return ControllerCopyRequest{}, newOperationValidationError(operation, "sourcePath", "copy source path is required")
	}
	if copyReq.DestinationPath == "" {
		return ControllerCopyRequest{}, newOperationValidationError(operation, "destinationPath", "copy destination path is required")
	}
	return copyReq, nil
}

func newOperationValidationError(operation, field, message string) *OperationError {
	err := NewInvalidConfigError(operation, ErrInvalidConfig)
	err.Field = field
	err.Message = message
	return err
}

func operationInvalidConfigError(operation string, err error) error {
	if err == nil {
		return nil
	}
	operationErr := NewInvalidConfigError(operation, err)
	var validationErr *OperationError
	if errors.As(err, &validationErr) {
		operationErr.Field = validationErr.Field
		operationErr.Message = validationErr.safeMessage()
	}
	return operationErr
}

func wrapBackendOperationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var operationErr *OperationError
	if errors.As(err, &operationErr) {
		if strings.TrimSpace(operationErr.Operation) != "" {
			return operationErr
		}
		wrapped := *operationErr
		wrapped.Operation = sanitizeIdentifier(operation)
		return &wrapped
	}
	return NewBackendOperationFailedError(operation, err)
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
	copied.Runtime.Metadata = cloneRuntimeMetadata(target.Runtime.Metadata)
	copied.Runtime.Driver = sandboxruntime.DriverMicroVM
	copied.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
	return &copied
}

func sanitizeTarget(target sandboxruntime.Target) sandboxruntime.Target {
	target.ID = strings.TrimSpace(target.ID)
	target.Name = strings.TrimSpace(target.Name)
	target.Runtime.RuntimeID = strings.TrimSpace(target.Runtime.RuntimeID)
	return *applyRuntimeMetadata(&target)
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneRuntimeMetadata(metadata *sandboxruntime.RuntimeMetadata) *sandboxruntime.RuntimeMetadata {
	if metadata == nil {
		return nil
	}
	copied := *metadata
	copied.CapabilityLabels = cloneStringSlice(metadata.CapabilityLabels)
	copied.PathRoles = cloneStringSlice(metadata.PathRoles)
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
