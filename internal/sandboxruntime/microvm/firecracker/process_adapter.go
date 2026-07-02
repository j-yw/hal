package firecracker

import "context"

// ProcessStarter is the narrow injected boundary that accepts a concrete
// Firecracker runner request and performs process startup.
type ProcessStarter interface {
	StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error)
}

// ProcessLaunchAdapter adapts a prepared Firecracker process descriptor to an
// injected process starter. It does not construct or start processes itself.
type ProcessLaunchAdapter struct {
	Starter ProcessStarter
}

// ProcessRunnerStartRequest is the raw process command shape passed only to an
// explicitly injected process starter. Environment is an explicit empty list
// until a later strict whitelist feature adds tested environment delivery.
type ProcessRunnerStartRequest struct {
	Executable  string   `json:"-"`
	Args        []string `json:"-"`
	Environment []string `json:"-"`
}

// PrepareStartCommand renders the process descriptor for a validated
// Firecracker start plan without requiring a process starter.
func (ProcessLaunchAdapter) PrepareStartCommand(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
	return ProcessCommandDescriptorFromStartPlan(req.Plan)
}

// StartProcess validates and converts the prepared descriptor before crossing
// the injected process starter boundary.
func (adapter ProcessLaunchAdapter) StartProcess(ctx context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
	if adapter.Starter == nil {
		return ProcessHandleMetadata{}, newProcessBoundaryError("processStarter", "process starter is required")
	}
	if err := validateProcessCommandDescriptor(req.Descriptor); err != nil {
		return ProcessHandleMetadata{}, err
	}
	ctx = processContext(ctx)
	if err := ctx.Err(); err != nil {
		return ProcessHandleMetadata{}, err
	}
	startReq, err := processRunnerStartRequest(req.Descriptor)
	if err != nil {
		return ProcessHandleMetadata{}, err
	}
	handle, err := adapter.Starter.StartProcess(ctx, startReq)
	if err != nil {
		return ProcessHandleMetadata{}, newProcessBoundaryAdapterError("processStarter", "process start failed", err)
	}
	return sanitizeProcessHandleMetadata(handle), nil
}

func processRunnerStartRequest(descriptor ProcessCommandDescriptor) (ProcessRunnerStartRequest, error) {
	if len(descriptor.Argv) == 0 {
		return ProcessRunnerStartRequest{}, newProcessBoundaryError("argv", "start argv is required")
	}
	return ProcessRunnerStartRequest{
		Executable:  descriptor.Executable.Path,
		Args:        cloneStringSlice(descriptor.Argv[1:]),
		Environment: []string{},
	}, nil
}
