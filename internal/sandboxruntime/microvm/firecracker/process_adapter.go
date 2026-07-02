package firecracker

import "context"

// ProcessStarter is the narrow injected boundary that accepts a prepared
// Firecracker process descriptor and performs process startup.
type ProcessStarter interface {
	StartProcess(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error)
}

// ProcessLaunchAdapter adapts a prepared Firecracker process descriptor to an
// injected process starter. It does not construct or start processes itself.
type ProcessLaunchAdapter struct {
	Starter ProcessStarter
}

// PrepareStartCommand renders the process descriptor for a validated
// Firecracker start plan without requiring a process starter.
func (ProcessLaunchAdapter) PrepareStartCommand(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
	return ProcessCommandDescriptorFromStartPlan(req.Plan)
}

// StartProcess forwards the prepared descriptor to the injected process
// starter boundary.
func (adapter ProcessLaunchAdapter) StartProcess(ctx context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
	if adapter.Starter == nil {
		return ProcessHandleMetadata{}, newProcessBoundaryError("processStarter", "process starter is required")
	}
	handle, err := adapter.Starter.StartProcess(processContext(ctx), req)
	if err != nil {
		return ProcessHandleMetadata{}, err
	}
	return sanitizeProcessHandleMetadata(handle), nil
}
