package sandboxworker

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// InspectResponse inspects an existing runtime target through a registered
// driver.
func (service *Service) InspectResponse(ctx context.Context, requestID, driverID string, req InspectRequest) Response {
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationInspect, err)
	}

	target, err := driver.Inspect(ctx, sandboxruntime.InspectRequest{
		Target: runtimeTargetFromWorkerTarget(req.Target),
	})
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationInspect, err)
	}
	return lifecycleTargetResponse(requestID, OperationInspect, driverID, target)
}
