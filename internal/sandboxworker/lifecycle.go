package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// CreateResponse creates a runtime target through a registered driver.
func (service *Service) CreateResponse(ctx context.Context, requestID, driverID string, req CreateRequest) Response {
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationCreate, err)
	}

	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{
		Name: req.Name,
		Env:  cloneStringMap(req.Env),
	})
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationCreate, err)
	}
	return lifecycleTargetResponse(requestID, OperationCreate, driverID, target)
}

// StartResponse starts an existing runtime target through a registered driver.
func (service *Service) StartResponse(ctx context.Context, requestID, driverID string, req LifecycleRequest) Response {
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationStart, err)
	}

	target, err := driver.Start(ctx, sandboxruntime.LifecycleRequest{
		Target: runtimeTargetFromWorkerTarget(req.Target),
	})
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationStart, err)
	}
	return lifecycleTargetResponse(requestID, OperationStart, driverID, target)
}

// StopResponse stops an existing runtime target through a registered driver.
func (service *Service) StopResponse(ctx context.Context, requestID, driverID string, req LifecycleRequest) Response {
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationStop, err)
	}

	target, err := driver.Stop(ctx, sandboxruntime.LifecycleRequest{
		Target: runtimeTargetFromWorkerTarget(req.Target),
	})
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationStop, err)
	}
	return lifecycleTargetResponse(requestID, OperationStop, driverID, target)
}

// DeleteResponse deletes an existing runtime target through a registered driver.
func (service *Service) DeleteResponse(ctx context.Context, requestID, driverID string, req LifecycleRequest) Response {
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationDelete, err)
	}

	err = driver.Delete(ctx, sandboxruntime.LifecycleRequest{
		Target: runtimeTargetFromWorkerTarget(req.Target),
	})
	if err != nil {
		return lifecycleErrorResponse(ctx, requestID, OperationDelete, err)
	}
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationDelete,
		OK:              true,
	}
}

func (service *Service) lookupDriver(driverID string) (sandboxruntime.Driver, error) {
	if service == nil || service.registry == nil {
		return nil, ErrDriverRequired
	}
	return service.registry.Lookup(driverID)
}

func lifecycleTargetResponse(requestID, operation, driverID string, target *sandboxruntime.Target) Response {
	if target == nil {
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverFailed, "runtime driver returned no target")
	}
	workerTarget := workerTargetFromRuntimeTarget(*target, driverID)
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       operation,
		OK:              true,
		Target:          &workerTarget,
	}
}

func lifecycleErrorResponse(ctx context.Context, requestID, operation string, err error) Response {
	if err == nil {
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverFailed, "runtime driver request failed")
	}
	if resp, ok := contextErrorResponse(ctx, Request{RequestID: requestID, Operation: operation}); ok {
		return resp
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocolErrorResponse(requestID, operation, ErrorCodeRequestTimeout, "worker request timed out")
	case errors.Is(err, context.Canceled):
		return protocolErrorResponse(requestID, operation, ErrorCodeRequestCanceled, "worker request canceled")
	case errors.Is(err, ErrDriverNotFound):
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverNotFound, err.Error())
	case errors.Is(err, ErrDriverIDRequired):
		return protocolErrorResponse(requestID, operation, ErrorCodeMalformedRequest, err.Error())
	default:
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverFailed, fmt.Sprintf("runtime driver request failed: %v", err))
	}
}

func runtimeTargetFromWorkerTarget(target Target) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:     strings.TrimSpace(target.ID),
		Name:   strings.TrimSpace(target.Name),
		Status: strings.TrimSpace(target.Status),
		Runtime: sandboxruntime.RuntimeState{
			Driver:         strings.TrimSpace(target.Runtime.Driver),
			RuntimeID:      strings.TrimSpace(target.Runtime.RuntimeID),
			Image:          strings.TrimSpace(target.Runtime.Image),
			WorkerID:       strings.TrimSpace(target.Runtime.WorkerID),
			IsolationLevel: strings.TrimSpace(target.Runtime.IsolationLevel),
		},
	}
}

func workerTargetFromRuntimeTarget(target sandboxruntime.Target, fallbackDriver string) Target {
	return Target{
		ID:     strings.TrimSpace(target.ID),
		Name:   strings.TrimSpace(target.Name),
		Status: strings.TrimSpace(target.Status),
		Runtime: RuntimeTarget{
			Driver:         defaultString(target.Runtime.Driver, strings.TrimSpace(fallbackDriver)),
			RuntimeID:      strings.TrimSpace(target.Runtime.RuntimeID),
			Image:          strings.TrimSpace(target.Runtime.Image),
			WorkerID:       strings.TrimSpace(target.Runtime.WorkerID),
			IsolationLevel: strings.TrimSpace(target.Runtime.IsolationLevel),
		},
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
