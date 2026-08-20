package sandboxworker

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var ErrL8ServiceUnavailable = errors.New("worker L8 service unavailable")

// L8Service is the explicitly injected, default-off worker v2 boundary.
type L8Service struct {
	binder *sandboxruntime.JobCredentialRuntimeBinder
}

func NewL8Service(binder *sandboxruntime.JobCredentialRuntimeBinder) (*L8Service, error) {
	if binder == nil {
		return nil, ErrL8ServiceUnavailable
	}
	return &L8Service{binder: binder}, nil
}

func (service *L8Service) HandleRequest(ctx context.Context, request Request) Response {
	if service == nil || service.binder == nil {
		return l8ServiceFailureResponse(request)
	}
	if response, ok := contextErrorResponse(ctx, request); ok {
		return response
	}
	if request.Operation != OperationJobStartV2 || request.JobStartV2 == nil || !request.JobStartV2.ProductionCredentialsRequested {
		return unsupportedOperationResponse(request)
	}
	if err := request.JobStartV2.Validate(); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker L8 job start request")
	}
	binding, err := service.binder.BindTarget(l8JobCredentialRuntimeTarget(request.JobStartV2.Exec.Target))
	if err != nil {
		return l8ServiceFailureResponse(request)
	}
	preflight, err := binding.PreflightNow()
	if err != nil {
		return l8ServiceFailureResponse(request)
	}
	if _, err := preflight.AbortNow(); err != nil {
		return l8ServiceFailureResponse(request)
	}
	return unsupportedOperationResponse(request)
}

func l8JobCredentialRuntimeTarget(target Target) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:     target.ID,
		Name:   target.Name,
		Status: target.Status,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         target.Runtime.Driver,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
			IsolationLevel: target.Runtime.IsolationLevel,
		},
	}
}

func l8ServiceFailureResponse(request Request) Response {
	return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "worker L8 job service is unavailable")
}
