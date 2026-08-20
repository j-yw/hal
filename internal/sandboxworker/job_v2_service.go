package sandboxworker

import (
	"context"
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type L8Service struct {
	workerID           string
	principalAuthority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	daemonGeneration   string
	jobs               *jobManagerV2
}

type L8ServiceOptions struct {
	WorkerID           string
	PrincipalAuthority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	StateDir           string
	DaemonGeneration   string
}

func NewL8Service(options L8ServiceOptions) (*L8Service, error) {
	if !validWorkerV2SafeID(strings.TrimSpace(options.WorkerID)) || options.PrincipalAuthority == nil || !validWorkerV2SafeID(strings.TrimSpace(options.DaemonGeneration)) {
		return nil, errors.New("worker l8 service configuration is invalid")
	}
	jobs, err := newJobManagerV2(jobManagerV2Options{
		StateDir:         options.StateDir,
		WorkerID:         strings.TrimSpace(options.WorkerID),
		DaemonGeneration: strings.TrimSpace(options.DaemonGeneration),
	})
	if err != nil {
		return nil, errors.New("worker l8 job state is unavailable")
	}
	return &L8Service{
		workerID:           strings.TrimSpace(options.WorkerID),
		principalAuthority: options.PrincipalAuthority,
		daemonGeneration:   strings.TrimSpace(options.DaemonGeneration),
		jobs:               jobs,
	}, nil
}

func (service *L8Service) Close() {
	if service == nil || service.jobs == nil {
		return
	}
	service.jobs.close()
}

func (service *L8Service) HandleRequest(ctx context.Context, request Request) Response {
	if service == nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "worker l8 service is not configured")
	}
	return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "authenticated worker principal is required")
}

func (service *L8Service) HandlesAuthenticatedRequest(request Request) bool {
	return service != nil && isWorkerV2Operation(request.Operation)
}

func (service *L8Service) HandleAuthenticatedRequest(ctx context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request Request) Response {
	if service == nil || service.principalAuthority == nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "authenticated worker principal was rejected")
	}
	principalID, err := service.principalAuthority.AuthenticatedWorkerPrincipalID(principal)
	if err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "authenticated worker principal was rejected")
	}
	if !isWorkerV2Operation(request.Operation) {
		return unsupportedOperationResponse(request)
	}
	if response, ok := contextErrorResponse(ctx, request); ok {
		return response
	}
	switch request.Operation {
	case OperationJobStatusV2:
		if request.JobStatusV2 == nil {
			return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "worker v2 job status payload is required")
		}
		return service.jobStatusV2Response(request.RequestID, principalID, *request.JobStatusV2)
	default:
		return unsupportedOperationResponse(request)
	}
}

var _ AuthenticatedRequestHandler = (*L8Service)(nil)
