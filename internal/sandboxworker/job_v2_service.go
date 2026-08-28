package sandboxworker

import (
	"context"
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var ErrL8ServiceUnavailable = errors.New("worker L8 service unavailable")

// L8Service is the explicitly injected, default-off worker v2 boundary.
type L8Service struct {
	binder             *sandboxruntime.JobCredentialRuntimeBinder
	workerID           string
	daemonGeneration   string
	principalAuthority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	jobs               *jobManagerV2
}

// L8DurableServiceOptions enables only the explicit authenticated worker-v2
// ownership boundary. Ordinary Service construction remains default-off.
type L8DurableServiceOptions struct {
	WorkerID           string
	DaemonGeneration   string
	StateDir           string
	Binder             *sandboxruntime.JobCredentialRuntimeBinder
	PrincipalAuthority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	// RecoveryProvider is the optional D6 restart adapter. A typed-nil value
	// fails closed. A missing provider retains ErrL8RecoveryDependency when
	// durable credential ownership is present.
	RecoveryProvider sandboxruntime.JobCredentialRuntimeRecoveryProvider
}

// L8AuthenticatedServerOptions attaches one durable L8 service to the
// otherwise unchanged worker server. The service's authority is the sole
// principal issuer; callers cannot pair it with a lookalike authority.
type L8AuthenticatedServerOptions struct {
	Server      ServerOptions
	Service     *L8Service
	PrincipalID string
}

func NewL8Service(binder *sandboxruntime.JobCredentialRuntimeBinder) (*L8Service, error) {
	if binder == nil {
		return nil, ErrL8ServiceUnavailable
	}
	return &L8Service{binder: binder}, nil
}

// NewL8DurableService constructs the explicit authenticated worker-v2 router.
// Startup fails while credential ownership needs a later D6 recovery adapter;
// retained state is never reconciled through the legacy queued-job path.
func NewL8DurableService(options L8DurableServiceOptions) (*L8Service, error) {
	workerID := strings.TrimSpace(options.WorkerID)
	daemonGeneration := strings.TrimSpace(options.DaemonGeneration)
	if !validWorkerV2SafeID(workerID) || !validWorkerV2SafeID(daemonGeneration) || options.Binder == nil || options.PrincipalAuthority == nil {
		return nil, ErrL8ServiceUnavailable
	}
	jobs, err := newJobManagerV2(jobManagerV2Options{
		StateDir: options.StateDir, WorkerID: workerID, DaemonGeneration: daemonGeneration,
	})
	if err != nil {
		return nil, err
	}
	return &L8Service{
		binder: options.Binder, workerID: workerID, daemonGeneration: daemonGeneration,
		principalAuthority: options.PrincipalAuthority, jobs: jobs,
	}, nil
}

// NewL8AuthenticatedServer is the only production worker-v2 principal router.
func NewL8AuthenticatedServer(options L8AuthenticatedServerOptions) (*Server, error) {
	principalID := strings.TrimSpace(options.PrincipalID)
	if options.Service == nil || options.Service.jobs == nil || options.Service.principalAuthority == nil || !validWorkerV2SafeID(principalID) {
		return nil, ErrL8ServiceUnavailable
	}
	server, err := NewServer(options.Server)
	if err != nil {
		return nil, err
	}
	server.authenticatedHandler = options.Service
	server.principalAuthority = options.Service.principalAuthority
	server.authenticatedPrincipalID = principalID
	return server, nil
}

// Close releases the explicit durable worker-v2 state owner. The neutral
// default-off seam owns no durable state.
func (service *L8Service) Close() {
	if service != nil && service.jobs != nil {
		service.jobs.close()
	}
}

func (service *L8Service) HandleRequest(ctx context.Context, request Request) Response {
	if service == nil || service.binder == nil {
		return l8ServiceFailureResponse(request)
	}
	if service.jobs != nil {
		return l8AuthenticatedPrincipalFailureResponse(request)
	}
	if response, ok := contextErrorResponse(ctx, request); ok {
		return response
	}
	if request.Operation != OperationJobStartV2 || request.JobStartV2 == nil || !request.JobStartV2.ProductionCredentialsRequested {
		return unsupportedOperationResponse(request)
	}
	if err := request.Validate(); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker L8 job start request")
	}
	binding, err := service.binder.Bind(ctx, l8JobCredentialRuntimeTarget(request.JobStartV2.Exec.Target))
	if err != nil {
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	preflight, err := binding.Preflight(ctx)
	if err != nil {
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	if _, err := preflight.AbortBounded(); err != nil {
		return l8ServiceFailureResponse(request)
	}
	return unsupportedOperationResponse(request)
}

// HandlesAuthenticatedRequest restricts principal-bearing dispatch to the
// explicitly separate worker-v2 operation family.
func (service *L8Service) HandlesAuthenticatedRequest(request Request) bool {
	return service != nil && service.jobs != nil && isWorkerV2Operation(request.Operation)
}

// HandleAuthenticatedRequest accepts a principal only from the authenticated
// transport method boundary. Request JSON has no principal input.
func (service *L8Service) HandleAuthenticatedRequest(ctx context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request Request) Response {
	if service == nil || service.binder == nil || service.jobs == nil || service.principalAuthority == nil {
		return l8ServiceFailureResponse(request)
	}
	principalID, ok := l8AuthenticatedPrincipalIdentity(service.principalAuthority, principal)
	if !ok {
		return l8AuthenticatedPrincipalFailureResponse(request)
	}
	if response, ok := contextErrorResponse(ctx, request); ok {
		return response
	}
	if request.Operation != OperationJobStartV2 || request.JobStartV2 == nil || !request.JobStartV2.ProductionCredentialsRequested {
		return unsupportedOperationResponse(request)
	}
	if err := request.Validate(); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker L8 job start request")
	}
	if _, existing, err := service.jobs.resolveAcceptedSubmission(request.DriverID, principalID, *request.JobStartV2); err != nil {
		return l8ServiceFailureResponse(request)
	} else if existing {
		return unsupportedOperationResponse(request)
	}

	binding, err := service.binder.Bind(ctx, l8JobCredentialRuntimeTarget(request.JobStartV2.Exec.Target))
	if err != nil {
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	seed := binding.Seed()
	job, existing, err := service.jobs.acceptCredentialSeed(request.DriverID, principalID, *request.JobStartV2, seed)
	if err != nil {
		return l8ServiceFailureResponse(request)
	}
	if existing {
		return unsupportedOperationResponse(request)
	}
	preflight, err := binding.Preflight(ctx)
	if err != nil {
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	if err := service.jobs.persistCredentialIdentity(job.ID, principalID, preflight.Identity()); err != nil {
		_, _ = preflight.AbortBounded()
		return l8ServiceFailureResponse(request)
	}
	if _, err := preflight.AbortBounded(); err != nil {
		return l8ServiceFailureResponse(request)
	}
	return unsupportedOperationResponse(request)
}

func l8AuthenticatedPrincipalIdentity(authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, principal sandboxruntime.AuthenticatedWorkerPrincipal) (string, bool) {
	if authority == nil || principal == nil {
		return "", false
	}
	id, err := authority.AuthenticatedWorkerPrincipalID(principal)
	return id, err == nil && validWorkerV2SafeID(id)
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

func l8AuthenticatedPrincipalFailureResponse(request Request) Response {
	return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeInternal, "authenticated worker principal was rejected")
}
