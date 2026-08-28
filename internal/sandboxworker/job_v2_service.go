package sandboxworker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

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
	liveMu             sync.Mutex
	live               map[string]*l8LiveJobCredential
	closed             bool
}

type l8LiveJobCredential struct {
	mu        sync.Mutex
	finished  bool
	session   *sandboxruntime.JobCredentialSessionBinding
	lifecycle *sandboxruntime.JobCredentialLifecycle
	identity  sandboxruntime.JobCredentialIdentity
	principal string
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
// A typed-nil recovery provider fails closed. Missing recovery retains
// ErrL8RecoveryDependency when durable credential ownership is present;
// retained state is never reconciled through the legacy queued-job path.
func NewL8DurableService(options L8DurableServiceOptions) (*L8Service, error) {
	workerID := strings.TrimSpace(options.WorkerID)
	daemonGeneration := strings.TrimSpace(options.DaemonGeneration)
	if !validWorkerV2SafeID(workerID) || !validWorkerV2SafeID(daemonGeneration) || options.Binder == nil || options.PrincipalAuthority == nil {
		return nil, ErrL8ServiceUnavailable
	}
	if options.RecoveryProvider != nil && sandboxruntime.JobCredentialRuntimeInterfaceNil(options.RecoveryProvider) {
		return nil, ErrL8ServiceUnavailable
	}
	jobs, err := newJobManagerV2(jobManagerV2Options{
		StateDir: options.StateDir, WorkerID: workerID, DaemonGeneration: daemonGeneration,
		Recovery: options.RecoveryProvider,
	})
	if err != nil {
		return nil, err
	}
	return &L8Service{
		binder: options.Binder, workerID: workerID, daemonGeneration: daemonGeneration,
		principalAuthority: options.PrincipalAuthority, jobs: jobs, live: make(map[string]*l8LiveJobCredential),
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
	if service == nil {
		return
	}
	service.liveMu.Lock()
	if service.closed {
		service.liveMu.Unlock()
		return
	}
	service.closed = true
	live := service.live
	service.live = nil
	service.liveMu.Unlock()
	for _, handle := range live {
		if handle == nil {
			continue
		}
		handle.mu.Lock()
		if !handle.finished && handle.session != nil {
			_, _ = handle.session.Revoke(context.Background(), "")
		}
		handle.mu.Unlock()
	}
	if service.jobs != nil {
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
	if request.Operation == OperationJobCancelV2 {
		return service.handleAuthenticatedJobCancelV2(ctx, principalID, request)
	}
	if request.Operation != OperationJobStartV2 || request.JobStartV2 == nil || !request.JobStartV2.ProductionCredentialsRequested {
		return unsupportedOperationResponse(request)
	}
	if err := request.Validate(); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker L8 job start request")
	}
	if job, existing, err := service.jobs.resolveAcceptedSubmission(request.DriverID, principalID, *request.JobStartV2); err != nil {
		return l8ServiceFailureResponse(request)
	} else if existing {
		return l8JobV2SuccessResponse(request, job)
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
		return l8JobV2SuccessResponse(request, job)
	}
	preflight, err := binding.Preflight(ctx)
	if err != nil {
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	identity := preflight.Identity()
	if err := service.jobs.persistCredentialIdentity(job.ID, principalID, identity); err != nil {
		_, _ = preflight.AbortBounded()
		return l8ServiceFailureResponse(request)
	}
	lifecycle, err := sandboxruntime.NewJobCredentialLifecycle(identity)
	if err != nil {
		_, _ = preflight.AbortBounded()
		return l8ServiceFailureResponse(request)
	}
	if err := lifecycle.BeginPrepare(identity); err != nil {
		_, _ = preflight.AbortBounded()
		return l8ServiceFailureResponse(request)
	}
	session, err := preflight.Prepare(ctx, sandboxruntime.JobCredentialPrepareRequest{Identity: identity})
	if err != nil {
		service.completeFailedPreflight(job.ID, principalID, preflight, lifecycle)
		if response, ok := contextErrorResponse(ctx, request); ok {
			return response
		}
		return l8ServiceFailureResponse(request)
	}
	observedAt := time.Now().UTC()
	if err := lifecycle.Activate(session.ActiveProof(), observedAt); err != nil {
		service.completeFailedSession(job.ID, principalID, session, lifecycle)
		return l8ServiceFailureResponse(request)
	}
	if err := service.jobs.persistCredentialRevision(job.ID, principalID, lifecycle.Revision()); err != nil {
		service.completeFailedSession(job.ID, principalID, session, lifecycle)
		return l8ServiceFailureResponse(request)
	}
	if !service.retainLiveJobCredential(job.ID, principalID, session, lifecycle, identity) {
		service.completeFailedSession(job.ID, principalID, session, lifecycle)
		return l8ServiceFailureResponse(request)
	}
	go service.watchJobCredentialLoss(job.ID, principalID, session)
	return l8JobV2SuccessResponse(request, job)
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

func l8JobV2SuccessResponse(request Request, job JobV2) Response {
	snapshot := cloneJobV2(job)
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(request.RequestID),
		Operation:       request.Operation,
		OK:              true,
		JobV2:           &snapshot,
	}
}

func (service *L8Service) handleAuthenticatedJobCancelV2(ctx context.Context, principalID string, request Request) Response {
	if request.JobCancelV2 == nil {
		return unsupportedOperationResponse(request)
	}
	if err := request.Validate(); err != nil {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker L8 job cancel request")
	}
	live := service.liveJobCredential(request.JobCancelV2.JobID, principalID)
	if live != nil {
		live.mu.Lock()
		defer live.mu.Unlock()
		if live.finished {
			return l8ServiceFailureResponse(request)
		}
		proof, err := live.session.Revoke(ctx, "")
		if err != nil || sandboxruntime.CleanupProofKind(proof) == "" {
			return l8ServiceFailureResponse(request)
		}
		if live.lifecycle != nil {
			if err := live.lifecycle.BeginRevoke(); err != nil {
				return l8ServiceFailureResponse(request)
			}
			if _, err := live.lifecycle.Revoke(proof, time.Now().UTC()); err != nil {
				return l8ServiceFailureResponse(request)
			}
		}
	}
	job, err := service.jobs.clearCredentialState(request.JobCancelV2.JobID, principalID, JobStateCanceled, "", time.Now().UTC(), live != nil)
	if err != nil {
		if err == errJobV2NotFound {
			return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeJobNotFound, "worker job was not found")
		}
		return l8ServiceFailureResponse(request)
	}
	if live != nil {
		live.finished = true
		service.removeLiveJobCredential(request.JobCancelV2.JobID, live)
	}
	return l8JobV2SuccessResponse(request, job)
}

func (service *L8Service) watchJobCredentialLoss(jobID, principalID string, session *sandboxruntime.JobCredentialSessionBinding) {
	if session == nil {
		return
	}
	lossCh := session.Loss()
	if lossCh == nil {
		return
	}
	loss, ok := <-lossCh
	if !ok {
		return
	}
	live := service.liveJobCredential(jobID, principalID)
	if live == nil {
		return
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.finished {
		return
	}
	if live.lifecycle != nil {
		if err := live.lifecycle.ObserveLoss(loss); err != nil {
			return
		}
	}
	proof, err := live.session.Revoke(context.Background(), "")
	if err != nil || sandboxruntime.CleanupProofKind(proof) == "" {
		return
	}
	if live.lifecycle != nil {
		if err := live.lifecycle.BeginRevoke(); err != nil {
			return
		}
		if _, err := live.lifecycle.Revoke(proof, time.Now().UTC()); err != nil {
			return
		}
	}
	failureCode := string(loss.Code)
	if !validWorkerV2SafeID(failureCode) {
		failureCode = string(sandboxruntime.JobCredentialFailureCleanupIncomplete)
	}
	if _, err := service.jobs.clearCredentialState(jobID, principalID, JobStateInterrupted, failureCode, time.Now().UTC(), true); err != nil {
		return
	}
	live.finished = true
	service.removeLiveJobCredential(jobID, live)
}

func (service *L8Service) retainLiveJobCredential(jobID, principalID string, session *sandboxruntime.JobCredentialSessionBinding, lifecycle *sandboxruntime.JobCredentialLifecycle, identity sandboxruntime.JobCredentialIdentity) bool {
	if service == nil || jobID == "" || session == nil {
		return false
	}
	service.liveMu.Lock()
	defer service.liveMu.Unlock()
	if service.closed || service.live == nil {
		return false
	}
	service.live[jobID] = &l8LiveJobCredential{session: session, lifecycle: lifecycle, identity: identity, principal: principalID}
	return true
}

func (service *L8Service) liveJobCredential(jobID, principalID string) *l8LiveJobCredential {
	if service == nil {
		return nil
	}
	service.liveMu.Lock()
	defer service.liveMu.Unlock()
	if service.live == nil {
		return nil
	}
	handle := service.live[jobID]
	if handle == nil || handle.principal != principalID {
		return nil
	}
	return handle
}

func (service *L8Service) removeLiveJobCredential(jobID string, handle *l8LiveJobCredential) {
	if service == nil || handle == nil {
		return
	}
	service.liveMu.Lock()
	defer service.liveMu.Unlock()
	if service.live[jobID] == handle {
		delete(service.live, jobID)
	}
}

func (service *L8Service) completeFailedPreflight(jobID, principalID string, preflight *sandboxruntime.JobCredentialRuntimePreflightBinding, lifecycle *sandboxruntime.JobCredentialLifecycle) {
	if service == nil || preflight == nil || lifecycle == nil {
		return
	}
	proof, err := preflight.AbortBounded()
	if err != nil {
		return
	}
	if sandboxruntime.CleanupProofKind(proof) == "" {
		return
	}
	if err := lifecycle.BeginRevoke(); err != nil {
		return
	}
	if _, err := lifecycle.Revoke(proof, time.Now().UTC()); err != nil {
		return
	}
	_, _ = service.jobs.clearCredentialState(jobID, principalID, JobStateInterrupted, string(sandboxruntime.JobCredentialFailurePrepareFailed), time.Now().UTC(), true)
}

func (service *L8Service) completeFailedSession(jobID, principalID string, session *sandboxruntime.JobCredentialSessionBinding, lifecycle *sandboxruntime.JobCredentialLifecycle) {
	if service == nil || session == nil || lifecycle == nil {
		return
	}
	proof, err := session.Revoke(context.Background(), "")
	if err != nil || sandboxruntime.CleanupProofKind(proof) == "" || lifecycle.BeginRevoke() != nil {
		return
	}
	if _, err := lifecycle.Revoke(proof, time.Now().UTC()); err != nil {
		return
	}
	_, _ = service.jobs.clearCredentialState(jobID, principalID, JobStateInterrupted, string(sandboxruntime.JobCredentialFailurePrepareFailed), time.Now().UTC(), true)
}
