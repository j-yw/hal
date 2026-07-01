package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtarget"
)

const sandboxCommandLeaseTTL = 30 * time.Minute

type sandboxCommandScheduledTargetRequest struct {
	Purpose        string
	SandboxName    string
	SandboxHostID  string
	SandboxRuntime string
	ProjectDir     string
	Repository     string
	Branch         string
	RunID          string
	Workspace      *sandbox.SandboxWorkspace
}

type sandboxCommandScheduledTargetDeps struct {
	listHosts    func() ([]*sandbox.SandboxHost, error)
	listLeases   func() ([]*sandbox.SandboxLease, error)
	now          func() time.Time
	acquireLease func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error)
}

func resolveSandboxCommandScheduledTarget(req sandboxCommandScheduledTargetRequest, deps sandboxCommandScheduledTargetDeps) (*sandbox.SandboxState, error) {
	result := sandboxtarget.Schedule(sandboxtarget.SchedulerRequest{
		Purpose:       sandboxtarget.Purpose(req.Purpose),
		SandboxName:   req.SandboxName,
		HostID:        req.SandboxHostID,
		RuntimeDriver: req.SandboxRuntime,
		Intent:        sandboxtarget.SchedulerIntentExplicitTarget,
		Project: sandboxtarget.ProjectContext{
			Dir:        req.ProjectDir,
			Repository: req.Repository,
			Branch:     req.Branch,
		},
		Workspace: sandboxCommandSchedulerWorkspace(req.Workspace),
	}, sandboxtarget.CachedState{
		ListHosts:  deps.listHosts,
		ListLeases: deps.listLeases,
		Now:        deps.now,
	})
	if result.Rejected() {
		return nil, sandboxCommandSchedulerFailureError(result.Rejection)
	}
	if !result.Selected() || result.Selection == nil {
		return nil, fmt.Errorf("sandbox target scheduling returned no target")
	}

	target := sandboxCommandStateFromSchedulerResult(req, result)
	if err := validateSandboxCommandWorkerRuntime(sandboxtarget.Result{
		Host:    target.Host,
		Runtime: sandboxRuntimeStateForTargetSelection(target.Runtime),
	}); err != nil {
		return nil, err
	}

	if result.RequiresLease() {
		lease, err := acquireSandboxCommandLease(req, target, result.Lease, deps)
		if err != nil {
			return nil, err
		}
		target.Lease = sandboxLeaseRefFromLease(lease, target)
	}

	return target, nil
}

func sandboxCommandSchedulerWorkspace(workspace *sandbox.SandboxWorkspace) sandboxtarget.WorkspaceContext {
	if workspace == nil {
		return sandboxtarget.WorkspaceContext{}
	}
	return sandboxtarget.WorkspaceContext{
		Mode:        strings.TrimSpace(workspace.Mode),
		InputSource: strings.TrimSpace(workspace.InputSource),
		Repository:  strings.TrimSpace(workspace.Repo),
		Branch:      strings.TrimSpace(workspace.Branch),
		SyncRef:     strings.TrimSpace(workspace.SyncRef),
	}
}

func sandboxCommandSchedulerFailureError(rejection *sandboxtarget.SchedulerRejection) error {
	if rejection == nil {
		return nil
	}
	return sandboxCommandTargetFailureError(&sandboxtarget.Failure{
		Reason:         rejection.Reason,
		Message:        rejection.Message,
		SandboxName:    rejection.SandboxName,
		HostID:         rejection.HostID,
		RuntimeDriver:  rejection.RuntimeDriver,
		IsolationLevel: rejection.IsolationLevel,
	})
}

func sandboxCommandStateFromSchedulerResult(req sandboxCommandScheduledTargetRequest, result sandboxtarget.SchedulerResult) *sandbox.SandboxState {
	if result.Selection.Sandbox != nil {
		target := cloneSandboxCommandState(result.Selection.Sandbox)
		applyScheduledTargetMetadata(target, result.Selection)
		return target
	}

	name := strings.TrimSpace(req.SandboxName)
	if name == "" {
		name = strings.TrimSpace(result.Selection.Identity.SandboxName)
	}
	if name == "" {
		name = sandbox.SandboxNameFromBranch(req.Branch)
	}

	target := &sandbox.SandboxState{
		Name:      name,
		Provider:  "local",
		Status:    sandbox.StatusStopped,
		Workspace: cloneSandboxWorkspace(req.Workspace),
	}
	applyScheduledTargetMetadata(target, result.Selection)
	return target
}

func applyScheduledTargetMetadata(target *sandbox.SandboxState, selection *sandboxtarget.SchedulerSelection) {
	if target == nil || selection == nil {
		return
	}
	if selection.Host != nil {
		target.Host = cloneSandboxHost(selection.Host)
		target.Security = cloneSandboxSecurity(selection.Host.Security)
	}
	if selection.Runtime != nil {
		target.Runtime = sandboxRuntimeStateFromSchedulerRuntime(selection.Runtime)
	}
	if target.Runtime != nil &&
		strings.TrimSpace(target.Runtime.WorkerID) == "" &&
		target.Host != nil &&
		strings.TrimSpace(target.Host.Kind) == sandbox.SandboxHostKindWorker {
		target.Runtime.WorkerID = strings.TrimSpace(target.Host.ID)
	}
}

func sandboxRuntimeStateFromSchedulerRuntime(runtime *sandboxruntime.RuntimeState) *sandbox.SandboxRuntimeState {
	if runtime == nil {
		return nil
	}
	return &sandbox.SandboxRuntimeState{
		Driver:         strings.TrimSpace(runtime.Driver),
		IsolationLevel: strings.TrimSpace(runtime.IsolationLevel),
		RuntimeID:      strings.TrimSpace(runtime.RuntimeID),
		Image:          strings.TrimSpace(runtime.Image),
		WorkerID:       strings.TrimSpace(runtime.WorkerID),
	}
}

func sandboxRuntimeStateForTargetSelection(runtime *sandbox.SandboxRuntimeState) *sandboxruntime.RuntimeState {
	if runtime == nil {
		return nil
	}
	return &sandboxruntime.RuntimeState{
		Driver:         strings.TrimSpace(runtime.Driver),
		IsolationLevel: strings.TrimSpace(runtime.IsolationLevel),
		RuntimeID:      strings.TrimSpace(runtime.RuntimeID),
		Image:          strings.TrimSpace(runtime.Image),
		WorkerID:       strings.TrimSpace(runtime.WorkerID),
	}
}

func acquireSandboxCommandLease(req sandboxCommandScheduledTargetRequest, target *sandbox.SandboxState, leaseReq sandboxtarget.SchedulerLeaseRequirement, deps sandboxCommandScheduledTargetDeps) (*sandbox.SandboxLease, error) {
	if deps.acquireLease == nil {
		return nil, fmt.Errorf("sandbox lease acquisition is required")
	}
	ttl := leaseReq.TTL
	if ttl <= 0 {
		ttl = sandboxCommandLeaseTTL
	}
	lease, err := deps.acquireLease(sandbox.SandboxLeaseAcquireRequest{
		ID:          strings.TrimSpace(req.RunID),
		SandboxID:   strings.TrimSpace(target.ID),
		SandboxName: strings.TrimSpace(target.Name),
		ResourceKey: strings.TrimSpace(leaseReq.ResourceKey),
		Holder:      sandboxCommandLeaseHolder(req),
		Purpose:     string(leaseReq.Purpose),
		RunID:       strings.TrimSpace(req.RunID),
	}, ttl)
	if err != nil {
		return nil, sandboxCommandSchedulerOperationError{
			message: "acquire sandbox lease failed",
			cause:   err,
		}
	}
	return lease, nil
}

func sandboxCommandLeaseHolder(req sandboxCommandScheduledTargetRequest) string {
	purpose := strings.TrimSpace(req.Purpose)
	runID := strings.TrimSpace(req.RunID)
	if purpose == "" {
		purpose = "sandbox"
	}
	if runID == "" {
		runID = "unknown"
	}
	return purpose + ":" + runID
}

func cloneSandboxCommandState(target *sandbox.SandboxState) *sandbox.SandboxState {
	if target == nil {
		return nil
	}
	clone := *target
	clone.Host = cloneSandboxHost(target.Host)
	clone.Runtime = cloneSandboxRuntime(target.Runtime)
	clone.Workspace = cloneSandboxWorkspace(target.Workspace)
	clone.Security = cloneSandboxSecurity(target.Security)
	if target.Lease != nil {
		lease := *target.Lease
		clone.Lease = &lease
	}
	return &clone
}

func sandboxCommandDefaultLeaseLister(now func() time.Time, customStore bool) func() ([]*sandbox.SandboxLease, error) {
	if customStore {
		return func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		}
	}
	store := sandbox.NewSandboxLeaseStore(now)
	return func() ([]*sandbox.SandboxLease, error) {
		if _, err := store.ExpireLeases(); err != nil {
			return nil, err
		}
		return store.List()
	}
}

func sandboxCommandDefaultLeaseAcquirer(now func() time.Time, customStore bool) func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
	if customStore {
		return func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
			current := now()
			return &sandbox.SandboxLease{
				ID:          strings.TrimSpace(req.ID),
				SandboxID:   strings.TrimSpace(req.SandboxID),
				SandboxName: strings.TrimSpace(req.SandboxName),
				ResourceKey: strings.TrimSpace(req.ResourceKey),
				Holder:      strings.TrimSpace(req.Holder),
				Purpose:     strings.TrimSpace(req.Purpose),
				RunID:       strings.TrimSpace(req.RunID),
				AcquiredAt:  current,
				ExpiresAt:   current.Add(ttl),
				HeartbeatAt: current,
				Status:      sandbox.SandboxLeaseStatusActive,
			}, nil
		}
	}
	store := sandbox.NewSandboxLeaseStore(now)
	return store.Acquire
}

func sandboxCommandDefaultLeaseReleaser(now func() time.Time, customStore bool) func(string) (*sandbox.SandboxLease, error) {
	if customStore {
		return func(id string) (*sandbox.SandboxLease, error) {
			return &sandbox.SandboxLease{
				ID:     strings.TrimSpace(id),
				Status: sandbox.SandboxLeaseStatusReleased,
			}, nil
		}
	}
	store := sandbox.NewSandboxLeaseStore(now)
	return store.Release
}

type sandboxCommandLeaseReleaseTracker struct {
	releaseLease func(string) (*sandbox.SandboxLease, error)
	leaseID      string
	released     bool
}

func (t *sandboxCommandLeaseReleaseTracker) observe(target *sandbox.SandboxState) {
	if t == nil || strings.TrimSpace(t.leaseID) != "" || target == nil || target.Lease == nil {
		return
	}
	t.leaseID = strings.TrimSpace(target.Lease.ID)
}

func (t *sandboxCommandLeaseReleaseTracker) release() error {
	if t == nil || t.released {
		return nil
	}
	leaseID := strings.TrimSpace(t.leaseID)
	if leaseID == "" {
		return nil
	}
	t.released = true
	if t.releaseLease == nil {
		return fmt.Errorf("sandbox lease release is required")
	}
	if _, err := t.releaseLease(leaseID); err != nil {
		return sandboxCommandSchedulerOperationError{
			message: "release sandbox lease failed",
			cause:   err,
		}
	}
	return nil
}

type sandboxCommandSchedulerOperationError struct {
	message string
	cause   error
}

func (e sandboxCommandSchedulerOperationError) Error() string {
	if strings.TrimSpace(e.message) == "" {
		return "sandbox scheduler operation failed"
	}
	return e.message
}

func (e sandboxCommandSchedulerOperationError) Unwrap() error {
	return e.cause
}
