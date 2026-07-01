package cmd

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

type sandboxCommandStatePersistenceRequest struct {
	SandboxHostID  string
	SandboxRuntime string
	Target         *sandbox.SandboxState
	Workspace      *sandbox.SandboxWorkspace
	Save           func(*sandbox.SandboxState) error
}

func persistSandboxCommandSelectedState(req sandboxCommandStatePersistenceRequest) error {
	if req.Save == nil || !sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
		return nil
	}
	if !selectedWorkerRootlessSandboxState(req.Target) {
		return nil
	}
	state := sandboxCommandPersistentState(req.Target, req.Workspace)
	if state == nil {
		return nil
	}
	if err := req.Save(state); err != nil {
		return fmt.Errorf("persist selected worker sandbox state %q: %w", state.Name, err)
	}
	return nil
}

func selectedWorkerRootlessSandboxState(target *sandbox.SandboxState) bool {
	if target == nil || target.Host == nil || target.Runtime == nil {
		return false
	}
	return strings.TrimSpace(target.Host.Kind) == sandbox.SandboxHostKindWorker &&
		strings.TrimSpace(target.Runtime.Driver) == sandbox.SandboxRuntimeDriverRootlessPodman
}

func sandboxCommandPersistentState(target *sandbox.SandboxState, workspace *sandbox.SandboxWorkspace) *sandbox.SandboxState {
	if target == nil {
		return nil
	}
	state := *target
	state.Host = sandboxCommandPersistentHost(target.Host)
	state.Runtime = cloneSandboxRuntime(target.Runtime)
	state.Workspace = sandboxCommandPersistentWorkspace(workspace)
	if state.Workspace == nil {
		state.Workspace = sandboxCommandPersistentWorkspace(target.Workspace)
	}
	state.Security = cloneSandboxSecurity(target.Security)
	state.Lease = sandboxLeaseRefFromState(target)
	return &state
}

func sandboxLeaseRefFromState(target *sandbox.SandboxState) *sandbox.SandboxLeaseRef {
	if target == nil || target.Lease == nil {
		return nil
	}
	lease := *target.Lease
	if strings.TrimSpace(lease.HostID) == "" && target.Host != nil {
		lease.HostID = strings.TrimSpace(target.Host.ID)
	}
	if strings.TrimSpace(lease.HostName) == "" && target.Host != nil {
		lease.HostName = strings.TrimSpace(target.Host.Name)
	}
	if strings.TrimSpace(lease.RuntimeDriver) == "" && target.Runtime != nil {
		lease.RuntimeDriver = strings.TrimSpace(target.Runtime.Driver)
	}
	lease.Holder = ""
	if sandboxLeaseRefEmpty(lease) {
		return nil
	}
	return &lease
}

func sandboxLeaseRefEmpty(lease sandbox.SandboxLeaseRef) bool {
	return strings.TrimSpace(lease.ID) == "" &&
		strings.TrimSpace(lease.HostID) == "" &&
		strings.TrimSpace(lease.HostName) == "" &&
		strings.TrimSpace(lease.RuntimeDriver) == "" &&
		strings.TrimSpace(lease.ResourceKey) == "" &&
		strings.TrimSpace(lease.Purpose) == "" &&
		strings.TrimSpace(lease.RunID) == "" &&
		lease.AcquiredAt.IsZero() &&
		lease.ExpiresAt.IsZero()
}

func sandboxCommandPersistentHost(host *sandbox.SandboxHost) *sandbox.SandboxHost {
	if host == nil {
		return nil
	}
	return &sandbox.SandboxHost{
		ID:   strings.TrimSpace(host.ID),
		Name: strings.TrimSpace(host.Name),
		Kind: strings.TrimSpace(host.Kind),
	}
}

func sandboxCommandPersistentWorkspace(workspace *sandbox.SandboxWorkspace) *sandbox.SandboxWorkspace {
	if workspace == nil {
		return nil
	}
	persisted := &sandbox.SandboxWorkspace{
		Mode:        strings.TrimSpace(workspace.Mode),
		InputSource: strings.TrimSpace(workspace.InputSource),
		Branch:      strings.TrimSpace(workspace.Branch),
		SyncRef:     strings.TrimSpace(workspace.SyncRef),
	}
	if persisted.Mode == "" && persisted.InputSource == "" && persisted.Branch == "" && persisted.SyncRef == "" {
		return nil
	}
	return persisted
}

func factorySandboxWorkspaceStateFromRecord(record factory.RunRecord) *sandbox.SandboxWorkspace {
	workspace := &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Branch:      strings.TrimSpace(record.BranchName),
		SyncRef:     strings.TrimSpace(record.BaseBranch),
	}
	if workspace.Branch == "" && workspace.SyncRef == "" {
		return nil
	}
	return workspace
}
