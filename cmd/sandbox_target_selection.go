package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxtarget"
)

type sandboxCommandTargetRequest struct {
	Purpose              string
	SandboxName          string
	SandboxHostID        string
	SandboxRuntime       string
	ProjectDir           string
	Repository           string
	Branch               string
	ProvisionRepository  string
	LoadContext          string
	Out                  io.Writer
	WrapProvisionFailure bool
}

type sandboxCommandTargetDeps struct {
	loadSandbox    func(string) (*sandbox.SandboxState, error)
	listSandboxes  func() ([]*sandbox.SandboxState, error)
	listHosts      func() ([]*sandbox.SandboxHost, error)
	resolveDefault func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	provision      func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
}

func resolveSandboxCommandTarget(ctx context.Context, req sandboxCommandTargetRequest, deps sandboxCommandTargetDeps) (*sandbox.SandboxState, error) {
	if !sandboxCommandHasTargetSelectionConstraint(req) {
		return resolveSandboxCommandLegacyTarget(ctx, req, deps)
	}
	result := sandboxtarget.Select(sandboxtarget.Request{
		Purpose:       sandboxtarget.Purpose(req.Purpose),
		SandboxName:   req.SandboxName,
		HostID:        req.SandboxHostID,
		RuntimeDriver: req.SandboxRuntime,
		Project: sandboxtarget.ProjectContext{
			Dir:        req.ProjectDir,
			Repository: req.Repository,
			Branch:     req.Branch,
		},
		Fallback: sandboxtarget.DefaultFallbackPolicy(),
	}, sandboxtarget.CachedState{
		LoadSandbox:   deps.loadSandbox,
		ListSandboxes: deps.listSandboxes,
		ListHosts:     deps.listHosts,
	})
	if result.Failed() {
		return nil, sandboxCommandTargetFailureError(result.Failure)
	}
	if err := validateSandboxCommandWorkerRuntime(result); err != nil {
		return nil, err
	}
	if result.Sandbox != nil {
		return result.Sandbox, nil
	}
	if !result.NeedsProvisioning() {
		return nil, fmt.Errorf("sandbox target selection returned no sandbox")
	}
	if err := validateSandboxCommandProvisioning(req, result); err != nil {
		return nil, err
	}

	provisionRepo := strings.TrimSpace(req.ProvisionRepository)
	if provisionRepo == "" {
		provisionRepo = result.Provisioning.Repository
	}
	target, err := deps.provision(ctx, factorySandboxProvisionRequest{
		ProjectDir: req.ProjectDir,
		Name:       result.Provisioning.SandboxName,
		BranchName: result.Provisioning.Branch,
		Repo:       provisionRepo,
		Out:        req.Out,
	})
	if err != nil {
		if req.WrapProvisionFailure {
			return nil, &sandboxexec.PhaseError{Phase: sandboxexec.PhaseProvisionTarget, Err: err}
		}
		return nil, err
	}
	return applySandboxCommandSelectedMetadata(target, result), nil
}

func sandboxCommandTargetFailureError(failure *sandboxtarget.Failure) error {
	if failure == nil {
		return nil
	}
	if failure.Reason != sandboxtarget.FailureReasonRuntimeUnsupported {
		return failure
	}
	message := failure.Error()
	if strings.Contains(message, string(failure.Reason)) {
		return failure
	}
	wrapped := *failure
	wrapped.Message = string(failure.Reason) + ": " + message
	return &wrapped
}

func validateSandboxCommandWorkerRuntime(result sandboxtarget.Result) error {
	if result.Host == nil || result.Runtime == nil {
		return nil
	}
	if strings.TrimSpace(result.Host.Kind) != sandbox.SandboxHostKindWorker {
		return nil
	}
	driver := strings.TrimSpace(result.Runtime.Driver)
	if driver == "" {
		return nil
	}
	if driver == sandbox.SandboxRuntimeDriverRootlessPodman {
		_, err := validateSandboxWorkerHostEndpoint(result.Host, driver)
		return err
	}
	hostID := sandboxHostDisplayValue(result.Host.ID, result.Host.Name)
	return &sandboxtarget.Failure{
		Reason:        sandboxtarget.FailureReasonRuntimeUnsupported,
		Message:       fmt.Sprintf("runtime_unsupported: worker host %q requested runtime %q is not supported by worker-backed sandbox execution", hostID, driver),
		HostID:        strings.TrimSpace(result.Host.ID),
		RuntimeDriver: driver,
	}
}

func validateSandboxCommandProvisioning(req sandboxCommandTargetRequest, result sandboxtarget.Result) error {
	if strings.TrimSpace(req.SandboxHostID) != "" || result.Host != nil {
		hostID := strings.TrimSpace(req.SandboxHostID)
		if hostID == "" && result.Host != nil {
			hostID = result.Host.ID
		}
		return fmt.Errorf("requested sandbox host %q cannot be provisioned by the current SSH-machine compatibility path; create a matching sandbox first or omit --%s", hostID, sandboxHostFlagName)
	}
	if result.Runtime == nil {
		return nil
	}
	driver := strings.TrimSpace(result.Runtime.Driver)
	if driver == "" || driver == sandbox.SandboxRuntimeDriverSSHMachine {
		return nil
	}
	return fmt.Errorf("requested sandbox runtime %q cannot be provisioned by the current SSH-machine compatibility path; create a matching sandbox first or request %s", driver, sandbox.SandboxRuntimeDriverSSHMachine)
}

func sandboxCommandHasTargetSelectionConstraint(req sandboxCommandTargetRequest) bool {
	return strings.TrimSpace(req.SandboxHostID) != "" || strings.TrimSpace(req.SandboxRuntime) != ""
}

func resolveSandboxCommandLegacyTarget(ctx context.Context, req sandboxCommandTargetRequest, deps sandboxCommandTargetDeps) (*sandbox.SandboxState, error) {
	if name := strings.TrimSpace(req.SandboxName); name != "" {
		target, err := deps.loadSandbox(name)
		if err == nil {
			return target, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load %s %q: %w", sandboxCommandLoadContext(req), name, err)
		}
		return provisionSandboxCommandTarget(ctx, req, deps, name, req.Branch, req.ProvisionRepository)
	}
	if deps.resolveDefault != nil {
		target, _, err := deps.resolveDefault(factoryRunningSandboxFilter)
		if err == nil {
			return target, nil
		}
		if !isFactorySandboxProvisionableResolutionError(err) {
			return nil, err
		}
	}

	name := sandbox.SandboxNameFromBranch(req.Branch)
	target, err := deps.loadSandbox(name)
	if err == nil {
		return target, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("load %s %q: %w", sandboxCommandLoadContext(req), name, err)
	}
	return provisionSandboxCommandTarget(ctx, req, deps, name, req.Branch, req.ProvisionRepository)
}

func sandboxCommandLoadContext(req sandboxCommandTargetRequest) string {
	if context := strings.TrimSpace(req.LoadContext); context != "" {
		return context
	}
	return "sandbox"
}

func provisionSandboxCommandTarget(ctx context.Context, req sandboxCommandTargetRequest, deps sandboxCommandTargetDeps, name, branchName, repo string) (*sandbox.SandboxState, error) {
	target, err := deps.provision(ctx, factorySandboxProvisionRequest{
		ProjectDir: req.ProjectDir,
		Name:       name,
		BranchName: branchName,
		Repo:       repo,
		Out:        req.Out,
	})
	if err != nil {
		if req.WrapProvisionFailure {
			return nil, &sandboxexec.PhaseError{Phase: sandboxexec.PhaseProvisionTarget, Err: err}
		}
		return nil, err
	}
	return target, nil
}

func applySandboxCommandSelectedMetadata(target *sandbox.SandboxState, result sandboxtarget.Result) *sandbox.SandboxState {
	if target == nil {
		return target
	}
	if result.Host != nil {
		target.Host = cloneSandboxHost(result.Host)
	}
	if result.Runtime != nil {
		target.Runtime = &sandbox.SandboxRuntimeState{
			Driver:         result.Runtime.Driver,
			IsolationLevel: result.Runtime.IsolationLevel,
			RuntimeID:      result.Runtime.RuntimeID,
			Image:          result.Runtime.Image,
			WorkerID:       result.Runtime.WorkerID,
		}
	}
	return target
}

func sandboxCommandListSandboxesFromDefault(resolveDefault func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)) func() ([]*sandbox.SandboxState, error) {
	return func() ([]*sandbox.SandboxState, error) {
		target, _, err := resolveDefault(factoryRunningSandboxFilter)
		if err == nil {
			return []*sandbox.SandboxState{target}, nil
		}
		if isFactorySandboxProvisionableResolutionError(err) {
			return nil, nil
		}
		return nil, err
	}
}
