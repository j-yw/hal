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
	Purpose                   string
	SandboxName               string
	SandboxHostID             string
	SandboxRuntime            string
	SecurityReadinessGateMode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
	ProjectDir                string
	Repository                string
	Branch                    string
	ProvisionRepository       string
	LoadContext               string
	Out                       io.Writer
	WrapProvisionFailure      bool
}

type sandboxCommandTargetDeps struct {
	loadSandbox    func(string) (*sandbox.SandboxState, error)
	listSandboxes  func() ([]*sandbox.SandboxState, error)
	listHosts      func() ([]*sandbox.SandboxHost, error)
	resolveDefault func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	provision      func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
}

type sandboxCommandSecurityReadinessGateError struct {
	cause    error
	decision sandbox.SandboxSecurityCapabilityReadinessGateDecision
}

func (e sandboxCommandSecurityReadinessGateError) Error() string {
	if e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e sandboxCommandSecurityReadinessGateError) Unwrap() error {
	return e.cause
}

func (e sandboxCommandSecurityReadinessGateError) securityReadinessGateDecision() *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&e.decision)
}

func resolveSandboxCommandTarget(ctx context.Context, req sandboxCommandTargetRequest, deps sandboxCommandTargetDeps) (*sandbox.SandboxState, error) {
	if !sandboxCommandHasTargetSelectionConstraint(req) {
		target, err := resolveSandboxCommandLegacyTarget(ctx, req, deps)
		if err != nil {
			return nil, err
		}
		return sandboxCommandLegacyCompatibilityTarget(target), nil
	}
	result := sandboxtarget.Select(sandboxtarget.Request{
		Purpose:                   sandboxtarget.Purpose(req.Purpose),
		SandboxName:               req.SandboxName,
		HostID:                    req.SandboxHostID,
		RuntimeDriver:             req.SandboxRuntime,
		SecurityReadinessGateMode: sandboxCommandTargetSelectionGateMode(req),
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
		err := sandboxCommandTargetFailureError(result.Failure)
		if result.SecurityReadinessGate != nil {
			return nil, sandboxCommandSecurityReadinessGateError{
				cause:    err,
				decision: *result.SecurityReadinessGate,
			}
		}
		return nil, err
	}
	if err := validateSandboxCommandWorkerRuntime(result); err != nil {
		return nil, err
	}
	if result.Sandbox != nil {
		return applySandboxCommandSelectedMetadata(result.Sandbox, result), nil
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
			return nil, &sandboxexec.PhaseError{Phase: sandboxexec.PhaseProvisionTarget, Target: target, Err: err}
		}
		return nil, err
	}
	return applySandboxCommandSelectedMetadata(target, result), nil
}

func sandboxCommandSecurityReadinessGateDecisionFromError(err error) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	if decision := sandboxCommandTargetSelectionSecurityReadinessGateDecisionFromError(err); decision != nil {
		return decision
	}
	var carrier interface {
		securityReadinessGateDecision() *sandbox.SandboxSecurityCapabilityReadinessGateDecision
	}
	if errors.As(err, &carrier) {
		return carrier.securityReadinessGateDecision()
	}
	return nil
}

func sandboxCommandTargetSelectionSecurityReadinessGateDecisionFromError(err error) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	var gateErr sandboxCommandSecurityReadinessGateError
	if !errors.As(err, &gateErr) {
		return nil
	}
	return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&gateErr.decision)
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
	return strings.TrimSpace(req.SandboxHostID) != "" ||
		strings.TrimSpace(req.SandboxRuntime) != "" ||
		sandboxCommandTargetSelectionGateMode(req) == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
}

func sandboxCommandTargetSelectionGateMode(req sandboxCommandTargetRequest) sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	if req.SecurityReadinessGateMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
		return ""
	}
	if req.Purpose == sandbox.SandboxLeasePurposeFactory &&
		(strings.TrimSpace(req.SandboxName) != "" ||
			strings.TrimSpace(req.SandboxHostID) != "" ||
			strings.TrimSpace(req.SandboxRuntime) != "") {
		return ""
	}
	return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
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
			return nil, &sandboxexec.PhaseError{Phase: sandboxexec.PhaseProvisionTarget, Target: target, Err: err}
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
	if result.SecurityReadinessGate != nil {
		if target.Security == nil {
			target.Security = &sandbox.SandboxSecurity{}
		}
		target.Security.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(result.SecurityReadinessGate)
	}
	return target
}

func sandboxCommandSSHMachineCompatWorkerTarget(target *sandbox.SandboxState) *sandbox.SandboxState {
	if target == nil || target.Host == nil {
		return target
	}
	if strings.TrimSpace(target.Host.Kind) != sandbox.SandboxHostKindWorker {
		return target
	}
	clone := *target
	clone.Host = sandboxCommandPersistentHost(target.Host)
	if target.Runtime != nil {
		clone.Runtime = &sandbox.SandboxRuntimeState{
			Driver: sandbox.SandboxRuntimeDriverSSHMachine,
		}
	}
	return &clone
}

func sandboxCommandLegacyCompatibilityTarget(target *sandbox.SandboxState) *sandbox.SandboxState {
	if target == nil || target.Lease == nil {
		return target
	}
	clone := *target
	clone.Lease = nil
	return &clone
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
