package sandboxtarget

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// CachedState provides target selection with durable sandbox metadata only.
// Callers adapt command-layer registry functions into these callbacks.
type CachedState struct {
	LoadSandbox   func(name string) (*sandbox.SandboxState, error)
	ListSandboxes func() ([]*sandbox.SandboxState, error)
	ListHosts     func() ([]*sandbox.SandboxHost, error)
}

// Select validates explicit cached target constraints before preserving the
// legacy unconstrained decision order: explicit sandbox name, then the only
// running sandbox, then branch-named provisioning when fallback policy allows it.
func Select(req Request, cache CachedState) Result {
	policy := req.EffectiveFallbackPolicy()
	var requestedHost *sandbox.SandboxHost
	var requestedRuntime *sandboxruntime.RuntimeState
	var requestedConstraint Result
	if req.HasHostConstraint() {
		hostResult := selectRequestedHost(req, cache, policy)
		if hostResult.Failed() {
			return hostResult
		}
		requestedHost = hostResult.Host
		requestedRuntime = hostResult.Runtime
		requestedConstraint = hostResult
	} else if req.HasRuntimeConstraint() {
		runtimeResult := selectRequestedRuntime(req, cache, policy)
		if runtimeResult.Failed() {
			return runtimeResult
		}
		requestedHost = runtimeResult.Host
		requestedRuntime = runtimeResult.Runtime
		requestedConstraint = runtimeResult
	}
	if req.HasExplicitSandboxName() {
		return withRequestedMetadata(selectExplicitSandbox(req, cache, policy), requestedHost, requestedRuntime)
	}
	if requestedHost != nil {
		if !policy.Disabled && policy.AllowBranchProvisioning {
			return withRequestedMetadata(provisioningResult(req, sandbox.SandboxNameFromBranch(req.Project.Branch), policy, requestedSelectionReason(requestedConstraint)), requestedHost, requestedRuntime)
		}
		return requestedConstraint
	}
	if !policy.Disabled && policy.AllowDefaultRunningSandbox {
		result, selected := selectDefaultRunningSandbox(req, cache, policy)
		if selected || result.Failed() {
			return result
		}
	}
	if !policy.Disabled && policy.AllowBranchProvisioning {
		return provisioningResult(req, sandbox.SandboxNameFromBranch(req.Project.Branch), policy, "no running sandbox selected")
	}
	return failureResult(Failure{
		Reason:  FailureReasonNoRunningSandbox,
		Message: "no running sandboxes",
	})
}

// RuntimeForSandbox returns the runtime metadata commands historically infer
// for a sandbox. Missing runtime metadata remains SSH-machine compatible.
func RuntimeForSandbox(target *sandbox.SandboxState) sandboxruntime.RuntimeState {
	if target == nil || target.Runtime == nil {
		return sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverSSHMachine}
	}
	runtime := sandboxruntime.RuntimeState{
		Driver:         strings.TrimSpace(target.Runtime.Driver),
		RuntimeID:      target.Runtime.RuntimeID,
		Image:          target.Runtime.Image,
		WorkerID:       target.Runtime.WorkerID,
		IsolationLevel: target.Runtime.IsolationLevel,
	}
	if runtime.Driver == "" {
		runtime.Driver = sandboxruntime.DriverSSHMachine
	}
	return runtime
}

func selectRequestedHost(req Request, cache CachedState, policy FallbackPolicy) Result {
	hostID := strings.TrimSpace(req.HostID)
	if cache.ListHosts == nil {
		return failureResult(Failure{
			Reason:  FailureReasonInvalidRequest,
			Message: "host lister is required",
			HostID:  hostID,
		})
	}
	hosts, err := cache.ListHosts()
	if err != nil {
		return failureResult(Failure{
			Reason:  FailureReasonInvalidRequest,
			Message: fmt.Sprintf("list cached sandbox hosts for %q failed", hostID),
			HostID:  hostID,
		})
	}

	var matches []*sandbox.SandboxHost
	for _, host := range hosts {
		if host != nil && host.ID == hostID {
			matches = append(matches, host)
		}
	}
	switch len(matches) {
	case 0:
		return failureResult(Failure{
			Reason:  FailureReasonHostNotFound,
			Message: fmt.Sprintf("host %q does not exist", hostID),
			HostID:  hostID,
		})
	case 1:
	default:
		return failureResult(Failure{
			Reason:  FailureReasonAmbiguousTarget,
			Message: fmt.Sprintf("host %q matched multiple durable host records", hostID),
			HostID:  hostID,
		})
	}

	host := matches[0]
	if status, ok := requestedHostUnhealthyStatus(host); ok {
		return failureResult(Failure{
			Reason:  FailureReasonHostUnhealthy,
			Message: fmt.Sprintf("host %q is not healthy: %s", hostID, status),
			HostID:  hostID,
		})
	}

	var runtime *sandboxruntime.RuntimeState
	if req.HasRuntimeConstraint() {
		runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
		if !hostSupportsRuntime(host, runtimeDriver) {
			return failureResult(Failure{
				Reason:        FailureReasonRuntimeUnsupported,
				Message:       fmt.Sprintf("host %q does not support requested runtime %q", hostID, runtimeDriver),
				HostID:        hostID,
				RuntimeDriver: runtimeDriver,
			})
		}
		runtime = &sandboxruntime.RuntimeState{Driver: runtimeDriver}
	}

	return requestedHostResult(host, runtime, policy)
}

func selectRequestedRuntime(req Request, cache CachedState, policy FallbackPolicy) Result {
	runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
	if cache.ListHosts == nil {
		return failureResult(Failure{
			Reason:        FailureReasonInvalidRequest,
			Message:       "host lister is required",
			RuntimeDriver: runtimeDriver,
		})
	}
	hosts, err := cache.ListHosts()
	if err != nil {
		return failureResult(Failure{
			Reason:        FailureReasonInvalidRequest,
			Message:       fmt.Sprintf("list cached sandbox hosts for runtime %q failed", runtimeDriver),
			RuntimeDriver: runtimeDriver,
		})
	}

	for _, host := range orderedHosts(hosts) {
		if !hostSupportsRuntime(host, runtimeDriver) {
			continue
		}
		return requestedRuntimeResult(host, &sandboxruntime.RuntimeState{Driver: runtimeDriver}, policy)
	}

	return failureResult(Failure{
		Reason:        FailureReasonRuntimeUnsupported,
		Message:       fmt.Sprintf("no durable host supports requested runtime %q", runtimeDriver),
		RuntimeDriver: runtimeDriver,
	})
}

func requestedHostUnhealthyStatus(host *sandbox.SandboxHost) (string, bool) {
	if host == nil || host.Health == nil {
		return "", false
	}
	status := strings.TrimSpace(host.Health.Status)
	switch status {
	case "", "healthy", "unknown":
		return "", false
	default:
		return status, true
	}
}

func hostSupportsRuntime(host *sandbox.SandboxHost, runtimeDriver string) bool {
	driver := strings.TrimSpace(runtimeDriver)
	if host == nil || driver == "" {
		return false
	}
	for _, supported := range host.SupportedRuntimes {
		if strings.TrimSpace(supported) == driver {
			return true
		}
	}
	return false
}

func orderedHosts(hosts []*sandbox.SandboxHost) []*sandbox.SandboxHost {
	ordered := make([]*sandbox.SandboxHost, 0, len(hosts))
	for _, host := range hosts {
		if host != nil {
			ordered = append(ordered, host)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Name == ordered[j].Name {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Name < ordered[j].Name
	})
	return ordered
}

func requestedHostResult(host *sandbox.SandboxHost, runtime *sandboxruntime.RuntimeState, policy FallbackPolicy) Result {
	result := Result{
		Host:    host,
		Runtime: runtime,
		Source: SourceMetadata{
			Kind: SourceRequestedHost,
		},
		Fallback: FallbackMetadata{
			Policy: policy,
		},
	}
	if host != nil {
		result.Source.Detail = host.ID
	}
	return result
}

func requestedRuntimeResult(host *sandbox.SandboxHost, runtime *sandboxruntime.RuntimeState, policy FallbackPolicy) Result {
	result := Result{
		Host:    host,
		Runtime: runtime,
		Source: SourceMetadata{
			Kind: SourceRequestedRuntime,
		},
		Fallback: FallbackMetadata{
			Policy: policy,
		},
	}
	if runtime != nil {
		result.Source.Detail = runtime.Driver
	}
	return result
}

func requestedSelectionReason(result Result) string {
	switch result.Source.Kind {
	case SourceRequestedRuntime:
		return "requested runtime selected"
	default:
		return "requested host selected"
	}
}

func withRequestedMetadata(result Result, host *sandbox.SandboxHost, runtime *sandboxruntime.RuntimeState) Result {
	if result.Failed() {
		return result
	}
	if host != nil {
		result.Host = host
	}
	if runtime != nil {
		result.Runtime = runtime
	}
	return result
}

func selectExplicitSandbox(req Request, cache CachedState, policy FallbackPolicy) Result {
	name := strings.TrimSpace(req.SandboxName)
	if cache.LoadSandbox == nil {
		return failureResult(Failure{
			Reason:      FailureReasonInvalidRequest,
			Message:     "sandbox loader is required",
			SandboxName: name,
		})
	}
	target, err := cache.LoadSandbox(name)
	if err == nil {
		return selectedSandboxResult(target, SourceExplicitSandbox, name, policy, false, SourceUnknown, "")
	}
	if errors.Is(err, fs.ErrNotExist) && !policy.Disabled && policy.AllowBranchProvisioning {
		return provisioningResult(req, name, policy, "explicit sandbox not found")
	}
	if errors.Is(err, fs.ErrNotExist) {
		return failureResult(Failure{
			Reason:      FailureReasonSandboxNotFound,
			Message:     fmt.Sprintf("sandbox %q does not exist", name),
			SandboxName: name,
		})
	}
	return failureResult(Failure{
		Reason:      FailureReasonInvalidRequest,
		Message:     fmt.Sprintf("load sandbox %q: %v", name, err),
		SandboxName: name,
	})
}

func selectDefaultRunningSandbox(req Request, cache CachedState, policy FallbackPolicy) (Result, bool) {
	if cache.ListSandboxes == nil {
		return failureResult(Failure{
			Reason:  FailureReasonInvalidRequest,
			Message: "sandbox lister is required",
		}), true
	}
	sandboxes, err := cache.ListSandboxes()
	if err != nil {
		return failureResult(Failure{
			Reason:  FailureReasonInvalidRequest,
			Message: fmt.Sprintf("list sandboxes: %v", err),
		}), true
	}

	running := make([]*sandbox.SandboxState, 0, len(sandboxes))
	for _, candidate := range sandboxes {
		if candidate != nil && candidate.Status == sandbox.StatusRunning {
			running = append(running, candidate)
		}
	}
	sort.SliceStable(running, func(i, j int) bool {
		return running[i].Name < running[j].Name
	})

	switch len(running) {
	case 0:
		return Result{}, false
	case 1:
		return selectedSandboxResult(running[0], SourceDefaultRunningSandbox, running[0].Name, policy, true, SourceDefaultRunningSandbox, "no explicit sandbox name"), true
	default:
		names := make([]string, 0, len(running))
		for _, candidate := range running {
			names = append(names, candidate.Name)
		}
		return failureResult(Failure{
			Reason:  FailureReasonAmbiguousTarget,
			Message: fmt.Sprintf("multiple sandboxes found: %s", strings.Join(names, ", ")),
		}), true
	}
}

func selectedSandboxResult(target *sandbox.SandboxState, source SourceKind, detail string, policy FallbackPolicy, fallbackUsed bool, fallbackSource SourceKind, fallbackReason string) Result {
	runtime := RuntimeForSandbox(target)
	return Result{
		Sandbox: target,
		Runtime: &runtime,
		Source: SourceMetadata{
			Kind:   source,
			Detail: detail,
		},
		Fallback: FallbackMetadata{
			Policy: policy,
			Used:   fallbackUsed,
			Source: fallbackSource,
			Reason: fallbackReason,
		},
	}
}

func provisioningResult(req Request, sandboxName string, policy FallbackPolicy, reason string) Result {
	name := strings.TrimSpace(sandboxName)
	return Result{
		Provisioning: &ProvisioningPlan{
			SandboxName: name,
			Branch:      req.Project.Branch,
			Repository:  req.Project.Repository,
		},
		Source: SourceMetadata{
			Kind:   SourceFallbackProvisioning,
			Detail: name,
		},
		Fallback: FallbackMetadata{
			Policy: policy,
			Used:   true,
			Source: SourceFallbackProvisioning,
			Reason: reason,
		},
	}
}

func failureResult(failure Failure) Result {
	return Result{Failure: &failure}
}
