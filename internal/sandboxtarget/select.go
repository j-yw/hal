package sandboxtarget

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// CachedState provides target selection with durable sandbox metadata only.
// Callers adapt command-layer registry functions into these callbacks.
type CachedState struct {
	LoadSandbox   func(name string) (*sandbox.SandboxState, error)
	ListSandboxes func() ([]*sandbox.SandboxState, error)
	ListHosts     func() ([]*sandbox.SandboxHost, error)
	ListLeases    func() ([]*sandbox.SandboxLease, error)
	Now           func() time.Time
}

// Select validates explicit cached target constraints before preserving the
// legacy unconstrained decision order: explicit sandbox name, then the only
// running sandbox, then branch-named provisioning when fallback policy allows it.
func Select(req Request, cache CachedState) Result {
	policy := req.EffectiveFallbackPolicy()
	if isolationResult := validateRequestedIsolation(req); isolationResult.Failed() {
		return isolationResult
	}
	if compatibilityResult := validateRequestedRuntimeIsolation(req); compatibilityResult.Failed() {
		return compatibilityResult
	}

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
	} else if req.HasIsolationConstraint() {
		isolationResult := selectRequestedIsolation(req, cache, policy)
		if isolationResult.Failed() {
			return isolationResult
		}
		requestedHost = isolationResult.Host
		requestedRuntime = isolationResult.Runtime
		requestedConstraint = isolationResult
	}
	if req.HasExplicitSandboxName() {
		result := selectExplicitSandbox(req, cache, policy)
		if failure := validateSelectedSandbox(req, result); failure.Failed() {
			return failure
		}
		return withRequestedMetadata(result, requestedHost, requestedRuntime)
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
		runtime = runtimeStateForDriver(runtimeDriver)
	}
	if req.HasIsolationConstraint() {
		isolationLevel := strings.TrimSpace(req.IsolationLevel)
		if runtime != nil {
			if !runtimeSatisfiesIsolation(*runtime, isolationLevel) {
				return failureResult(Failure{
					Reason:         FailureReasonIsolationUnavailable,
					Message:        fmt.Sprintf("requested runtime %q does not satisfy requested isolation %q", runtime.Driver, isolationLevel),
					HostID:         hostID,
					RuntimeDriver:  runtime.Driver,
					IsolationLevel: isolationLevel,
				})
			}
		} else {
			runtimeDriver, ok := hostRuntimeForIsolation(host, isolationLevel)
			if !ok {
				return failureResult(Failure{
					Reason:         FailureReasonIsolationUnavailable,
					Message:        fmt.Sprintf("host %q does not support requested isolation %q", hostID, isolationLevel),
					HostID:         hostID,
					IsolationLevel: isolationLevel,
				})
			}
			runtime = runtimeStateForDriver(runtimeDriver)
		}
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
		return requestedRuntimeResult(host, runtimeStateForDriver(runtimeDriver), policy)
	}

	return failureResult(Failure{
		Reason:        FailureReasonRuntimeUnsupported,
		Message:       fmt.Sprintf("no durable host supports requested runtime %q", runtimeDriver),
		RuntimeDriver: runtimeDriver,
	})
}

func selectRequestedIsolation(req Request, cache CachedState, policy FallbackPolicy) Result {
	isolationLevel := strings.TrimSpace(req.IsolationLevel)
	if cache.ListHosts == nil {
		return failureResult(Failure{
			Reason:         FailureReasonInvalidRequest,
			Message:        "host lister is required",
			IsolationLevel: isolationLevel,
		})
	}
	hosts, err := cache.ListHosts()
	if err != nil {
		return failureResult(Failure{
			Reason:         FailureReasonInvalidRequest,
			Message:        fmt.Sprintf("list cached sandbox hosts for isolation %q failed", isolationLevel),
			IsolationLevel: isolationLevel,
		})
	}

	for _, host := range orderedHosts(hosts) {
		runtimeDriver, ok := hostRuntimeForIsolation(host, isolationLevel)
		if !ok {
			continue
		}
		return requestedIsolationResult(host, runtimeStateForDriver(runtimeDriver), isolationLevel, policy)
	}

	return failureResult(Failure{
		Reason:         FailureReasonIsolationUnavailable,
		Message:        fmt.Sprintf("no durable host supports requested isolation %q", isolationLevel),
		IsolationLevel: isolationLevel,
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

func hostRuntimeForIsolation(host *sandbox.SandboxHost, isolationLevel string) (string, bool) {
	isolationLevel = strings.TrimSpace(isolationLevel)
	if host == nil || isolationLevel == "" {
		return "", false
	}
	for _, driver := range orderedRuntimeDrivers(host.SupportedRuntimes) {
		runtime := runtimeStateForDriver(driver)
		if runtime != nil && runtimeSatisfiesIsolation(*runtime, isolationLevel) {
			return runtime.Driver, true
		}
	}
	return "", false
}

func orderedRuntimeDrivers(runtimeDrivers []string) []string {
	seen := make(map[string]struct{}, len(runtimeDrivers))
	ordered := make([]string, 0, len(runtimeDrivers))
	for _, runtimeDriver := range runtimeDrivers {
		driver := strings.TrimSpace(runtimeDriver)
		if driver == "" {
			continue
		}
		if _, ok := seen[driver]; ok {
			continue
		}
		seen[driver] = struct{}{}
		ordered = append(ordered, driver)
	}
	sort.Strings(ordered)
	return ordered
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
	host = cloneSandboxHost(host)
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
	host = cloneSandboxHost(host)
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

func requestedIsolationResult(host *sandbox.SandboxHost, runtime *sandboxruntime.RuntimeState, isolationLevel string, policy FallbackPolicy) Result {
	host = cloneSandboxHost(host)
	result := Result{
		Host:    host,
		Runtime: runtime,
		Source: SourceMetadata{
			Kind:   SourceRequestedIsolation,
			Detail: isolationLevel,
		},
		Fallback: FallbackMetadata{
			Policy: policy,
		},
	}
	return result
}

func requestedSelectionReason(result Result) string {
	switch result.Source.Kind {
	case SourceRequestedRuntime:
		return "requested runtime selected"
	case SourceRequestedIsolation:
		return "requested isolation selected"
	default:
		return "requested host selected"
	}
}

func withRequestedMetadata(result Result, host *sandbox.SandboxHost, runtime *sandboxruntime.RuntimeState) Result {
	if result.Failed() {
		return result
	}
	if host != nil {
		result.Host = cloneSandboxHost(host)
		if result.Sandbox != nil {
			result.Sandbox.Host = cloneSandboxHost(host)
		}
	}
	if runtime != nil {
		mergedRuntime := mergeRuntimeState(result.Runtime, runtime)
		result.Runtime = &mergedRuntime
		if result.Sandbox != nil {
			result.Sandbox.Runtime = sandboxRuntimeStateFromRuntime(mergedRuntime)
		}
	}
	return result
}

func mergeRuntimeState(existing, selected *sandboxruntime.RuntimeState) sandboxruntime.RuntimeState {
	var merged sandboxruntime.RuntimeState
	if existing != nil {
		merged = *existing
	}
	if selected == nil {
		return merged
	}
	if driver := strings.TrimSpace(selected.Driver); driver != "" {
		merged.Driver = driver
	}
	if selected.RuntimeID != "" {
		merged.RuntimeID = selected.RuntimeID
	}
	if selected.Image != "" {
		merged.Image = selected.Image
	}
	if selected.WorkerID != "" {
		merged.WorkerID = selected.WorkerID
	}
	if selected.IsolationLevel != "" {
		merged.IsolationLevel = selected.IsolationLevel
	}
	return merged
}

func sandboxRuntimeStateFromRuntime(runtime sandboxruntime.RuntimeState) *sandbox.SandboxRuntimeState {
	return &sandbox.SandboxRuntimeState{
		Driver:         runtime.Driver,
		IsolationLevel: runtime.IsolationLevel,
		RuntimeID:      runtime.RuntimeID,
		Image:          runtime.Image,
		WorkerID:       runtime.WorkerID,
	}
}

func cloneSandboxHost(host *sandbox.SandboxHost) *sandbox.SandboxHost {
	if host == nil {
		return nil
	}
	cloned := *host
	cloned.Labels = cloneStringMap(host.Labels)
	cloned.SupportedRuntimes = append([]string(nil), host.SupportedRuntimes...)
	if host.Capacity != nil {
		capacity := *host.Capacity
		cloned.Capacity = &capacity
	}
	if host.Health != nil {
		health := *host.Health
		if host.Health.LastHeartbeatAt != nil {
			lastHeartbeatAt := *host.Health.LastHeartbeatAt
			health.LastHeartbeatAt = &lastHeartbeatAt
		}
		cloned.Health = &health
	}
	cloned.Security = cloneSandboxSecurity(host.Security)
	if host.Cost != nil {
		cost := *host.Cost
		cloned.Cost = &cost
	}
	return &cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurity {
	if security == nil {
		return nil
	}
	cloned := *security
	if security.Network != nil {
		network := *security.Network
		cloned.Network = &network
	}
	if security.Secrets != nil {
		secrets := *security.Secrets
		secrets.RequestedModes = append([]string(nil), security.Secrets.RequestedModes...)
		secrets.ActiveModes = append([]string(nil), security.Secrets.ActiveModes...)
		cloned.Secrets = &secrets
	}
	return &cloned
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

func validateRequestedIsolation(req Request) Result {
	if !req.HasIsolationConstraint() {
		return Result{}
	}
	isolationLevel := strings.TrimSpace(req.IsolationLevel)
	if isRecognizedIsolationLevel(isolationLevel) {
		return Result{}
	}
	return failureResult(Failure{
		Reason:         FailureReasonIsolationUnavailable,
		Message:        fmt.Sprintf("requested isolation %q is not supported", isolationLevel),
		IsolationLevel: isolationLevel,
	})
}

func validateRequestedRuntimeIsolation(req Request) Result {
	if !req.HasRuntimeConstraint() || !req.HasIsolationConstraint() {
		return Result{}
	}
	runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
	isolationLevel := strings.TrimSpace(req.IsolationLevel)
	runtime := runtimeStateForDriver(runtimeDriver)
	if runtime == nil || runtimeSatisfiesIsolation(*runtime, isolationLevel) {
		return Result{}
	}
	runtimeIsolation := selectedRuntimeIsolation(*runtime)
	return failureResult(Failure{
		Reason:         FailureReasonIsolationUnavailable,
		Message:        fmt.Sprintf("requested runtime %q provides isolation %q, not requested isolation %q", runtimeDriver, runtimeIsolation, isolationLevel),
		RuntimeDriver:  runtimeDriver,
		IsolationLevel: isolationLevel,
	})
}

func validateSelectedSandbox(req Request, result Result) Result {
	if result.Failed() || result.Sandbox == nil || (!req.HasHostConstraint() && !req.HasRuntimeConstraint() && !req.HasIsolationConstraint()) {
		return Result{}
	}
	if req.HasHostConstraint() {
		hostID := strings.TrimSpace(req.HostID)
		actualHostID := selectedSandboxHostID(result.Sandbox)
		if actualHostID == "" {
			return failureResult(Failure{
				Reason:      FailureReasonHostMismatch,
				Message:     fmt.Sprintf("sandbox %q has no durable host metadata for requested host %q", result.Sandbox.Name, hostID),
				SandboxName: result.Sandbox.Name,
				HostID:      hostID,
			})
		}
		if actualHostID != hostID {
			return failureResult(Failure{
				Reason:      FailureReasonHostMismatch,
				Message:     fmt.Sprintf("sandbox %q is on host %q, not requested host %q", result.Sandbox.Name, actualHostID, hostID),
				SandboxName: result.Sandbox.Name,
				HostID:      hostID,
			})
		}
	}
	runtime := RuntimeForSandbox(result.Sandbox)
	if req.HasRuntimeConstraint() {
		runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
		if strings.TrimSpace(runtime.Driver) != runtimeDriver {
			return failureResult(Failure{
				Reason:        FailureReasonRuntimeUnsupported,
				Message:       fmt.Sprintf("sandbox %q uses runtime %q, not requested runtime %q", result.Sandbox.Name, runtime.Driver, runtimeDriver),
				SandboxName:   result.Sandbox.Name,
				RuntimeDriver: runtimeDriver,
			})
		}
		expectedIsolation, ok := runtimeDriverIsolationLevel(runtimeDriver)
		if ok && !runtimeSatisfiesIsolation(runtime, expectedIsolation) {
			return failureResult(Failure{
				Reason:         FailureReasonRuntimeUnsupported,
				Message:        fmt.Sprintf("sandbox %q runtime %q does not satisfy requested runtime category %q", result.Sandbox.Name, runtimeDriver, expectedIsolation),
				SandboxName:    result.Sandbox.Name,
				RuntimeDriver:  runtimeDriver,
				IsolationLevel: expectedIsolation,
			})
		}
	}
	if req.HasIsolationConstraint() {
		isolationLevel := strings.TrimSpace(req.IsolationLevel)
		if !runtimeSatisfiesIsolation(runtime, isolationLevel) {
			return failureResult(Failure{
				Reason:         FailureReasonIsolationUnavailable,
				Message:        fmt.Sprintf("sandbox %q does not satisfy requested isolation %q", result.Sandbox.Name, isolationLevel),
				SandboxName:    result.Sandbox.Name,
				RuntimeDriver:  runtime.Driver,
				IsolationLevel: isolationLevel,
			})
		}
	}
	return Result{}
}

func selectedSandboxHostID(target *sandbox.SandboxState) string {
	if target == nil || target.Host == nil {
		return ""
	}
	return strings.TrimSpace(target.Host.ID)
}

func runtimeStateForDriver(runtimeDriver string) *sandboxruntime.RuntimeState {
	driver := strings.TrimSpace(runtimeDriver)
	if driver == "" {
		return nil
	}
	runtime := &sandboxruntime.RuntimeState{Driver: driver}
	if isolationLevel, ok := runtimeDriverIsolationLevel(driver); ok {
		runtime.IsolationLevel = isolationLevel
	}
	return runtime
}

func runtimeSatisfiesIsolation(runtime sandboxruntime.RuntimeState, requestedIsolation string) bool {
	requestedIsolation = strings.TrimSpace(requestedIsolation)
	if requestedIsolation == "" {
		return true
	}
	selectedIsolation := selectedRuntimeIsolation(runtime)
	return selectedIsolation == requestedIsolation
}

func selectedRuntimeIsolation(runtime sandboxruntime.RuntimeState) string {
	if isolationLevel := strings.TrimSpace(runtime.IsolationLevel); isolationLevel != "" {
		return isolationLevel
	}
	isolationLevel, _ := runtimeDriverIsolationLevel(runtime.Driver)
	return isolationLevel
}

func isRecognizedIsolationLevel(isolationLevel string) bool {
	switch strings.TrimSpace(isolationLevel) {
	case sandbox.SandboxIsolationLevelHost, sandbox.SandboxIsolationLevelContainer, sandbox.SandboxIsolationLevelVM:
		return true
	default:
		return false
	}
}

func runtimeDriverIsolationLevel(runtimeDriver string) (string, bool) {
	switch strings.TrimSpace(runtimeDriver) {
	case sandbox.SandboxRuntimeDriverSSHMachine:
		return sandbox.SandboxIsolationLevelHost, true
	case sandbox.SandboxRuntimeDriverRootlessPodman:
		return sandbox.SandboxIsolationLevelContainer, true
	case sandbox.SandboxRuntimeDriverMicroVM:
		return sandbox.SandboxIsolationLevelVM, true
	default:
		return "", false
	}
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
