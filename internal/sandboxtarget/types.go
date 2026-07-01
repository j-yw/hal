package sandboxtarget

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// Purpose identifies the sandbox-capable workflow requesting a target.
type Purpose string

const (
	PurposeRun     Purpose = sandbox.SandboxLeasePurposeRun
	PurposeAuto    Purpose = sandbox.SandboxLeasePurposeAuto
	PurposeFactory Purpose = sandbox.SandboxLeasePurposeFactory
)

// Request describes cached-metadata target-selection intent. It is deliberately
// data-only so command packages can construct it without coupling selection to
// Cobra, worker clients, runtime drivers, or live provider calls.
type Request struct {
	Purpose        Purpose
	SandboxName    string
	HostID         string
	RuntimeDriver  string
	IsolationLevel string
	Project        ProjectContext
	Fallback       FallbackPolicy
}

// ProjectContext carries repository context that can influence deterministic
// target selection without importing command-layer request types.
type ProjectContext struct {
	Dir        string
	Repository string
	Branch     string
}

// FallbackPolicy controls whether the selector may use legacy fallback paths
// when no exact explicit target is selected.
type FallbackPolicy struct {
	AllowDefaultRunningSandbox bool
	AllowBranchProvisioning    bool
	Disabled                   bool
}

// DefaultFallbackPolicy returns the Phase 17 legacy-compatible fallback policy.
func DefaultFallbackPolicy() FallbackPolicy {
	return FallbackPolicy{
		AllowDefaultRunningSandbox: true,
		AllowBranchProvisioning:    true,
	}
}

// Effective returns the policy implied by p. The zero value intentionally keeps
// existing sandbox behavior available until callers opt into stricter handling.
func (p FallbackPolicy) Effective() FallbackPolicy {
	if p.Disabled {
		return FallbackPolicy{Disabled: true}
	}
	if p == (FallbackPolicy{}) {
		return DefaultFallbackPolicy()
	}
	return p
}

// EffectiveFallbackPolicy returns the fallback policy that should be applied to
// this request.
func (r Request) EffectiveFallbackPolicy() FallbackPolicy {
	return r.Fallback.Effective()
}

// HasExplicitSandboxName reports whether the request names a specific sandbox.
func (r Request) HasExplicitSandboxName() bool {
	return strings.TrimSpace(r.SandboxName) != ""
}

// HasHostConstraint reports whether the request names a specific durable host.
func (r Request) HasHostConstraint() bool {
	return strings.TrimSpace(r.HostID) != ""
}

// HasRuntimeConstraint reports whether the request names a required runtime.
func (r Request) HasRuntimeConstraint() bool {
	return strings.TrimSpace(r.RuntimeDriver) != ""
}

// HasIsolationConstraint reports whether the request names a required isolation
// level or tier.
func (r Request) HasIsolationConstraint() bool {
	return strings.TrimSpace(r.IsolationLevel) != ""
}

// Result describes the outcome of target selection using cached durable
// metadata only. Selector implementations can fill whichever selected metadata
// is known without constructing live clients or runtime drivers.
type Result struct {
	Sandbox      *sandbox.SandboxState
	Host         *sandbox.SandboxHost
	Runtime      *sandboxruntime.RuntimeState
	Provisioning *ProvisioningPlan
	Source       SourceMetadata
	Fallback     FallbackMetadata
	Failure      *Failure
}

// Selected reports whether the result carries any selected target metadata.
func (r Result) Selected() bool {
	return r.Sandbox != nil || r.Host != nil || r.Runtime != nil
}

// Failed reports whether the result carries a deterministic failure reason.
func (r Result) Failed() bool {
	return r.Failure != nil && r.Failure.Reason != FailureReasonNone
}

// NeedsProvisioning reports whether selection intentionally left sandbox
// creation to the command layer.
func (r Result) NeedsProvisioning() bool {
	return r.Provisioning != nil && strings.TrimSpace(r.Provisioning.SandboxName) != ""
}

// ProvisioningPlan describes a legacy-compatible sandbox creation fallback.
type ProvisioningPlan struct {
	SandboxName string
	Branch      string
	Repository  string
}

// SourceKind identifies how a target was selected.
type SourceKind string

const (
	SourceUnknown               SourceKind = ""
	SourceExplicitSandbox       SourceKind = "explicit_sandbox"
	SourceDefaultRunningSandbox SourceKind = "default_running_sandbox"
	SourceRequestedHost         SourceKind = "requested_host"
	SourceRequestedRuntime      SourceKind = "requested_runtime"
	SourceRequestedIsolation    SourceKind = "requested_isolation"
	SourceFallbackProvisioning  SourceKind = "fallback_provisioning"
)

// SourceMetadata records the cached source used to select a target.
type SourceMetadata struct {
	Kind   SourceKind
	Detail string
}

// FallbackMetadata records any fallback path used during target selection.
type FallbackMetadata struct {
	Policy FallbackPolicy
	Used   bool
	Source SourceKind
	Reason string
}

// FailureReason identifies deterministic target-selection failures.
type FailureReason string

const (
	FailureReasonNone                 FailureReason = ""
	FailureReasonInvalidRequest       FailureReason = "invalid_request"
	FailureReasonSandboxNotFound      FailureReason = "sandbox_not_found"
	FailureReasonNoRunningSandbox     FailureReason = "no_running_sandbox"
	FailureReasonHostNotFound         FailureReason = "host_not_found"
	FailureReasonHostMismatch         FailureReason = "host_mismatch"
	FailureReasonHostUnhealthy        FailureReason = "host_unhealthy"
	FailureReasonRuntimeUnsupported   FailureReason = "runtime_unsupported"
	FailureReasonIsolationUnavailable FailureReason = "isolation_unavailable"
	FailureReasonAmbiguousTarget      FailureReason = "ambiguous_target"
)

// Failure carries redaction-safe failure context for target selection.
type Failure struct {
	Reason         FailureReason
	Message        string
	SandboxName    string
	HostID         string
	RuntimeDriver  string
	IsolationLevel string
}

// Error returns a stable, human-readable failure description.
func (f Failure) Error() string {
	if message := strings.TrimSpace(f.Message); message != "" {
		return message
	}
	if f.Reason != FailureReasonNone {
		return "sandbox target selection failed: " + string(f.Reason)
	}
	return "sandbox target selection failed"
}
