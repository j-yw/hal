package firecracker

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// GuestReadinessWaiter is the optional backend boundary for checking guest
// readiness after host-side process acceptance.
type GuestReadinessWaiter interface {
	WaitForGuestReadiness(context.Context, GuestReadinessRequest) (GuestReadinessResult, error)
}

// GuestReadinessRequest identifies the accepted host process and runtime using
// only sanitized metadata.
type GuestReadinessRequest struct {
	Handle    ProcessHandleMetadata `json:"handle,omitempty"`
	RuntimeID string                `json:"runtimeId,omitempty"`
}

// GuestReadinessResult is the Firecracker backend readiness result shape. Its
// durable surface carries only shared readiness state, a safe transport label,
// and safe labels. Live proof bindings are intentionally excluded from JSON.
type GuestReadinessResult struct {
	State                      sandboxruntime.RuntimeGuestReadinessState `json:"state,omitempty"`
	Transport                  string                                    `json:"transport,omitempty"`
	Labels                     []string                                  `json:"labels,omitempty"`
	IsolationProofGeneration   string                                    `json:"-"`
	IsolationRuntimeGeneration string                                    `json:"-"`
}

// NewGuestReadinessRequest builds a sanitized guest readiness request.
func NewGuestReadinessRequest(handle ProcessHandleMetadata, runtimeID string) GuestReadinessRequest {
	return SanitizeGuestReadinessRequest(GuestReadinessRequest{
		Handle:    handle,
		RuntimeID: runtimeID,
	})
}

// SanitizeGuestReadinessRequest preserves only safe process handle metadata
// and a safe runtime ID.
func SanitizeGuestReadinessRequest(req GuestReadinessRequest) GuestReadinessRequest {
	return GuestReadinessRequest{
		Handle:    sanitizeProcessHandleMetadata(req.Handle),
		RuntimeID: safeFirecrackerMetadataToken(req.RuntimeID),
	}
}

// NewGuestReadinessResult builds a sanitized guest readiness result.
func NewGuestReadinessResult(state sandboxruntime.RuntimeGuestReadinessState, transport string, labels []string) GuestReadinessResult {
	return SanitizeGuestReadinessResult(GuestReadinessResult{
		State:     state,
		Transport: transport,
		Labels:    labels,
	})
}

// SanitizeGuestReadinessResult preserves only canonical readiness metadata.
func SanitizeGuestReadinessResult(result GuestReadinessResult) GuestReadinessResult {
	metadata := sandboxruntime.NewRuntimeGuestReadinessMetadata(result.State, result.Transport, result.Labels)
	if metadata == nil {
		return GuestReadinessResult{}
	}
	sanitized := GuestReadinessResult{
		State:     metadata.State,
		Transport: metadata.Transport,
		Labels:    cloneStringSlice(metadata.Labels),
	}
	proofGeneration := safeFirecrackerMetadataToken(result.IsolationProofGeneration)
	runtimeGeneration := safeFirecrackerMetadataToken(result.IsolationRuntimeGeneration)
	if proofGeneration != "" && runtimeGeneration != "" {
		sanitized.IsolationProofGeneration = proofGeneration
		sanitized.IsolationRuntimeGeneration = runtimeGeneration
	}
	return sanitized
}

// RuntimeMetadata converts the Firecracker readiness result into the shared
// runtime metadata shape.
func (result GuestReadinessResult) RuntimeMetadata() *sandboxruntime.RuntimeGuestReadinessMetadata {
	sanitized := SanitizeGuestReadinessResult(result)
	return sandboxruntime.NewRuntimeGuestReadinessMetadata(sanitized.State, sanitized.Transport, sanitized.Labels)
}
