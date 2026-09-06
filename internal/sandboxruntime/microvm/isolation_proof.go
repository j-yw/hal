package microvm

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// ProjectMicroVMIsolationProofMetadata maps sanitized target metadata to the
// strict-readiness proof surface for active VM isolation.
func ProjectMicroVMIsolationProofMetadata(target *sandboxruntime.Target) *sandbox.SandboxMicroVMIsolationProofMetadata {
	if target == nil {
		return nil
	}
	proof := sandbox.SandboxMicroVMIsolationProofMetadata{
		RuntimeDriver:   target.Runtime.Driver,
		IsolationLevel:  target.Runtime.IsolationLevel,
		RuntimeStatus:   target.Status,
		ResultSupported: target.Runtime.Driver == sandboxruntime.DriverMicroVM && target.Runtime.IsolationLevel == sandbox.SandboxIsolationLevelVM,
	}
	if target.Runtime.Metadata != nil {
		if readiness := sandboxruntime.SanitizeRuntimeGuestReadinessMetadata(target.Runtime.Metadata.GuestReadiness); readiness != nil {
			proof.GuestReadinessState = string(readiness.State)
			// The L5 vsock labels are durable diagnostics, not the private
			// live-session authority. This target-only projection cannot
			// consult that authority, so it leaves L5 strict isolation blocked
			// while preserving the established compatibility projection.
			if l5VsockReadinessMetadata(readiness) {
				proof.ResultSupported = false
			}
		}
		proof.ProcessLaunchState = microVMIsolationProcessLaunchState(target.Runtime.Metadata.ProcessLaunch)
	}
	sanitized := sandbox.SanitizeSandboxMicroVMIsolationProofMetadata(proof)
	return &sanitized
}

func l5VsockReadinessMetadata(metadata *sandboxruntime.RuntimeGuestReadinessMetadata) bool {
	if metadata == nil || metadata.Transport != "vsock" {
		return false
	}
	required := map[string]bool{
		"protocol_v1":   false,
		"runtime_bound": false,
		"probe_ok":      false,
	}
	for _, label := range metadata.Labels {
		if _, ok := required[label]; ok {
			required[label] = true
		}
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func microVMIsolationProcessLaunchState(metadata *sandboxruntime.RuntimeProcessLaunchMetadata) string {
	if metadata == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(metadata.State)) {
	case "accepted", "process_launch_accepted":
		return "accepted"
	case "attempted", "process_launch_attempted":
		return "attempted"
	case "boundary_available", "process_boundary_available":
		return "boundary_available"
	default:
		return ""
	}
}
