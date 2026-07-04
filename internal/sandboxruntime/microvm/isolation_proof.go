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
		}
		proof.ProcessLaunchState = microVMIsolationProcessLaunchState(target.Runtime.Metadata.ProcessLaunch)
	}
	sanitized := sandbox.SanitizeSandboxMicroVMIsolationProofMetadata(proof)
	return &sanitized
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
