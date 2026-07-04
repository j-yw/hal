package sandbox

import "strings"

// SandboxMicroVMIsolationProofMetadata carries only safe labels needed to
// prove that a runtime target is actively using VM isolation.
type SandboxMicroVMIsolationProofMetadata struct {
	RuntimeDriver       string `json:"runtimeDriver,omitempty"`
	IsolationLevel      string `json:"isolationLevel,omitempty"`
	RuntimeStatus       string `json:"runtimeStatus,omitempty"`
	GuestReadinessState string `json:"guestReadinessState,omitempty"`
	ProcessLaunchState  string `json:"processLaunchState,omitempty"`
	ResultSupported     bool   `json:"resultSupported,omitempty"`
	WarningCount        int    `json:"warningCount,omitempty"`
}

// SanitizeSandboxMicroVMIsolationProofMetadata keeps only enum-like proof
// labels and bounded counts. Unsafe host details are omitted by construction.
func SanitizeSandboxMicroVMIsolationProofMetadata(proof SandboxMicroVMIsolationProofMetadata) SandboxMicroVMIsolationProofMetadata {
	return SandboxMicroVMIsolationProofMetadata{
		RuntimeDriver:       sanitizeSandboxSecurityCapabilityRuntimeDriverValue(proof.RuntimeDriver),
		IsolationLevel:      sanitizeSandboxSecurityCapabilityIsolationLevelValue(proof.IsolationLevel),
		RuntimeStatus:       sanitizeSandboxMicroVMIsolationRuntimeStatus(proof.RuntimeStatus),
		GuestReadinessState: sanitizeSandboxMicroVMIsolationGuestReadinessState(proof.GuestReadinessState),
		ProcessLaunchState:  sanitizeSandboxMicroVMIsolationProcessLaunchState(proof.ProcessLaunchState),
		ResultSupported:     proof.ResultSupported,
		WarningCount:        sanitizeSandboxMicroVMIsolationWarningCount(proof.WarningCount),
	}
}

// SandboxMicroVMIsolationProofProvesActiveVMIsolation reports true only when
// sanitized proof shows active microVM runtime isolation without warnings.
func SandboxMicroVMIsolationProofProvesActiveVMIsolation(proof *SandboxMicroVMIsolationProofMetadata) bool {
	if proof == nil {
		return false
	}
	sanitized := SanitizeSandboxMicroVMIsolationProofMetadata(*proof)
	return sanitized.ResultSupported &&
		sanitized.RuntimeDriver == SandboxRuntimeDriverMicroVM &&
		sanitized.IsolationLevel == SandboxIsolationLevelVM &&
		sandboxMicroVMIsolationRuntimeStatusActive(sanitized.RuntimeStatus) &&
		sandboxMicroVMIsolationGuestReadinessReady(sanitized.GuestReadinessState) &&
		sandboxMicroVMIsolationProcessLaunchReady(sanitized.ProcessLaunchState) &&
		sanitized.WarningCount == 0
}

func sandboxMicroVMIsolationProofEmpty(proof SandboxMicroVMIsolationProofMetadata) bool {
	return proof.RuntimeDriver == "" &&
		proof.IsolationLevel == "" &&
		proof.RuntimeStatus == "" &&
		proof.GuestReadinessState == "" &&
		proof.ProcessLaunchState == "" &&
		!proof.ResultSupported &&
		proof.WarningCount == 0
}

func sanitizeSandboxMicroVMIsolationRuntimeStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case StatusRunning, "active", "ready":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func sanitizeSandboxMicroVMIsolationGuestReadinessState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "ready", "waiting", "not_configured":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func sanitizeSandboxMicroVMIsolationProcessLaunchState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ""
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

func normalizeSandboxMicroVMIsolationProcessLaunchState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "process_launch_accepted":
		return "accepted"
	case "process_launch_attempted":
		return "attempted"
	case "process_boundary_available":
		return "boundary_available"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func sanitizeSandboxMicroVMIsolationWarningCount(count int) int {
	if count < 0 {
		return 0
	}
	if count > 1000 {
		return 1000
	}
	return count
}

func sandboxMicroVMIsolationRuntimeStatusActive(status string) bool {
	switch status {
	case StatusRunning, "active", "ready":
		return true
	default:
		return false
	}
}

func sandboxMicroVMIsolationGuestReadinessReady(state string) bool {
	return state == "" || state == "ready"
}

func sandboxMicroVMIsolationProcessLaunchReady(state string) bool {
	return normalizeSandboxMicroVMIsolationProcessLaunchState(state) == "accepted"
}
