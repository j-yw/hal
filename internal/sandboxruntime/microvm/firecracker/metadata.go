package firecracker

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	ProcessLaunchStateBoundaryAvailable ProcessLaunchState = "process_boundary_available"
	ProcessLaunchStateAttempted         ProcessLaunchState = "process_launch_attempted"
	ProcessLaunchStateAccepted          ProcessLaunchState = "process_launch_accepted"
)

// ProcessLaunchState is the safe public Firecracker launch-state label. These
// states stop at host process acceptance and do not imply guest or VM readiness.
type ProcessLaunchState string

// ProcessLaunchMetadata carries redaction-safe Firecracker launch-state labels.
// Process identity is optional and only exposed after process launch acceptance.
type ProcessLaunchMetadata struct {
	State           ProcessLaunchState `json:"state,omitempty"`
	Labels          []string           `json:"labels,omitempty"`
	ProcessID       string             `json:"processId,omitempty"`
	ProcessIDSource string             `json:"processIdSource,omitempty"`
}

// NewProcessLaunchMetadata builds sanitized Firecracker launch-state metadata.
func NewProcessLaunchMetadata(state ProcessLaunchState, handle ProcessHandleMetadata) ProcessLaunchMetadata {
	metadata := ProcessLaunchMetadata{State: normalizeProcessLaunchState(state)}
	if metadata.State == "" {
		return ProcessLaunchMetadata{}
	}
	metadata.Labels = []string{string(metadata.State)}
	if metadata.State != ProcessLaunchStateAccepted {
		return metadata
	}
	handle = sanitizeProcessHandleMetadata(handle)
	metadata.ProcessID = handle.ID
	metadata.ProcessIDSource = handle.Source
	return metadata
}

// SanitizeProcessLaunchMetadata returns a copy that preserves only canonical
// launch-state labels and strict process identity tokens.
func SanitizeProcessLaunchMetadata(metadata ProcessLaunchMetadata) ProcessLaunchMetadata {
	state := normalizeProcessLaunchState(metadata.State)
	if state == "" {
		return ProcessLaunchMetadata{}
	}
	handle := ProcessHandleMetadata{}
	if state == ProcessLaunchStateAccepted {
		handle = ProcessHandleMetadata{
			ID:     metadata.ProcessID,
			Source: metadata.ProcessIDSource,
		}
	}
	return NewProcessLaunchMetadata(state, handle)
}

// RuntimeMetadata converts Firecracker launch-state metadata into the shared
// runtime metadata shape.
func (metadata ProcessLaunchMetadata) RuntimeMetadata() *sandboxruntime.RuntimeProcessLaunchMetadata {
	metadata = SanitizeProcessLaunchMetadata(metadata)
	if metadata.State == "" {
		return nil
	}
	return &sandboxruntime.RuntimeProcessLaunchMetadata{
		State:           string(metadata.State),
		Labels:          cloneStringSlice(metadata.Labels),
		ProcessID:       metadata.ProcessID,
		ProcessIDSource: metadata.ProcessIDSource,
	}
}

func processBoundaryAvailableRuntimeMetadata() *sandboxruntime.RuntimeProcessLaunchMetadata {
	return NewProcessLaunchMetadata(ProcessLaunchStateBoundaryAvailable, ProcessHandleMetadata{}).RuntimeMetadata()
}

func cloneRuntimeProcessLaunchMetadata(metadata *sandboxruntime.RuntimeProcessLaunchMetadata) *sandboxruntime.RuntimeProcessLaunchMetadata {
	if metadata == nil {
		return nil
	}
	copied := *metadata
	copied.Labels = cloneStringSlice(metadata.Labels)
	return &copied
}

func normalizeProcessLaunchState(state ProcessLaunchState) ProcessLaunchState {
	switch ProcessLaunchState(strings.TrimSpace(string(state))) {
	case ProcessLaunchStateBoundaryAvailable:
		return ProcessLaunchStateBoundaryAvailable
	case ProcessLaunchStateAttempted:
		return ProcessLaunchStateAttempted
	case ProcessLaunchStateAccepted:
		return ProcessLaunchStateAccepted
	default:
		return ""
	}
}
