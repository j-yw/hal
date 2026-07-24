package sandboxexecution

import (
	"fmt"
	"regexp"
	"time"
)

const FinalizationContractVersion = "sandbox-finalization-v1"

// FinalizationState identifies the durable state of execution finalization.
type FinalizationState string

const (
	FinalizationStatePending    FinalizationState = "pending"
	FinalizationStateFinalizing FinalizationState = "finalizing"
	FinalizationStateBlocked    FinalizationState = "blocked"
	FinalizationStateCompleted  FinalizationState = "completed"
)

// FinalizationCheckpoint records completion of one retry-safe finalization
// step. It intentionally contains no runtime, endpoint, command, or path data.
type FinalizationCheckpoint struct {
	Completed   bool       `json:"completed"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

// FinalizationCheckpoints records the ordered, durable finalization steps.
type FinalizationCheckpoints struct {
	Artifacts           FinalizationCheckpoint `json:"artifacts"`
	SyncOut             FinalizationCheckpoint `json:"syncOut"`
	LeaseRelease        FinalizationCheckpoint `json:"leaseRelease"`
	TerminalPublication FinalizationCheckpoint `json:"terminalPublication"`
}

// FinalizationMetadata is the safe durable finalization intent and checkpoint
// contract for a non-factory sandbox execution.
type FinalizationMetadata struct {
	ContractVersion  string                  `json:"contractVersion"`
	State            FinalizationState       `json:"state"`
	SyncOutRequested bool                    `json:"syncOutRequested"`
	TerminalJobState string                  `json:"terminalJobState,omitempty"`
	Checkpoints      FinalizationCheckpoints `json:"checkpoints"`
	ReasonCode       string                  `json:"reasonCode,omitempty"`
	StartedAt        *time.Time              `json:"startedAt,omitempty"`
	UpdatedAt        time.Time               `json:"updatedAt"`
	CompletedAt      *time.Time              `json:"completedAt,omitempty"`
}

var finalizationReasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

func validateFinalizationMetadata(metadata *FinalizationMetadata) error {
	if metadata == nil {
		return nil
	}
	if metadata.ContractVersion != FinalizationContractVersion {
		return fmt.Errorf("sandbox execution finalization contractVersion is invalid")
	}
	if !validFinalizationState(metadata.State) {
		return fmt.Errorf("sandbox execution finalization state is invalid")
	}
	if metadata.UpdatedAt.IsZero() {
		return fmt.Errorf("sandbox execution finalization updatedAt is required")
	}
	if metadata.StartedAt != nil && metadata.UpdatedAt.Before(*metadata.StartedAt) {
		return fmt.Errorf("sandbox execution finalization updatedAt precedes startedAt")
	}
	if metadata.ReasonCode != "" && !finalizationReasonCodePattern.MatchString(metadata.ReasonCode) {
		return fmt.Errorf("sandbox execution finalization reasonCode is invalid")
	}
	if metadata.State == FinalizationStateBlocked && metadata.ReasonCode == "" {
		return fmt.Errorf("sandbox execution blocked finalization requires reasonCode")
	}
	if !validFinalizationTerminalJobState(metadata.TerminalJobState) {
		return fmt.Errorf("sandbox execution finalization terminalJobState is invalid")
	}

	checkpoints := []struct {
		name       string
		checkpoint FinalizationCheckpoint
	}{
		{name: "artifacts", checkpoint: metadata.Checkpoints.Artifacts},
		{name: "syncOut", checkpoint: metadata.Checkpoints.SyncOut},
		{name: "leaseRelease", checkpoint: metadata.Checkpoints.LeaseRelease},
		{name: "terminalPublication", checkpoint: metadata.Checkpoints.TerminalPublication},
	}
	for _, item := range checkpoints {
		if err := validateFinalizationCheckpoint(item.name, item.checkpoint); err != nil {
			return err
		}
	}
	if err := validateFinalizationCheckpointOrder(metadata); err != nil {
		return err
	}

	switch metadata.State {
	case FinalizationStatePending:
		if anyFinalizationCheckpointComplete(metadata.Checkpoints) {
			return fmt.Errorf("sandbox execution pending finalization has completed checkpoints")
		}
		if metadata.CompletedAt != nil {
			return fmt.Errorf("sandbox execution pending finalization has completedAt")
		}
	case FinalizationStateFinalizing, FinalizationStateBlocked:
		if metadata.Checkpoints.TerminalPublication.Completed {
			return fmt.Errorf("sandbox execution incomplete finalization published terminal state")
		}
		if metadata.CompletedAt != nil {
			return fmt.Errorf("sandbox execution incomplete finalization has completedAt")
		}
	case FinalizationStateCompleted:
		if metadata.TerminalJobState == "" {
			return fmt.Errorf("sandbox execution completed finalization requires terminalJobState")
		}
		if !metadata.Checkpoints.Artifacts.Completed ||
			!metadata.Checkpoints.LeaseRelease.Completed ||
			!metadata.Checkpoints.TerminalPublication.Completed {
			return fmt.Errorf("sandbox execution completed finalization has incomplete checkpoints")
		}
		if metadata.SyncOutRequested && !metadata.Checkpoints.SyncOut.Completed {
			return fmt.Errorf("sandbox execution completed finalization has incomplete syncOut checkpoint")
		}
		if metadata.CompletedAt == nil {
			return fmt.Errorf("sandbox execution completed finalization requires completedAt")
		}
		if metadata.StartedAt != nil && metadata.CompletedAt.Before(*metadata.StartedAt) {
			return fmt.Errorf("sandbox execution finalization completedAt precedes startedAt")
		}
		if metadata.UpdatedAt.Before(*metadata.CompletedAt) {
			return fmt.Errorf("sandbox execution finalization completedAt follows updatedAt")
		}
		for _, item := range checkpoints {
			if item.checkpoint.CompletedAt != nil && metadata.CompletedAt.Before(*item.checkpoint.CompletedAt) {
				return fmt.Errorf("sandbox execution finalization completedAt precedes checkpoint")
			}
		}
	}
	return nil
}

func validFinalizationState(state FinalizationState) bool {
	switch state {
	case FinalizationStatePending, FinalizationStateFinalizing, FinalizationStateBlocked, FinalizationStateCompleted:
		return true
	default:
		return false
	}
}

func validFinalizationTerminalJobState(state string) bool {
	switch state {
	case "", "succeeded", "failed", "canceled", "interrupted", "unknown":
		return true
	default:
		return false
	}
}

func validateFinalizationCheckpoint(name string, checkpoint FinalizationCheckpoint) error {
	if checkpoint.Completed && checkpoint.CompletedAt == nil {
		return fmt.Errorf("sandbox execution finalization %s checkpoint requires completedAt", name)
	}
	if !checkpoint.Completed && checkpoint.CompletedAt != nil {
		return fmt.Errorf("sandbox execution finalization %s checkpoint has completedAt before completion", name)
	}
	return nil
}

func validateFinalizationCheckpointOrder(metadata *FinalizationMetadata) error {
	checkpoints := metadata.Checkpoints
	if checkpoints.SyncOut.Completed && !checkpoints.Artifacts.Completed {
		return fmt.Errorf("sandbox execution finalization syncOut checkpoint precedes artifacts")
	}
	if checkpoints.LeaseRelease.Completed {
		if !checkpoints.Artifacts.Completed {
			return fmt.Errorf("sandbox execution finalization leaseRelease checkpoint precedes artifacts")
		}
		if metadata.SyncOutRequested && !checkpoints.SyncOut.Completed {
			return fmt.Errorf("sandbox execution finalization leaseRelease checkpoint precedes syncOut")
		}
	}
	if checkpoints.TerminalPublication.Completed && !checkpoints.LeaseRelease.Completed {
		return fmt.Errorf("sandbox execution finalization terminalPublication checkpoint precedes leaseRelease")
	}

	ordered := []FinalizationCheckpoint{
		checkpoints.Artifacts,
		checkpoints.SyncOut,
		checkpoints.LeaseRelease,
		checkpoints.TerminalPublication,
	}
	var previous *time.Time
	for _, checkpoint := range ordered {
		if !checkpoint.Completed || checkpoint.CompletedAt == nil {
			continue
		}
		if previous != nil && checkpoint.CompletedAt.Before(*previous) {
			return fmt.Errorf("sandbox execution finalization checkpoint timestamps are out of order")
		}
		previous = checkpoint.CompletedAt
	}
	return nil
}

func anyFinalizationCheckpointComplete(checkpoints FinalizationCheckpoints) bool {
	return checkpoints.Artifacts.Completed ||
		checkpoints.SyncOut.Completed ||
		checkpoints.LeaseRelease.Completed ||
		checkpoints.TerminalPublication.Completed
}
