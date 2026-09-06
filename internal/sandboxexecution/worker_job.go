package sandboxexecution

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const WorkerJobContractVersion = "sandboxjob-v1"

// WorkerJobReference is the sanitized durable link from an execution manifest
// to a daemon-owned asynchronous job. It intentionally contains no command,
// environment, process, endpoint, credential, or filesystem-path data.
type WorkerJobReference struct {
	ContractVersion string     `json:"contractVersion"`
	JobID           string     `json:"jobId"`
	SubmissionKey   string     `json:"submissionKey,omitempty"`
	WorkerID        string     `json:"workerId"`
	HostID          string     `json:"hostId,omitempty"`
	RuntimeDriver   string     `json:"runtimeDriver"`
	RuntimeID       string     `json:"runtimeId,omitempty"`
	State           string     `json:"state"`
	SubmittedAt     time.Time  `json:"submittedAt"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	HeartbeatAt     *time.Time `json:"heartbeatAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	LogCursor       uint64     `json:"logCursor"`
}

var (
	workerJobSafeIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$`)
	workerJobSubmissionKeyPattern = regexp.MustCompile(`^submission-[a-f0-9]{64}$`)
)

// SanitizeWorkerJobReference returns a detached safe reference or nil when the
// supplied metadata cannot be represented without unsafe values.
func SanitizeWorkerJobReference(reference *WorkerJobReference) *WorkerJobReference {
	if reference == nil {
		return nil
	}
	cloned := *reference
	cloned.ContractVersion = strings.TrimSpace(cloned.ContractVersion)
	cloned.JobID = strings.TrimSpace(cloned.JobID)
	cloned.SubmissionKey = strings.TrimSpace(cloned.SubmissionKey)
	cloned.WorkerID = strings.TrimSpace(cloned.WorkerID)
	cloned.HostID = strings.TrimSpace(cloned.HostID)
	cloned.RuntimeDriver = strings.TrimSpace(cloned.RuntimeDriver)
	cloned.RuntimeID = strings.TrimSpace(cloned.RuntimeID)
	cloned.State = strings.TrimSpace(cloned.State)
	cloned.StartedAt = cloneWorkerJobTime(reference.StartedAt)
	cloned.HeartbeatAt = cloneWorkerJobTime(reference.HeartbeatAt)
	cloned.FinishedAt = cloneWorkerJobTime(reference.FinishedAt)
	if validateWorkerJobReference(&cloned) != nil {
		return nil
	}
	return &cloned
}

func validateWorkerJobReference(reference *WorkerJobReference) error {
	if reference == nil {
		return nil
	}
	if reference.ContractVersion != WorkerJobContractVersion {
		return fmt.Errorf("sandbox execution workerJob contractVersion is invalid")
	}
	if reference.SubmissionKey != "" && !workerJobSubmissionKeyPattern.MatchString(reference.SubmissionKey) {
		return fmt.Errorf("sandbox execution workerJob submissionKey is invalid")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "jobId", value: reference.JobID},
		{name: "workerId", value: reference.WorkerID},
		{name: "runtimeDriver", value: reference.RuntimeDriver},
	} {
		if !validWorkerJobSafeID(field.value) {
			return fmt.Errorf("sandbox execution workerJob %s is invalid", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "hostId", value: reference.HostID},
		{name: "runtimeId", value: reference.RuntimeID},
	} {
		if field.value != "" && !validWorkerJobSafeID(field.value) {
			return fmt.Errorf("sandbox execution workerJob %s is invalid", field.name)
		}
	}
	switch reference.State {
	case "queued", "running", "succeeded", "failed", "canceled", "interrupted", "unknown":
	default:
		return fmt.Errorf("sandbox execution workerJob state is invalid")
	}
	if reference.SubmittedAt.IsZero() {
		return fmt.Errorf("sandbox execution workerJob submittedAt is required")
	}
	if err := validateWorkerJobLifecycle(reference); err != nil {
		return err
	}
	return nil
}

func validateWorkerJobLifecycle(reference *WorkerJobReference) error {
	if reference.StartedAt != nil && reference.StartedAt.Before(reference.SubmittedAt) {
		return fmt.Errorf("sandbox execution workerJob startedAt precedes submittedAt")
	}
	if reference.HeartbeatAt != nil && reference.HeartbeatAt.Before(reference.SubmittedAt) {
		return fmt.Errorf("sandbox execution workerJob heartbeatAt precedes submittedAt")
	}
	if reference.FinishedAt != nil && reference.FinishedAt.Before(reference.SubmittedAt) {
		return fmt.Errorf("sandbox execution workerJob finishedAt precedes submittedAt")
	}
	if reference.StartedAt != nil && reference.HeartbeatAt != nil && reference.HeartbeatAt.Before(*reference.StartedAt) {
		return fmt.Errorf("sandbox execution workerJob heartbeatAt precedes startedAt")
	}
	if reference.StartedAt != nil && reference.FinishedAt != nil && reference.FinishedAt.Before(*reference.StartedAt) {
		return fmt.Errorf("sandbox execution workerJob finishedAt precedes startedAt")
	}
	if reference.HeartbeatAt != nil && reference.FinishedAt != nil && reference.FinishedAt.Before(*reference.HeartbeatAt) {
		return fmt.Errorf("sandbox execution workerJob finishedAt precedes heartbeatAt")
	}
	switch reference.State {
	case "queued":
		if reference.StartedAt != nil || reference.HeartbeatAt != nil || reference.FinishedAt != nil {
			return fmt.Errorf("sandbox execution workerJob queued state has lifecycle progress timestamps")
		}
	case "running":
		if reference.StartedAt == nil {
			return fmt.Errorf("sandbox execution workerJob running state requires startedAt")
		}
		if reference.FinishedAt != nil {
			return fmt.Errorf("sandbox execution workerJob running state has finishedAt")
		}
	default:
		if reference.FinishedAt == nil {
			return fmt.Errorf("sandbox execution workerJob terminal state requires finishedAt")
		}
		if (reference.State == "succeeded" || reference.State == "failed") && reference.StartedAt == nil {
			return fmt.Errorf("sandbox execution workerJob terminal execution state requires startedAt")
		}
	}
	return nil
}

func validWorkerJobSafeID(value string) bool {
	return value != "" && value != "." && value != ".." && workerJobSafeIDPattern.MatchString(value)
}

func cloneWorkerJobTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
