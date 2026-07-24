package sandboxworker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	JobContractVersion = "sandboxjob-v1"

	JobStateQueued      = "queued"
	JobStateRunning     = "running"
	JobStateSucceeded   = "succeeded"
	JobStateFailed      = "failed"
	JobStateCanceled    = "canceled"
	JobStateInterrupted = "interrupted"
	JobStateUnknown     = "unknown"

	JobLogStreamStdout = "stdout"
	JobLogStreamStderr = "stderr"

	DefaultJobLogRetentionBytes int64 = 1 << 20
	DefaultJobLogRecordBytes    int64 = 32 << 10
	DefaultJobLogReadBytes      int64 = 64 << 10
)

var jobSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$`)

// Job is the redaction-safe public snapshot of one daemon-owned asynchronous
// execution. It deliberately omits command arguments, environment, stdin,
// process IDs, filesystem paths, endpoints, and credentials.
type Job struct {
	ContractVersion string     `json:"contractVersion"`
	ID              string     `json:"jobId"`
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
	LogTruncated    bool       `json:"logTruncated,omitempty"`
	StdoutTruncated bool       `json:"stdoutTruncated,omitempty"`
	StderrTruncated bool       `json:"stderrTruncated,omitempty"`
	ExitCode        *int       `json:"exitCode,omitempty"`
	FailureCode     string     `json:"failureCode,omitempty"`
	CancelRequested bool       `json:"cancelRequested,omitempty"`
	requestKey      string
}

// JobStartRequest submits one asynchronous exec request to the daemon.
type JobStartRequest struct {
	ContractVersion string      `json:"contractVersion"`
	SubmissionID    string      `json:"submissionId"`
	Exec            ExecRequest `json:"exec"`
}

// JobStatusRequest retrieves the latest durable job snapshot.
type JobStatusRequest struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
}

// JobLogsRequest reads bounded redacted records after Cursor.
type JobLogsRequest struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
	Cursor          uint64 `json:"cursor"`
	LimitBytes      int64  `json:"limitBytes"`
}

// JobCancelRequest requests cancellation of one daemon-owned job.
type JobCancelRequest struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
}

// JobLogRecord is one redacted stdout or stderr record in global cursor order.
type JobLogRecord struct {
	Cursor    uint64    `json:"cursor"`
	Stream    string    `json:"stream"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// JobLogsResponse is a bounded cursor page from the daemon-owned log spool.
type JobLogsResponse struct {
	ContractVersion string         `json:"contractVersion"`
	JobID           string         `json:"jobId"`
	Records         []JobLogRecord `json:"records,omitempty"`
	NextCursor      uint64         `json:"nextCursor"`
	OldestCursor    uint64         `json:"oldestCursor,omitempty"`
	Truncated       bool           `json:"truncated,omitempty"`
}

func (req JobStartRequest) Validate() error {
	if err := validateJobContractVersion(req.ContractVersion); err != nil {
		return err
	}
	if !validJobSafeID(req.SubmissionID) {
		return fmt.Errorf("worker job submissionId is invalid")
	}
	for _, value := range req.Exec.Env {
		if int64(len([]byte(value))) > MaxExecStdinBytes {
			return fmt.Errorf("worker job environment value exceeds redaction limit")
		}
	}
	return req.Exec.Validate()
}

func (req JobStatusRequest) Validate() error {
	if err := validateJobContractVersion(req.ContractVersion); err != nil {
		return err
	}
	return validateJobID(req.JobID)
}

func (req JobLogsRequest) Validate() error {
	if err := validateJobContractVersion(req.ContractVersion); err != nil {
		return err
	}
	if err := validateJobID(req.JobID); err != nil {
		return err
	}
	if req.LimitBytes < DefaultJobLogRecordBytes || req.LimitBytes > DefaultJobLogReadBytes {
		return fmt.Errorf("worker job log limitBytes must be between %d and %d", DefaultJobLogRecordBytes, DefaultJobLogReadBytes)
	}
	return nil
}

func (req JobCancelRequest) Validate() error {
	if err := validateJobContractVersion(req.ContractVersion); err != nil {
		return err
	}
	return validateJobID(req.JobID)
}

// Validate checks that a public job snapshot contains only coherent durable
// identity and lifecycle metadata.
func (job Job) Validate() error {
	if err := validateJobContractVersion(job.ContractVersion); err != nil {
		return err
	}
	if err := validateJobID(job.ID); err != nil {
		return err
	}
	if job.SubmissionKey != "" && !validJobSafeID(job.SubmissionKey) {
		return fmt.Errorf("worker job submissionKey is invalid")
	}
	if job.requestKey != "" && !validJobRequestKey(job.requestKey) {
		return fmt.Errorf("worker job private request identity is invalid")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "workerId", value: job.WorkerID},
		{name: "runtimeDriver", value: job.RuntimeDriver},
	} {
		if !validJobSafeID(field.value) {
			return fmt.Errorf("worker job %s is invalid", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "hostId", value: job.HostID},
		{name: "runtimeId", value: job.RuntimeID},
	} {
		if field.value != "" && !validJobSafeID(field.value) {
			return fmt.Errorf("worker job %s is invalid", field.name)
		}
	}
	if !validJobState(job.State) {
		return fmt.Errorf("worker job state %q is unsupported", job.State)
	}
	if job.SubmittedAt.IsZero() {
		return fmt.Errorf("worker job submittedAt is required")
	}
	if err := job.validateLifecycle(); err != nil {
		return err
	}
	if job.FailureCode != "" && !validJobSafeID(job.FailureCode) {
		return fmt.Errorf("worker job failureCode is invalid")
	}
	return nil
}

func jobSubmissionKey(submissionID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(submissionID)))
	return "submission-" + hex.EncodeToString(sum[:])
}

func (job Job) validateLifecycle() error {
	if job.StartedAt != nil && job.StartedAt.Before(job.SubmittedAt) {
		return fmt.Errorf("worker job startedAt precedes submittedAt")
	}
	if job.HeartbeatAt != nil && job.HeartbeatAt.Before(job.SubmittedAt) {
		return fmt.Errorf("worker job heartbeatAt precedes submittedAt")
	}
	if job.FinishedAt != nil && job.FinishedAt.Before(job.SubmittedAt) {
		return fmt.Errorf("worker job finishedAt precedes submittedAt")
	}
	if job.StartedAt != nil && job.HeartbeatAt != nil && job.HeartbeatAt.Before(*job.StartedAt) {
		return fmt.Errorf("worker job heartbeatAt precedes startedAt")
	}
	if job.StartedAt != nil && job.FinishedAt != nil && job.FinishedAt.Before(*job.StartedAt) {
		return fmt.Errorf("worker job finishedAt precedes startedAt")
	}
	if job.HeartbeatAt != nil && job.FinishedAt != nil && job.FinishedAt.Before(*job.HeartbeatAt) {
		return fmt.Errorf("worker job finishedAt precedes heartbeatAt")
	}
	switch job.State {
	case JobStateQueued:
		if job.StartedAt != nil || job.HeartbeatAt != nil || job.FinishedAt != nil {
			return fmt.Errorf("worker job queued state has lifecycle progress timestamps")
		}
	case JobStateRunning:
		if job.StartedAt == nil {
			return fmt.Errorf("worker job running state requires startedAt")
		}
		if job.FinishedAt != nil {
			return fmt.Errorf("worker job running state has finishedAt")
		}
	default:
		if job.FinishedAt == nil {
			return fmt.Errorf("worker job terminal state requires finishedAt")
		}
		if (job.State == JobStateSucceeded || job.State == JobStateFailed) && job.StartedAt == nil {
			return fmt.Errorf("worker job %s state requires startedAt", job.State)
		}
	}
	return nil
}

// Validate checks a bounded log response.
func (resp JobLogsResponse) Validate() error {
	if err := validateJobContractVersion(resp.ContractVersion); err != nil {
		return err
	}
	if err := validateJobID(resp.JobID); err != nil {
		return err
	}
	var previous uint64
	for i, record := range resp.Records {
		if record.Cursor == 0 || (i > 0 && record.Cursor <= previous) {
			return fmt.Errorf("worker job log record cursor is invalid")
		}
		if record.Stream != JobLogStreamStdout && record.Stream != JobLogStreamStderr {
			return fmt.Errorf("worker job log record stream %q is unsupported", record.Stream)
		}
		if record.Timestamp.IsZero() {
			return fmt.Errorf("worker job log record timestamp is required")
		}
		if int64(len([]byte(record.Data))) > DefaultJobLogRecordBytes {
			return fmt.Errorf("worker job log record exceeds maximum size")
		}
		previous = record.Cursor
	}
	if previous > resp.NextCursor {
		return fmt.Errorf("worker job log nextCursor precedes returned records")
	}
	return nil
}

func validateJobContractVersion(version string) error {
	if strings.TrimSpace(version) == "" {
		version = JobContractVersion
	}
	if version != JobContractVersion {
		return fmt.Errorf("worker job contract version %q is unsupported", version)
	}
	return nil
}

func defaultJobContractVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return JobContractVersion
	}
	return strings.TrimSpace(version)
}

func validateJobID(jobID string) error {
	if !validJobSafeID(jobID) {
		return fmt.Errorf("worker job jobId is invalid")
	}
	return nil
}

func validJobSafeID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "." && value != ".." && jobSafeIDPattern.MatchString(value)
}

func validJobState(state string) bool {
	switch state {
	case JobStateQueued,
		JobStateRunning,
		JobStateSucceeded,
		JobStateFailed,
		JobStateCanceled,
		JobStateInterrupted,
		JobStateUnknown:
		return true
	default:
		return false
	}
}

func jobStateTerminal(state string) bool {
	switch state {
	case JobStateSucceeded, JobStateFailed, JobStateCanceled, JobStateInterrupted, JobStateUnknown:
		return true
	default:
		return false
	}
}
