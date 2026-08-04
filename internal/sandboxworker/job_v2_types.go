package sandboxworker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	JobContractVersionV2 = "sandboxjob-v2"

	OperationJobStartV2   = "job_start_v2"
	OperationJobResolveV2 = "job_resolve_v2"
	OperationJobStatusV2  = "job_status_v2"
	OperationJobLogsV2    = "job_logs_v2"
	OperationJobCancelV2  = "job_cancel_v2"
)

type JobCredentialBindingV2 struct {
	BindingID         string `json:"bindingId"`
	SourceReferenceID string `json:"sourceReferenceId"`
	Mode              string `json:"mode"`
	ServiceID         string `json:"serviceId,omitempty"`
}

type JobCredentialIntentV2 struct {
	ProductionCredentialsRequested bool                     `json:"productionCredentialsRequested"`
	PlanID                         string                   `json:"planId,omitempty"`
	AdmissionGrantID               string                   `json:"admissionGrantId,omitempty"`
	AdmissionGrantRevision         uint64                   `json:"admissionGrantRevision,omitempty"`
	TemplatePolicyID               string                   `json:"templatePolicyId,omitempty"`
	WorkspacePolicyID              string                   `json:"workspacePolicyId,omitempty"`
	SourceReferenceIDs             []string                 `json:"sourceReferenceIds,omitempty"`
	Bindings                       []JobCredentialBindingV2 `json:"bindings,omitempty"`
}

type JobStartRequestV2 struct {
	ContractVersion                string                   `json:"contractVersion"`
	SubmissionID                   string                   `json:"submissionId"`
	Exec                           ExecRequest              `json:"exec"`
	ProductionCredentialsRequested bool                     `json:"productionCredentialsRequested"`
	PlanID                         string                   `json:"planId,omitempty"`
	AdmissionGrantID               string                   `json:"admissionGrantId,omitempty"`
	AdmissionGrantRevision         uint64                   `json:"admissionGrantRevision,omitempty"`
	TemplatePolicyID               string                   `json:"templatePolicyId,omitempty"`
	WorkspacePolicyID              string                   `json:"workspacePolicyId,omitempty"`
	SourceReferenceIDs             []string                 `json:"sourceReferenceIds,omitempty"`
	Bindings                       []JobCredentialBindingV2 `json:"bindings,omitempty"`
}

type JobResolveRequestV2 struct {
	ContractVersion string `json:"contractVersion"`
	SubmissionID    string `json:"submissionId"`
}

type JobStatusRequestV2 struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
}

type JobLogsRequestV2 struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
	Cursor          uint64 `json:"cursor"`
	LimitBytes      int64  `json:"limitBytes"`
}

type JobCancelRequestV2 struct {
	ContractVersion string `json:"contractVersion"`
	JobID           string `json:"jobId"`
}

type JobLogsResponseV2 struct {
	ContractVersion string         `json:"contractVersion"`
	JobID           string         `json:"jobId"`
	Records         []JobLogRecord `json:"records,omitempty"`
	NextCursor      uint64         `json:"nextCursor"`
	OldestCursor    uint64         `json:"oldestCursor,omitempty"`
	Truncated       bool           `json:"truncated,omitempty"`
}

type JobV2 struct {
	ContractVersion  string                `json:"contractVersion"`
	ID               string                `json:"jobId"`
	SubmissionKey    string                `json:"submissionKey,omitempty"`
	WorkerID         string                `json:"workerId"`
	HostID           string                `json:"hostId,omitempty"`
	RuntimeDriver    string                `json:"runtimeDriver"`
	RuntimeID        string                `json:"runtimeId,omitempty"`
	State            string                `json:"state"`
	SubmittedAt      time.Time             `json:"submittedAt"`
	StartedAt        *time.Time            `json:"startedAt,omitempty"`
	HeartbeatAt      *time.Time            `json:"heartbeatAt,omitempty"`
	FinishedAt       *time.Time            `json:"finishedAt,omitempty"`
	LogCursor        uint64                `json:"logCursor"`
	LogTruncated     bool                  `json:"logTruncated,omitempty"`
	StdoutTruncated  bool                  `json:"stdoutTruncated,omitempty"`
	StderrTruncated  bool                  `json:"stderrTruncated,omitempty"`
	ExitCode         *int                  `json:"exitCode,omitempty"`
	FailureCode      string                `json:"failureCode,omitempty"`
	CancelRequested  bool                  `json:"cancelRequested,omitempty"`
	CredentialIntent JobCredentialIntentV2 `json:"credentialIntent"`
}

func (request JobStartRequestV2) Validate() error {
	if request.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", request.ContractVersion)
	}
	if !validWorkerV2SafeID(request.SubmissionID) {
		return fmt.Errorf("worker job submissionId is invalid")
	}
	for _, value := range request.Exec.Env {
		if int64(len([]byte(value))) > MaxExecStdinBytes {
			return fmt.Errorf("worker job environment value exceeds redaction limit")
		}
	}
	if err := validateJobExecRequestV2(request.Exec); err != nil {
		return err
	}
	return request.credentialIntent().Validate()
}

func validateJobExecRequestV2(request ExecRequest) error {
	if strings.TrimSpace(request.OperationID) == "" {
		return fmt.Errorf("worker job exec operationId is required")
	}
	if err := request.Target.Validate(); err != nil {
		return fmt.Errorf("worker job exec target is invalid")
	}
	if len(request.Args) == 0 || strings.TrimSpace(request.Args[0]) == "" {
		return fmt.Errorf("worker job exec args are required")
	}
	if request.StdoutLimitBytes <= 0 || request.StdoutLimitBytes > MaxExecStdoutCaptureBytes || request.StderrLimitBytes <= 0 || request.StderrLimitBytes > MaxExecStderrCaptureBytes {
		return fmt.Errorf("worker job exec output limit is invalid")
	}
	if request.Stdin == nil {
		return nil
	}
	stdin := request.Stdin
	if stdin.Encoding != CopyPayloadEncodingBase64 || stdin.SizeBytes <= 0 || stdin.LimitBytes <= 0 || stdin.SizeBytes > stdin.LimitBytes || stdin.LimitBytes > MaxExecStdinBytes || len(stdin.Data) > 4*int((stdin.LimitBytes+2)/3) {
		return fmt.Errorf("worker job exec stdin is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(stdin.Data)
	if err != nil || int64(len(decoded)) != stdin.SizeBytes {
		return fmt.Errorf("worker job exec stdin is invalid")
	}
	return nil
}

func (request JobResolveRequestV2) Validate() error {
	if request.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", request.ContractVersion)
	}
	if !validWorkerV2SafeID(request.SubmissionID) {
		return fmt.Errorf("worker job submissionId is invalid")
	}
	return nil
}

func (request JobStatusRequestV2) Validate() error {
	if request.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", request.ContractVersion)
	}
	return validateWorkerV2JobID(request.JobID)
}

func (request JobLogsRequestV2) Validate() error {
	if request.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", request.ContractVersion)
	}
	if err := validateWorkerV2JobID(request.JobID); err != nil {
		return err
	}
	if request.LimitBytes < DefaultJobLogRecordBytes || request.LimitBytes > DefaultJobLogReadBytes {
		return fmt.Errorf("worker job log limitBytes must be between %d and %d", DefaultJobLogRecordBytes, DefaultJobLogReadBytes)
	}
	return nil
}

func (request JobCancelRequestV2) Validate() error {
	if request.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", request.ContractVersion)
	}
	return validateWorkerV2JobID(request.JobID)
}

func (intent JobCredentialIntentV2) Validate() error {
	if !intent.ProductionCredentialsRequested {
		if intent.PlanID != "" || intent.AdmissionGrantID != "" || intent.AdmissionGrantRevision != 0 || intent.TemplatePolicyID != "" || intent.WorkspacePolicyID != "" || intent.SourceReferenceIDs != nil || intent.Bindings != nil {
			return fmt.Errorf("worker job credential intent must be absent when production credentials are not requested")
		}
		return nil
	}
	for _, value := range []string{intent.PlanID, intent.AdmissionGrantID, intent.TemplatePolicyID, intent.WorkspacePolicyID} {
		if !validWorkerV2SafeID(value) {
			return fmt.Errorf("worker job credential intent identity is invalid")
		}
	}
	if intent.AdmissionGrantRevision == 0 || len(intent.SourceReferenceIDs) == 0 || len(intent.Bindings) == 0 {
		return fmt.Errorf("worker job credential intent is incomplete")
	}
	sources := make(map[string]bool, len(intent.SourceReferenceIDs))
	bound := make(map[string]bool, len(intent.SourceReferenceIDs))
	for _, source := range intent.SourceReferenceIDs {
		if !validWorkerV2SafeID(source) || sources[source] {
			return fmt.Errorf("worker job credential source identity is invalid")
		}
		sources[source] = true
	}
	bindings := make(map[string]bool, len(intent.Bindings))
	for _, binding := range intent.Bindings {
		if !validWorkerV2SafeID(binding.BindingID) || bindings[binding.BindingID] || !validWorkerV2SafeID(binding.SourceReferenceID) || !sources[binding.SourceReferenceID] {
			return fmt.Errorf("worker job credential binding identity is invalid")
		}
		bindings[binding.BindingID] = true
		bound[binding.SourceReferenceID] = true
		switch binding.Mode {
		case "http_proxy":
			if !validWorkerV2SafeID(binding.ServiceID) {
				return fmt.Errorf("worker job credential binding service identity is invalid")
			}
		case CredentialModeFileTmpfs, CredentialModeSSHAgent:
			if binding.ServiceID != "" {
				return fmt.Errorf("worker job credential binding service identity is invalid")
			}
		default:
			return fmt.Errorf("worker job credential binding mode is unsupported")
		}
	}
	for source := range sources {
		if !bound[source] {
			return fmt.Errorf("worker job credential source is unbound")
		}
	}
	return nil
}

func (request JobStartRequestV2) credentialIntent() JobCredentialIntentV2 {
	return JobCredentialIntentV2{
		ProductionCredentialsRequested: request.ProductionCredentialsRequested,
		PlanID:                         request.PlanID,
		AdmissionGrantID:               request.AdmissionGrantID,
		AdmissionGrantRevision:         request.AdmissionGrantRevision,
		TemplatePolicyID:               request.TemplatePolicyID,
		WorkspacePolicyID:              request.WorkspacePolicyID,
		SourceReferenceIDs:             append([]string(nil), request.SourceReferenceIDs...),
		Bindings:                       append([]JobCredentialBindingV2(nil), request.Bindings...),
	}
}

func (job JobV2) Validate() error {
	if job.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", job.ContractVersion)
	}
	if err := validateWorkerV2JobID(job.ID); err != nil {
		return err
	}
	if !validWorkerV2OpaqueKey(job.SubmissionKey, "submission-v2-") {
		return fmt.Errorf("worker job submissionKey is invalid")
	}
	for _, value := range []string{job.WorkerID, job.RuntimeDriver} {
		if !validWorkerV2SafeID(value) {
			return fmt.Errorf("worker job identity is invalid")
		}
	}
	for _, value := range []string{job.HostID, job.RuntimeID} {
		if value != "" && !validWorkerV2SafeID(value) {
			return fmt.Errorf("worker job identity is invalid")
		}
	}
	if !validWorkerV2JobState(job.State) || job.SubmittedAt.IsZero() {
		return fmt.Errorf("worker job lifecycle is invalid")
	}
	if job.StartedAt != nil && job.StartedAt.Before(job.SubmittedAt) || job.HeartbeatAt != nil && job.HeartbeatAt.Before(job.SubmittedAt) || job.FinishedAt != nil && job.FinishedAt.Before(job.SubmittedAt) {
		return fmt.Errorf("worker job lifecycle is invalid")
	}
	if job.StartedAt != nil && job.HeartbeatAt != nil && job.HeartbeatAt.Before(*job.StartedAt) || job.StartedAt != nil && job.FinishedAt != nil && job.FinishedAt.Before(*job.StartedAt) || job.HeartbeatAt != nil && job.FinishedAt != nil && job.FinishedAt.Before(*job.HeartbeatAt) {
		return fmt.Errorf("worker job lifecycle is invalid")
	}
	switch job.State {
	case "queued":
		if job.StartedAt != nil || job.HeartbeatAt != nil || job.FinishedAt != nil {
			return fmt.Errorf("worker job lifecycle is invalid")
		}
	case "running":
		if job.StartedAt == nil || job.FinishedAt != nil {
			return fmt.Errorf("worker job lifecycle is invalid")
		}
	default:
		if job.FinishedAt == nil || (job.State == "succeeded" || job.State == "failed") && job.StartedAt == nil {
			return fmt.Errorf("worker job lifecycle is invalid")
		}
	}
	if job.FailureCode != "" && !validWorkerV2SafeID(job.FailureCode) {
		return fmt.Errorf("worker job failureCode is invalid")
	}
	return job.CredentialIntent.Validate()
}

func (response JobLogsResponseV2) Validate() error {
	if response.ContractVersion != JobContractVersionV2 {
		return fmt.Errorf("worker job contractVersion %q is unsupported", response.ContractVersion)
	}
	if err := validateWorkerV2JobID(response.JobID); err != nil {
		return err
	}
	previous := uint64(0)
	for index, record := range response.Records {
		if record.Cursor == 0 || index > 0 && record.Cursor <= previous {
			return fmt.Errorf("worker job log record cursor is invalid")
		}
		if record.Stream != JobLogStreamStdout && record.Stream != JobLogStreamStderr {
			return fmt.Errorf("worker job log record stream is unsupported")
		}
		if record.Timestamp.IsZero() || int64(len([]byte(record.Data))) > DefaultJobLogRecordBytes {
			return fmt.Errorf("worker job log record is invalid")
		}
		previous = record.Cursor
	}
	if previous > response.NextCursor {
		return fmt.Errorf("worker job log nextCursor precedes returned records")
	}
	return nil
}

func validWorkerV2SafeID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || current == '.' || current == '_' || current == '-' {
			continue
		}
		return false
	}
	return true
}

func validateWorkerV2JobID(jobID string) error {
	if !validJobSafeID(jobID) {
		return fmt.Errorf("worker job jobId is invalid")
	}
	return nil
}

func validWorkerV2JobState(state string) bool {
	switch state {
	case "queued", "running", "succeeded", "failed", "canceled", "interrupted", "unknown":
		return true
	default:
		return false
	}
}

func validWorkerV2OpaqueKey(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	digest := strings.TrimPrefix(value, prefix)
	if digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}
