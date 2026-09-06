package sandboxworker

import (
	"context"
	"errors"
	"sort"
	"strings"
)

var ErrCredentialWorkerProtocolUnsupported = errors.New("worker credential protocol is unsupported")

func (client *Client) JobStartV2(ctx context.Context, driverID string, request JobStartRequestV2) (*JobV2, error) {
	if strings.TrimSpace(request.ContractVersion) == "" {
		request.ContractVersion = JobContractVersionV2
	}
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobStartV2, DriverID: driverID, JobStartV2: &request})
	if err != nil {
		return nil, err
	}
	return clientJobResponseV2(Request{Operation: OperationJobStartV2, DriverID: driverID, JobStartV2: &request}, response)
}

func (client *Client) JobResolveV2(ctx context.Context, request JobResolveRequestV2) (*JobV2, error) {
	if strings.TrimSpace(request.ContractVersion) == "" {
		request.ContractVersion = JobContractVersionV2
	}
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobResolveV2, JobResolveV2: &request})
	if err != nil {
		return nil, err
	}
	return clientJobResponseV2(Request{Operation: OperationJobResolveV2, JobResolveV2: &request}, response)
}

func (client *Client) JobStatusV2(ctx context.Context, request JobStatusRequestV2) (*JobV2, error) {
	if strings.TrimSpace(request.ContractVersion) == "" {
		request.ContractVersion = JobContractVersionV2
	}
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobStatusV2, JobStatusV2: &request})
	if err != nil {
		return nil, err
	}
	return clientJobResponseV2(Request{Operation: OperationJobStatusV2, JobStatusV2: &request}, response)
}

func (client *Client) JobLogsV2(ctx context.Context, request JobLogsRequestV2) (*JobLogsResponseV2, error) {
	if strings.TrimSpace(request.ContractVersion) == "" {
		request.ContractVersion = JobContractVersionV2
	}
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobLogsV2, JobLogsV2: &request})
	if err != nil {
		return nil, err
	}
	if response.JobLogsV2 == nil {
		return nil, malformedClientResponseError(OperationJobLogsV2, "worker response did not include jobLogsV2 payload")
	}
	logs := *response.JobLogsV2
	logs.Records = append([]JobLogRecord(nil), response.JobLogsV2.Records...)
	if err := validateClientJobLogsV2(request, logs); err != nil {
		return nil, malformedClientResponseError(OperationJobLogsV2, "worker job_logs_v2 response identity is invalid")
	}
	return &logs, nil
}

func (client *Client) JobCancelV2(ctx context.Context, request JobCancelRequestV2) (*JobV2, error) {
	if strings.TrimSpace(request.ContractVersion) == "" {
		request.ContractVersion = JobContractVersionV2
	}
	response, err := client.roundTrip(ctx, Request{Operation: OperationJobCancelV2, JobCancelV2: &request})
	if err != nil {
		return nil, err
	}
	return clientJobResponseV2(Request{Operation: OperationJobCancelV2, JobCancelV2: &request}, response)
}

func clientJobResponseV2(request Request, response Response) (*JobV2, error) {
	if response.JobV2 == nil {
		return nil, malformedClientResponseError(request.Operation, "worker response did not include jobV2 payload")
	}
	job := cloneJobV2(*response.JobV2)
	if err := validateClientJobV2Identity(request, job); err != nil {
		return nil, malformedClientResponseError(request.Operation, "worker jobV2 response identity is invalid")
	}
	return &job, nil
}

func validateClientJobV2Identity(request Request, job JobV2) error {
	switch request.Operation {
	case OperationJobStartV2:
		if request.JobStartV2 == nil || job.RuntimeDriver != strings.TrimSpace(request.DriverID) || job.RuntimeID != strings.TrimSpace(request.JobStartV2.Exec.Target.Runtime.RuntimeID) {
			return errors.New("worker job_start_v2 identity did not match request")
		}
		if !equivalentCredentialIntentV2(request.JobStartV2.credentialIntent(), job.CredentialIntent) {
			return errors.New("worker job_start_v2 credential intent did not match request")
		}
	case OperationJobResolveV2:
		if !validWorkerV2OpaqueKey(job.SubmissionKey, "submission-v2-") {
			return errors.New("worker job_resolve_v2 submission identity is invalid")
		}
	case OperationJobStatusV2:
		if request.JobStatusV2 == nil || job.ID != request.JobStatusV2.JobID {
			return errors.New("worker job_status_v2 jobId did not match request")
		}
	case OperationJobCancelV2:
		if request.JobCancelV2 == nil || job.ID != request.JobCancelV2.JobID {
			return errors.New("worker job_cancel_v2 jobId did not match request")
		}
	}
	return nil
}

func equivalentCredentialIntentV2(left, right JobCredentialIntentV2) bool {
	left.SourceReferenceIDs = append([]string(nil), left.SourceReferenceIDs...)
	right.SourceReferenceIDs = append([]string(nil), right.SourceReferenceIDs...)
	left.Bindings = append([]JobCredentialBindingV2(nil), left.Bindings...)
	right.Bindings = append([]JobCredentialBindingV2(nil), right.Bindings...)
	sort.Strings(left.SourceReferenceIDs)
	sort.Strings(right.SourceReferenceIDs)
	sortCredentialBindingsV2(left.Bindings)
	sortCredentialBindingsV2(right.Bindings)
	if left.ProductionCredentialsRequested != right.ProductionCredentialsRequested || left.PlanID != right.PlanID || left.AdmissionGrantID != right.AdmissionGrantID || left.AdmissionGrantRevision != right.AdmissionGrantRevision || left.TemplatePolicyID != right.TemplatePolicyID || left.WorkspacePolicyID != right.WorkspacePolicyID || len(left.SourceReferenceIDs) != len(right.SourceReferenceIDs) || len(left.Bindings) != len(right.Bindings) {
		return false
	}
	for index := range left.SourceReferenceIDs {
		if left.SourceReferenceIDs[index] != right.SourceReferenceIDs[index] {
			return false
		}
	}
	for index := range left.Bindings {
		if left.Bindings[index] != right.Bindings[index] {
			return false
		}
	}
	return true
}

func validateClientJobLogsV2(request JobLogsRequestV2, response JobLogsResponseV2) error {
	if response.JobID != request.JobID {
		return errors.New("worker job_logs_v2 jobId did not match request")
	}
	var recordsSize int64
	for _, record := range response.Records {
		recordsSize += int64(len([]byte(record.Data)))
	}
	if recordsSize > request.LimitBytes {
		return errors.New("worker job_logs_v2 records exceed requested limit")
	}
	if response.NextCursor < request.Cursor {
		return errors.New("worker job_logs_v2 nextCursor precedes requested cursor")
	}
	previous := request.Cursor
	gap := false
	for _, record := range response.Records {
		if record.Cursor <= previous {
			return errors.New("worker job_logs_v2 record cursor does not follow requested cursor")
		}
		if record.Cursor-previous > 1 {
			gap = true
		}
		previous = record.Cursor
	}
	if response.NextCursor < previous {
		return errors.New("worker job_logs_v2 nextCursor precedes returned records")
	}
	if response.NextCursor > previous {
		gap = true
	}
	if gap && !response.Truncated {
		return errors.New("worker job_logs_v2 cursor gap requires truncation marker")
	}
	return nil
}

func exactCredentialWorkerProtocolUnsupported(request Request, response Response) bool {
	if !isWorkerV2Operation(request.Operation) || response.ProtocolVersion != ProtocolVersion || response.RequestID == "" || response.RequestID != request.RequestID || response.OK || response.Error == nil || workerResponseHasPayload(response) {
		return false
	}
	if response.Operation == OperationProtocolError {
		return response.Error.Code == ErrorCodeMalformedRequest && response.Error.Message == "malformed worker request: worker request operation \""+request.Operation+"\" is unsupported"
	}
	return response.Operation == request.Operation && response.Error.Code == ErrorCodeUnsupportedOp && response.Error.Message == "worker operation \""+request.Operation+"\" is not supported by this worker service"
}

func workerResponseHasPayload(response Response) bool {
	return response.Status != nil || response.Capabilities != nil || response.Target != nil || response.Exec != nil || response.CopyIn != nil || response.CopyOut != nil || response.Job != nil || response.JobLogs != nil || response.JobV2 != nil || response.JobLogsV2 != nil
}
