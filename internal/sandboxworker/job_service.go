package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// JobStartResponse durably accepts an async exec request before returning.
func (service *Service) JobStartResponse(ctx context.Context, requestID, driverID string, req JobStartRequest) Response {
	if service == nil || service.jobs == nil {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobStart, DriverID: driverID})
	}
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobStart, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker job start request: %v", err))
	}
	if job, exists, err := service.jobs.existingSubmission(req, driverID); err != nil {
		return jobOperationErrorResponse(requestID, OperationJobStart, err)
	} else if exists {
		return jobSuccessResponse(requestID, OperationJobStart, job)
	}
	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobStart, err)
	}
	if !driverSupportsJobExecution(driver) {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobStart, DriverID: driverID})
	}
	job, err := service.jobs.start(ctx, driverID, driver, req)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobStart, err)
	}
	return jobSuccessResponse(requestID, OperationJobStart, job)
}

// JobResolveResponse returns an already admitted job by its caller-stable
// submission identity without starting or reconstructing work.
func (service *Service) JobResolveResponse(requestID string, req JobResolveRequest) Response {
	if service == nil || service.jobs == nil {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobResolve})
	}
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobResolve, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker job resolve request: %v", err))
	}
	job, err := service.jobs.resolveSubmission(req)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobResolve, err)
	}
	return jobSuccessResponse(requestID, OperationJobResolve, job)
}

// JobStatusResponse returns the latest durable job snapshot.
func (service *Service) JobStatusResponse(requestID string, req JobStatusRequest) Response {
	if service == nil || service.jobs == nil {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobStatus})
	}
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobStatus, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker job status request: %v", err))
	}
	job, err := service.jobs.status(req.JobID)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobStatus, err)
	}
	return jobSuccessResponse(requestID, OperationJobStatus, job)
}

// JobLogsResponse returns one bounded cursor page from the redacted log spool.
func (service *Service) JobLogsResponse(requestID string, req JobLogsRequest) Response {
	if service == nil || service.jobs == nil {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobLogs})
	}
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobLogs, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker job logs request: %v", err))
	}
	logs, err := service.jobs.logs(req)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobLogs, err)
	}
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationJobLogs,
		OK:              true,
		JobLogs:         &logs,
	}
}

// JobCancelResponse accepts cancellation without overriding a terminal state.
func (service *Service) JobCancelResponse(requestID string, req JobCancelRequest) Response {
	if service == nil || service.jobs == nil {
		return unsupportedOperationResponse(Request{RequestID: requestID, Operation: OperationJobCancel})
	}
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationJobCancel, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker job cancel request: %v", err))
	}
	job, err := service.jobs.cancelJob(req.JobID)
	if err != nil {
		return jobOperationErrorResponse(requestID, OperationJobCancel, err)
	}
	return jobSuccessResponse(requestID, OperationJobCancel, job)
}

func jobSuccessResponse(requestID, operation string, job Job) Response {
	snapshot := cloneJob(job)
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       operation,
		OK:              true,
		Job:             &snapshot,
	}
}

func jobOperationErrorResponse(requestID, operation string, err error) Response {
	switch {
	case errors.Is(err, errJobNotFound):
		return protocolErrorResponse(requestID, operation, ErrorCodeJobNotFound, "worker job was not found")
	case errors.Is(err, errJobCapacityExceeded):
		return protocolErrorResponse(requestID, operation, ErrorCodeCapacityExceeded, "worker job capacity is exhausted")
	case errors.Is(err, errJobSubmissionConflict):
		return protocolErrorResponse(requestID, operation, ErrorCodeSubmissionConflict, "worker job submission identity conflicts with accepted request")
	case errors.Is(err, ErrDriverNotFound):
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverNotFound, err.Error())
	case errors.Is(err, ErrDriverIDRequired):
		return protocolErrorResponse(requestID, operation, ErrorCodeMalformedRequest, err.Error())
	default:
		return protocolErrorResponse(requestID, operation, ErrorCodeInternal, "worker job operation failed")
	}
}
