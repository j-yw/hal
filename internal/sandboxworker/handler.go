package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// HandleRequest dispatches validated worker protocol requests through the
// service-backed operation set.
func (service *Service) HandleRequest(ctx context.Context, req Request) Response {
	if service == nil {
		return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeInternal, "worker service is not configured")
	}
	if resp, ok := contextErrorResponse(ctx, req); ok {
		return resp
	}
	if !service.supportsRequestOperation(req.Operation, req.DriverID) {
		return unsupportedOperationResponse(req)
	}

	switch req.Operation {
	case OperationStatus:
		return service.StatusResponse(req.RequestID)
	case OperationCapabilities:
		return service.CapabilitiesResponse(req.RequestID)
	case OperationCreate:
		if req.Create == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request create payload is required")
		}
		return service.CreateResponse(ctx, req.RequestID, req.DriverID, *req.Create)
	case OperationStart:
		if req.Lifecycle == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request lifecycle payload is required")
		}
		return service.StartResponse(ctx, req.RequestID, req.DriverID, *req.Lifecycle)
	case OperationStop:
		if req.Lifecycle == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request lifecycle payload is required")
		}
		return service.StopResponse(ctx, req.RequestID, req.DriverID, *req.Lifecycle)
	case OperationDelete:
		if req.Lifecycle == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request lifecycle payload is required")
		}
		return service.DeleteResponse(ctx, req.RequestID, req.DriverID, *req.Lifecycle)
	case OperationInspect:
		if req.Inspect == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request inspect payload is required")
		}
		return service.InspectResponse(ctx, req.RequestID, req.DriverID, *req.Inspect)
	case OperationExec:
		if req.Exec == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request exec payload is required")
		}
		return service.ExecResponse(ctx, req.RequestID, req.DriverID, *req.Exec)
	case OperationCopyIn:
		if req.CopyIn == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request copyIn payload is required")
		}
		return service.CopyInResponse(ctx, req.RequestID, req.DriverID, *req.CopyIn)
	case OperationCopyOut:
		if req.CopyOut == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request copyOut payload is required")
		}
		return service.CopyOutResponse(ctx, req.RequestID, req.DriverID, *req.CopyOut)
	case OperationJobStart:
		if req.JobStart == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request jobStart payload is required")
		}
		return service.JobStartResponse(ctx, req.RequestID, req.DriverID, *req.JobStart)
	case OperationJobResolve:
		if req.JobResolve == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request jobResolve payload is required")
		}
		return service.JobResolveResponse(req.RequestID, *req.JobResolve)
	case OperationJobStatus:
		if req.JobStatus == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request jobStatus payload is required")
		}
		return service.JobStatusResponse(req.RequestID, *req.JobStatus)
	case OperationJobLogs:
		if req.JobLogs == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request jobLogs payload is required")
		}
		return service.JobLogsResponse(req.RequestID, *req.JobLogs)
	case OperationJobCancel:
		if req.JobCancel == nil {
			return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, "worker request jobCancel payload is required")
		}
		return service.JobCancelResponse(req.RequestID, *req.JobCancel)
	default:
		return unsupportedOperationResponse(req)
	}
}

func contextErrorResponse(ctx context.Context, req Request) (Response, bool) {
	if ctx == nil {
		return Response{}, false
	}
	err := ctx.Err()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeRequestTimeout, "worker request timed out"), true
	case errors.Is(err, context.Canceled):
		return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeRequestCanceled, "worker request canceled"), true
	default:
		return Response{}, false
	}
}

func unsupportedOperationResponse(req Request) Response {
	operation := strings.TrimSpace(req.Operation)
	if !validOperation(operation) {
		return protocolErrorResponse(req.RequestID, OperationProtocolError, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker request: worker request operation %q is unsupported", req.Operation))
	}
	return protocolErrorResponse(req.RequestID, operation, ErrorCodeUnsupportedOp, fmt.Sprintf("worker operation %q is not supported by this worker service", operation))
}
