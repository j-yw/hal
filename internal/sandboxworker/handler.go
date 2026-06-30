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

	switch req.Operation {
	case OperationStatus:
		return service.StatusResponse(req.RequestID)
	case OperationCapabilities:
		return service.CapabilitiesResponse(req.RequestID)
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
