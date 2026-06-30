package sandboxworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// ExecResponse runs a bounded command through a registered runtime driver.
func (service *Service) ExecResponse(ctx context.Context, requestID, driverID string, req ExecRequest) Response {
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker exec request: %v", err))
	}

	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return execErrorResponse(ctx, requestID, err, nil, nil, nil)
	}

	stdout := newBoundedExecCapture(req.StdoutLimitBytes)
	stderr := newBoundedExecCapture(req.StderrLimitBytes)
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  runtimeTargetFromWorkerTarget(req.Target),
		Args:    cloneStringSlice(req.Args),
		Stdout:  stdout,
		Stderr:  stderr,
		Stdin:   execStdinReader(req.Stdin),
		Env:     cloneStringMap(req.Env),
		WorkDir: strings.TrimSpace(req.WorkDir),
	})
	if err != nil {
		return execErrorResponse(ctx, requestID, err, result, stdout, stderr)
	}
	if result == nil {
		return execErrorResponse(ctx, requestID, fmt.Errorf("runtime driver returned no exec result"), nil, stdout, stderr)
	}
	return execSuccessResponse(requestID, result.ExitCode, stdout, stderr, nil)
}

func execSuccessResponse(requestID string, exitCode int, stdout, stderr *boundedExecCapture, commandErr *Error) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationExec,
		OK:              true,
		Exec: &ExecResponse{
			ExitCode: exitCode,
			Stdout:   stdout.Payload(),
			Stderr:   stderr.Payload(),
			Error:    commandErr,
		},
	}
}

func execErrorResponse(ctx context.Context, requestID string, err error, result *sandboxruntime.ExecResult, stdout, stderr *boundedExecCapture) Response {
	if err == nil {
		err = fmt.Errorf("runtime driver exec failed")
	}
	if resp, ok := contextErrorResponse(ctx, Request{RequestID: requestID, Operation: OperationExec}); ok {
		return resp
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeRequestTimeout, "worker request timed out")
	case errors.Is(err, context.Canceled):
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeRequestCanceled, "worker request canceled")
	case errors.Is(err, ErrWorkerOperationUnsupported):
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeUnsupportedOp, fmt.Sprintf("worker operation %q is not supported by this worker service", OperationExec))
	case errors.Is(err, ErrDriverNotFound):
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeDriverNotFound, err.Error())
	case errors.Is(err, ErrDriverIDRequired):
		return protocolErrorResponse(requestID, OperationExec, ErrorCodeMalformedRequest, err.Error())
	}

	if result != nil && stdout != nil && stderr != nil {
		return execSuccessResponse(requestID, result.ExitCode, stdout, stderr, &Error{
			Code:    ErrorCodeDriverFailed,
			Message: sanitizeProtocolErrorDetail(fmt.Sprintf("runtime driver request failed: %v", err)),
		})
	}
	return protocolErrorResponse(requestID, OperationExec, ErrorCodeDriverFailed, fmt.Sprintf("runtime driver request failed: %v", err))
}

func execStdinReader(payload *ExecStdinPayload) io.Reader {
	if payload == nil {
		return nil
	}
	return strings.NewReader(payload.Data)
}

type boundedExecCapture struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func newBoundedExecCapture(limit int64) *boundedExecCapture {
	return &boundedExecCapture{limit: limit}
}

func (capture *boundedExecCapture) Write(p []byte) (int, error) {
	if capture == nil {
		return len(p), nil
	}
	remaining := capture.limit - int64(capture.buf.Len())
	if remaining <= 0 {
		if len(p) > 0 {
			capture.truncated = true
		}
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = capture.buf.Write(p[:remaining])
		capture.truncated = true
		return len(p), nil
	}
	_, _ = capture.buf.Write(p)
	return len(p), nil
}

func (capture *boundedExecCapture) Payload() ExecOutputPayload {
	if capture == nil {
		return ExecOutputPayload{}
	}
	data := capture.buf.String()
	return ExecOutputPayload{
		Data:       data,
		SizeBytes:  int64(len([]byte(data))),
		LimitBytes: capture.limit,
		Truncated:  capture.truncated,
	}
}
