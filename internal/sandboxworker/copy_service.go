package sandboxworker

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// CopyInResponse copies a bounded JSON payload into a target through a
// registered runtime driver.
func (service *Service) CopyInResponse(ctx context.Context, requestID, driverID string, req CopyInRequest) Response {
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationCopyIn, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker copy_in request: %v", err))
	}

	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return copyProtocolErrorResponse(ctx, requestID, OperationCopyIn, err)
	}

	payload, err := decodeWorkerCopyPayload(req.Payload)
	if err != nil {
		return protocolErrorResponse(requestID, OperationCopyIn, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker copy_in request: %v", err))
	}
	sourcePath, cleanup, err := writeWorkerCopyTempFile(payload)
	if err != nil {
		return protocolErrorResponse(requestID, OperationCopyIn, ErrorCodeDriverFailed, fmt.Sprintf("stage worker copy_in payload: %v", err))
	}
	defer cleanup()

	err = driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          runtimeTargetFromWorkerTarget(req.Target),
		SourcePath:      sourcePath,
		DestinationPath: strings.TrimSpace(req.RemoteDestinationPath),
	})
	if err != nil {
		return copyInErrorResponse(ctx, requestID, err)
	}
	return copyInSuccessResponse(requestID)
}

// CopyOutResponse copies a target file out through a registered runtime driver
// and returns a bounded JSON payload.
func (service *Service) CopyOutResponse(ctx context.Context, requestID, driverID string, req CopyOutRequest) Response {
	if err := req.Validate(); err != nil {
		return protocolErrorResponse(requestID, OperationCopyOut, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker copy_out request: %v", err))
	}

	driver, err := service.lookupDriver(driverID)
	if err != nil {
		return copyProtocolErrorResponse(ctx, requestID, OperationCopyOut, err)
	}

	destinationPath, cleanup, err := workerCopyOutDestinationPath()
	if err != nil {
		return protocolErrorResponse(requestID, OperationCopyOut, ErrorCodeDriverFailed, fmt.Sprintf("stage worker copy_out destination: %v", err))
	}
	defer cleanup()

	err = driver.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          runtimeTargetFromWorkerTarget(req.Target),
		SourcePath:      strings.TrimSpace(req.RemoteSourcePath),
		DestinationPath: destinationPath,
	})
	if err != nil {
		return copyProtocolErrorResponse(ctx, requestID, OperationCopyOut, err)
	}

	payload, limitExceeded, err := boundedWorkerCopyOutPayload(destinationPath, req.MaxPayloadBytes)
	if err != nil {
		return protocolErrorResponse(requestID, OperationCopyOut, ErrorCodeDriverFailed, fmt.Sprintf("read worker copy_out payload: %v", err))
	}
	return copyOutSuccessResponse(requestID, payload, limitExceeded)
}

func copyInSuccessResponse(requestID string) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationCopyIn,
		OK:              true,
		CopyIn: &CopyInResponse{
			Status: CopyStatusCompleted,
		},
	}
}

func copyInErrorResponse(ctx context.Context, requestID string, err error) Response {
	if protocolResp, ok := copyProtocolErrorResponseIfNeeded(ctx, requestID, OperationCopyIn, err); ok {
		return protocolResp
	}
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationCopyIn,
		OK:              true,
		CopyIn: &CopyInResponse{
			Status: CopyStatusFailed,
			Error: &Error{
				Code:    ErrorCodeDriverFailed,
				Message: sanitizeProtocolErrorDetail(fmt.Sprintf("runtime driver request failed: %v", err)),
			},
		},
	}
}

func copyOutSuccessResponse(requestID string, payload CopyFilePayload, limitExceeded bool) Response {
	copyOut := &CopyOutResponse{
		Payload:       &payload,
		Truncated:     limitExceeded,
		LimitExceeded: limitExceeded,
	}
	if limitExceeded {
		copyOut.Error = &Error{
			Code:    ErrorCodeDriverFailed,
			Message: "copy_out payload exceeded requested limit and was truncated",
		}
	}
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationCopyOut,
		OK:              true,
		CopyOut:         copyOut,
	}
}

func copyProtocolErrorResponse(ctx context.Context, requestID, operation string, err error) Response {
	if resp, ok := copyProtocolErrorResponseIfNeeded(ctx, requestID, operation, err); ok {
		return resp
	}
	if err == nil {
		err = fmt.Errorf("runtime driver request failed")
	}
	return protocolErrorResponse(requestID, operation, ErrorCodeDriverFailed, fmt.Sprintf("runtime driver request failed: %v", err))
}

func copyProtocolErrorResponseIfNeeded(ctx context.Context, requestID, operation string, err error) (Response, bool) {
	if err == nil {
		return Response{}, false
	}
	if resp, ok := contextErrorResponse(ctx, Request{RequestID: requestID, Operation: operation}); ok {
		return resp, true
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocolErrorResponse(requestID, operation, ErrorCodeRequestTimeout, "worker request timed out"), true
	case errors.Is(err, context.Canceled):
		return protocolErrorResponse(requestID, operation, ErrorCodeRequestCanceled, "worker request canceled"), true
	case errors.Is(err, ErrWorkerOperationUnsupported):
		return protocolErrorResponse(requestID, operation, ErrorCodeUnsupportedOp, fmt.Sprintf("worker operation %q is not supported by this worker service", operation)), true
	case errors.Is(err, ErrDriverNotFound):
		return protocolErrorResponse(requestID, operation, ErrorCodeDriverNotFound, err.Error()), true
	case errors.Is(err, ErrDriverIDRequired):
		return protocolErrorResponse(requestID, operation, ErrorCodeMalformedRequest, err.Error()), true
	default:
		return Response{}, false
	}
}

func decodeWorkerCopyPayload(payload CopyFilePayload) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, workerIOValidationError("copy_in payload data is not valid %s", CopyPayloadEncodingBase64)
	}
	if int64(len(decoded)) != payload.SizeBytes {
		return nil, workerIOValidationError("copy_in payload sizeBytes %d does not match decoded data size %d bytes", payload.SizeBytes, len(decoded))
	}
	return decoded, nil
}

func writeWorkerCopyTempFile(payload []byte) (string, func(), error) {
	file, err := os.CreateTemp("", "hal-worker-copy-in-*")
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	cleanup := func() {
		_ = os.Remove(path)
	}

	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func workerCopyOutDestinationPath() (string, func(), error) {
	dir, err := os.MkdirTemp("", "hal-worker-copy-out-*")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "payload"), func() {
		_ = os.RemoveAll(dir)
	}, nil
}

func boundedWorkerCopyOutPayload(path string, limit int64) (CopyFilePayload, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return CopyFilePayload{}, false, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return CopyFilePayload{}, false, err
	}
	limitExceeded := int64(len(data)) > limit
	if limitExceeded {
		data = data[:int(limit)]
	}
	return copyPayloadFromBytes(data, limit), limitExceeded, nil
}

func copyPayloadFromBytes(data []byte, limit int64) CopyFilePayload {
	return CopyFilePayload{
		Data:       base64.StdEncoding.EncodeToString(data),
		Encoding:   CopyPayloadEncodingBase64,
		SizeBytes:  int64(len(data)),
		LimitBytes: limit,
	}
}
