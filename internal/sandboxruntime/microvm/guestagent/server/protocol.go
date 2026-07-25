package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// Handle strictly decodes and dispatches one bounded protocol request.
func (server *Server) Handle(ctx context.Context, request Request) Response {
	if server == nil {
		return encodeStandaloneError(guestagent.ErrorCodeInternalFailure, "", "server")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if int64(len(request.Encoded)) > server.limits.MaxRequestBytes {
		return server.errorResponse(guestagent.ErrorCodeOversizedRequest, "", "request")
	}
	if err := strictRequestObject(request.Encoded); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, "", "request")
	}

	var header struct {
		ProtocolVersion guestagent.ProtocolVersion `json:"protocolVersion"`
		Operation       guestagent.Operation       `json:"operation"`
	}
	if err := json.Unmarshal(request.Encoded, &header); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, "", "request")
	}
	operation := supportedOperation(header.Operation)
	if !requestRootFieldsKnown(request.Encoded) {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, operation, "request")
	}
	if header.ProtocolVersion == "" {
		return server.errorResponse(guestagent.ErrorCodeMissingRequiredField, operation, "protocolVersion")
	}
	if header.ProtocolVersion != guestagent.ProtocolVersionV1 {
		return server.errorResponse(guestagent.ErrorCodeUnsupportedProtocolVersion, operation, "protocolVersion")
	}
	if header.Operation == "" {
		return server.errorResponse(guestagent.ErrorCodeMissingRequiredField, "", "operation")
	}
	if operation == "" {
		return server.errorResponse(guestagent.ErrorCodeUnknownOperation, "", "operation")
	}

	switch operation {
	case guestagent.OperationReadiness:
		return server.handleReadiness(ctx, request.Encoded)
	case guestagent.OperationExec:
		return server.handleExec(ctx, request.Encoded)
	case guestagent.OperationCopyIn:
		return server.handleCopyIn(ctx, request.Encoded)
	case guestagent.OperationCopyOut:
		return server.handleCopyOut(ctx, request.Encoded)
	default:
		return server.errorResponse(guestagent.ErrorCodeUnknownOperation, "", "operation")
	}
}

func (server *Server) handleReadiness(ctx context.Context, encoded []byte) Response {
	var request guestagent.ReadinessRequest
	if err := strictDecodeRequest(encoded, &request); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, guestagent.OperationReadiness, "request")
	}
	if err := guestagent.ValidateReadinessRequest(request); err != nil {
		return server.validationErrorResponse(err, guestagent.OperationReadiness)
	}
	callCtx, cancel := server.contextWithTiming(ctx, request.Timing)
	defer cancel()
	backendCtx, release, err := server.beginBackendCall(callCtx, false)
	if err != nil {
		if errors.Is(err, errServerNotReady) {
			return server.readinessResponse(false)
		}
		return server.contextErrorResponse(err, guestagent.OperationReadiness)
	}
	defer release()
	if err := server.backend.Ready(backendCtx); err != nil {
		if backendCtx.Err() != nil {
			return server.contextErrorResponse(backendCtx.Err(), guestagent.OperationReadiness)
		}
		return server.readinessResponse(false)
	}
	if err := backendCtx.Err(); err != nil {
		return server.contextErrorResponse(err, guestagent.OperationReadiness)
	}
	return server.readinessResponse(true)
}

func (server *Server) handleExec(ctx context.Context, encoded []byte) Response {
	var request guestagent.ExecRequest
	if err := strictDecodeRequest(encoded, &request); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, guestagent.OperationExec, "request")
	}
	if err := guestagent.ValidateExecRequest(request); err != nil {
		return server.validationErrorResponse(err, guestagent.OperationExec)
	}
	callCtx, cancel := server.contextWithTiming(ctx, request.Timing)
	defer cancel()
	backendCtx, release, err := server.beginBackendCall(callCtx, true)
	if err != nil {
		return server.admissionErrorResponse(err, guestagent.OperationExec)
	}
	defer release()

	environment, err := server.resolveEnvironment(backendCtx, request.Env)
	if err != nil {
		if backendCtx.Err() != nil {
			return server.contextErrorResponse(backendCtx.Err(), guestagent.OperationExec)
		}
		return server.errorResponse(guestagent.ErrorCodeEnvironmentUnavailable, guestagent.OperationExec, "env")
	}
	stdin, err := decodeExecStdin(request.Stdin)
	if err != nil {
		return server.errorResponse(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationExec, "stdin")
	}
	if int64(len(stdin)) > DefaultExecStdinBytes {
		return server.errorResponse(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationExec, "stdin")
	}
	stdoutLimit := smallerPositive(request.Stdout.MaxBytes, DefaultExecStdoutBytes)
	stderrLimit := smallerPositive(request.Stderr.MaxBytes, DefaultExecStderrBytes)
	result, err := server.backend.Exec(backendCtx, ExecPlan{
		Args:           append([]string(nil), request.Args...),
		Environment:    environment,
		WorkDir:        request.WorkDir,
		Stdin:          stdin,
		StdoutMaxBytes: stdoutLimit,
		StderrMaxBytes: stderrLimit,
	})
	if err != nil {
		if backendCtx.Err() != nil {
			return server.contextErrorResponse(backendCtx.Err(), guestagent.OperationExec)
		}
		return server.backendErrorResponse(err, guestagent.ErrorCodeExecutionFailed, guestagent.OperationExec, "exec")
	}
	if err := backendCtx.Err(); err != nil {
		return server.contextErrorResponse(err, guestagent.OperationExec)
	}
	if result.ExitCode < 0 {
		return server.errorResponse(guestagent.ErrorCodeInternalFailure, guestagent.OperationExec, "exec")
	}
	stdout, stdoutTruncated := boundedResult(result.Stdout, stdoutLimit, result.StdoutTruncated)
	stderr, stderrTruncated := boundedResult(result.Stderr, stderrLimit, result.StderrTruncated)
	return server.encodeResponse(guestagent.ExecResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		ExitCode:        result.ExitCode,
		Stdout:          encodedStream(stdout, stdoutLimit, stdoutTruncated),
		Stderr:          encodedStream(stderr, stderrLimit, stderrTruncated),
	}, guestagent.OperationExec)
}

func (server *Server) handleCopyIn(ctx context.Context, encoded []byte) Response {
	var request guestagent.CopyInRequest
	if err := strictDecodeRequest(encoded, &request); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, guestagent.OperationCopyIn, "request")
	}
	if err := guestagent.ValidateCopyInRequest(request); err != nil {
		return server.validationErrorResponse(err, guestagent.OperationCopyIn)
	}
	callCtx, cancel := server.contextWithTiming(ctx, request.Timing)
	defer cancel()
	backendCtx, release, err := server.beginBackendCall(callCtx, true)
	if err != nil {
		return server.admissionErrorResponse(err, guestagent.OperationCopyIn)
	}
	defer release()

	data, err := base64.StdEncoding.DecodeString(request.Payload.Data)
	if err != nil {
		return server.errorResponse(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationCopyIn, "payload.data")
	}
	limit := smallerPositive(request.Payload.MaxBytes, DefaultCopyBytes)
	if int64(len(data)) > limit {
		return server.errorResponse(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyIn, "payload")
	}
	if !validSHA256Digest(request.Payload.Digest) {
		code := guestagent.ErrorCodeInvalidMetadata
		if request.Payload.Digest == "" {
			code = guestagent.ErrorCodeMissingRequiredField
		}
		return server.errorResponse(code, guestagent.OperationCopyIn, "payload.digest")
	}
	if digestBytes(data) != request.Payload.Digest {
		return server.errorResponse(guestagent.ErrorCodeDigestMismatch, guestagent.OperationCopyIn, "payload.digest")
	}
	result, err := server.backend.CopyIn(backendCtx, CopyInPlan{
		DestinationPath: request.DestinationPath,
		Data:            data,
		MaxBytes:        limit,
		Digest:          request.Payload.Digest,
	})
	if err != nil {
		if backendCtx.Err() != nil {
			return server.contextErrorResponse(backendCtx.Err(), guestagent.OperationCopyIn)
		}
		return server.backendErrorResponse(err, guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "copy")
	}
	if err := backendCtx.Err(); err != nil {
		return server.contextErrorResponse(err, guestagent.OperationCopyIn)
	}
	if result.SizeBytes != int64(len(data)) || result.Digest != request.Payload.Digest {
		return server.errorResponse(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "copy")
	}
	return server.encodeResponse(guestagent.CopyInResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyIn,
		Written: guestagent.PayloadMetadata{
			SizeBytes: result.SizeBytes,
			MaxBytes:  limit,
			Digest:    result.Digest,
			Encoding:  guestagent.PayloadEncodingBase64,
		},
	}, guestagent.OperationCopyIn)
}

func (server *Server) handleCopyOut(ctx context.Context, encoded []byte) Response {
	var request guestagent.CopyOutRequest
	if err := strictDecodeRequest(encoded, &request); err != nil {
		return server.errorResponse(guestagent.ErrorCodeMalformedRequest, guestagent.OperationCopyOut, "request")
	}
	if err := guestagent.ValidateCopyOutRequest(request); err != nil {
		return server.validationErrorResponse(err, guestagent.OperationCopyOut)
	}
	callCtx, cancel := server.contextWithTiming(ctx, request.Timing)
	defer cancel()
	backendCtx, release, err := server.beginBackendCall(callCtx, true)
	if err != nil {
		return server.admissionErrorResponse(err, guestagent.OperationCopyOut)
	}
	defer release()

	limit := smallerPositive(request.Payload.MaxBytes, DefaultCopyBytes)
	result, err := server.backend.CopyOut(backendCtx, CopyOutPlan{
		SourcePath: request.SourcePath,
		MaxBytes:   limit,
	})
	if err != nil {
		if backendCtx.Err() != nil {
			return server.contextErrorResponse(backendCtx.Err(), guestagent.OperationCopyOut)
		}
		return server.backendErrorResponse(err, guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "copy")
	}
	if err := backendCtx.Err(); err != nil {
		return server.contextErrorResponse(err, guestagent.OperationCopyOut)
	}
	if int64(len(result.Data)) > limit {
		return server.errorResponse(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyOut, "payload")
	}
	if result.SizeBytes != int64(len(result.Data)) ||
		!validSHA256Digest(result.Digest) ||
		result.Digest != digestBytes(result.Data) {
		return server.errorResponse(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "copy")
	}
	return server.encodeResponse(guestagent.CopyOutResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyOut,
		Payload: guestagent.PayloadMetadata{
			SizeBytes: result.SizeBytes,
			MaxBytes:  limit,
			Digest:    result.Digest,
			Encoding:  guestagent.PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(result.Data),
		},
	}, guestagent.OperationCopyOut)
}

func (server *Server) resolveEnvironment(ctx context.Context, entries []guestagent.EnvironmentEntry) ([]string, error) {
	resolved := make([]string, 0, len(entries))
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, duplicate := names[entry.Name]; duplicate {
			return nil, errors.New("duplicate environment name")
		}
		names[entry.Name] = struct{}{}
		if entry.Source == guestagent.EnvironmentSourceSecret {
			return nil, errors.New("secret environment source is unavailable")
		}
		value, err := server.resolver.Resolve(ctx, entry)
		if err != nil {
			return nil, err
		}
		if strings.ContainsRune(value, 0) {
			return nil, errors.New("resolved environment value is invalid")
		}
		resolved = append(resolved, entry.Name+"="+value)
	}
	return resolved, nil
}

func (server *Server) contextWithTiming(ctx context.Context, timing *guestagent.TimingMetadata) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	requestCtx := ctx
	requestCancel := func() {}
	if timing != nil {
		switch {
		case timing.TimeoutMillis > 0:
			requestCtx, requestCancel = context.WithTimeout(ctx, time.Duration(timing.TimeoutMillis)*time.Millisecond)
		case timing.DeadlineUnixMillis > 0:
			requestCtx, requestCancel = context.WithDeadline(ctx, time.UnixMilli(timing.DeadlineUnixMillis))
		}
	}
	operationCtx, operationCancel := context.WithTimeout(requestCtx, server.maxOperationTime)
	return operationCtx, func() {
		operationCancel()
		requestCancel()
	}
}

func (server *Server) admissionErrorResponse(err error, operation guestagent.Operation) Response {
	switch {
	case errors.Is(err, errServerNotReady):
		return server.errorResponse(guestagent.ErrorCodeServerNotReady, operation, "server")
	case errors.Is(err, errServerBusy):
		return server.errorResponse(guestagent.ErrorCodeServerBusy, operation, "server")
	default:
		return server.contextErrorResponse(err, operation)
	}
}

func (server *Server) contextErrorResponse(err error, operation guestagent.Operation) Response {
	if errors.Is(err, context.DeadlineExceeded) {
		return server.errorResponse(guestagent.ErrorCodeRequestTimeout, operation, "context")
	}
	return server.errorResponse(guestagent.ErrorCodeRequestCanceled, operation, "context")
}

func (server *Server) backendErrorResponse(err error, fallback guestagent.ErrorCode, operation guestagent.Operation, field string) Response {
	var protocolErr *guestagent.ProtocolError
	if errors.As(err, &protocolErr) && allowedBackendErrorCode(protocolErr.Code) {
		return server.errorResponse(protocolErr.Code, operation, field)
	}
	return server.errorResponse(fallback, operation, field)
}

func (server *Server) validationErrorResponse(err error, operation guestagent.Operation) Response {
	var protocolErr *guestagent.ProtocolError
	if errors.As(err, &protocolErr) {
		return server.errorResponse(protocolErr.Code, operation, protocolErr.Field)
	}
	return server.errorResponse(guestagent.ErrorCodeInvalidMetadata, operation, "request")
}

func (server *Server) readinessResponse(ready bool) Response {
	status := guestagent.ReadinessStatusNotReady
	if ready {
		status = guestagent.ReadinessStatusReady
	}
	return server.encodeResponse(guestagent.ReadinessResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
		Ready:           ready,
		Status:          status,
	}, guestagent.OperationReadiness)
}

func (server *Server) encodeResponse(value any, operation guestagent.Operation) Response {
	encoded, err := json.Marshal(value)
	if err != nil {
		return server.errorResponse(guestagent.ErrorCodeInternalFailure, operation, "response")
	}
	if int64(len(encoded)) > server.limits.MaxResponseBytes {
		return server.errorResponse(guestagent.ErrorCodeOversizedResponse, operation, "response")
	}
	return Response{Encoded: encoded}
}

func (server *Server) errorResponse(code guestagent.ErrorCode, operation guestagent.Operation, field string) Response {
	message := fixedErrorMessage(code)
	envelope := guestagent.ErrorResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       operation,
		Error: &guestagent.ProtocolError{
			Code:      code,
			Operation: operation,
			Field:     field,
			Message:   message,
		},
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || int64(len(encoded)) > server.limits.MaxResponseBytes {
		return encodeStandaloneError(guestagent.ErrorCodeInternalFailure, operation, "response")
	}
	return Response{Encoded: encoded}
}

func encodeStandaloneError(code guestagent.ErrorCode, operation guestagent.Operation, field string) Response {
	encoded, _ := json.Marshal(guestagent.ErrorResponse{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       operation,
		Error: &guestagent.ProtocolError{
			Code:      code,
			Operation: operation,
			Field:     field,
			Message:   fixedErrorMessage(code),
		},
	})
	return Response{Encoded: encoded}
}

func supportedOperation(operation guestagent.Operation) guestagent.Operation {
	switch operation {
	case guestagent.OperationReadiness,
		guestagent.OperationExec,
		guestagent.OperationCopyIn,
		guestagent.OperationCopyOut:
		return operation
	default:
		return ""
	}
}

func requestRootFieldsKnown(encoded []byte) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		return false
	}
	for key := range object {
		switch key {
		case "protocolVersion", "operation", "timing",
			"args", "env", "workDir", "stdin", "stdout", "stderr",
			"destinationPath", "sourcePath", "payload":
		default:
			return false
		}
	}
	return true
}

func allowedBackendErrorCode(code guestagent.ErrorCode) bool {
	switch code {
	case guestagent.ErrorCodeMalformedPath,
		guestagent.ErrorCodeInvalidMetadata,
		guestagent.ErrorCodeOversizedPayloadMetadata,
		guestagent.ErrorCodeRequestCanceled,
		guestagent.ErrorCodeRequestTimeout,
		guestagent.ErrorCodeExecutionFailed,
		guestagent.ErrorCodeCopyFailed,
		guestagent.ErrorCodeDigestMismatch,
		guestagent.ErrorCodeResourceChanged,
		guestagent.ErrorCodeDurabilityUncertain,
		guestagent.ErrorCodeBackendUnavailable,
		guestagent.ErrorCodeUnsupportedPlatform,
		guestagent.ErrorCodeInternalFailure:
		return true
	default:
		return false
	}
}

func fixedErrorMessage(code guestagent.ErrorCode) string {
	switch code {
	case guestagent.ErrorCodeMalformedRequest:
		return "guest agent request is malformed"
	case guestagent.ErrorCodeServerNotReady:
		return "guest agent server is not ready"
	case guestagent.ErrorCodeServerBusy:
		return "guest agent server is busy"
	case guestagent.ErrorCodeEnvironmentUnavailable:
		return "guest environment is unavailable"
	case guestagent.ErrorCodeExecutionFailed:
		return "guest command execution failed"
	case guestagent.ErrorCodeCopyFailed:
		return "guest copy operation failed"
	case guestagent.ErrorCodeDigestMismatch:
		return "guest payload digest does not match"
	case guestagent.ErrorCodeResourceChanged:
		return "guest resource changed during operation"
	case guestagent.ErrorCodeDurabilityUncertain:
		return "guest copy durability is uncertain"
	case guestagent.ErrorCodeBackendUnavailable:
		return "guest backend is unavailable"
	case guestagent.ErrorCodeUnsupportedPlatform:
		return "guest backend platform is unsupported"
	case guestagent.ErrorCodeInternalFailure:
		return "guest agent internal failure"
	case guestagent.ErrorCodeUnsupportedProtocolVersion:
		return "guest agent protocol version is unsupported"
	case guestagent.ErrorCodeUnknownOperation:
		return "guest agent operation is unsupported"
	case guestagent.ErrorCodeMissingRequiredField:
		return "guest agent request is missing a required field"
	case guestagent.ErrorCodeOversizedPayloadMetadata:
		return "guest agent payload exceeds its byte limit"
	case guestagent.ErrorCodeOversizedRequest:
		return "guest agent request exceeds its byte limit"
	case guestagent.ErrorCodeOversizedResponse:
		return "guest agent response exceeds its byte limit"
	case guestagent.ErrorCodeRequestCanceled:
		return "guest agent request was canceled"
	case guestagent.ErrorCodeRequestTimeout:
		return "guest agent request timed out"
	default:
		return "guest agent request is invalid"
	}
}

func decodeExecStdin(metadata *guestagent.StreamMetadata) ([]byte, error) {
	if metadata == nil || metadata.Data == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(metadata.Data)
}

func smallerPositive(requested, maximum int64) int64 {
	if requested > 0 && requested < maximum {
		return requested
	}
	return maximum
}

func boundedResult(data []byte, limit int64, truncated bool) ([]byte, bool) {
	if int64(len(data)) <= limit {
		return append([]byte(nil), data...), truncated
	}
	return append([]byte(nil), data[:limit]...), true
}

func encodedStream(data []byte, maximum int64, truncated bool) guestagent.StreamMetadata {
	metadata := guestagent.StreamMetadata{
		SizeBytes: int64(len(data)),
		MaxBytes:  maximum,
		Truncated: truncated,
	}
	if len(data) > 0 {
		metadata.Encoding = guestagent.PayloadEncodingBase64
		metadata.Data = base64.StdEncoding.EncodeToString(data)
	}
	return metadata
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(hexValue) != hexValue {
		return false
	}
	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == sha256.Size
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type rejectingEnvironmentResolver struct{}

func (rejectingEnvironmentResolver) Resolve(context.Context, guestagent.EnvironmentEntry) (string, error) {
	return "", errors.New("environment resolution is unavailable")
}
