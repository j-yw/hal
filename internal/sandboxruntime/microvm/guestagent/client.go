package guestagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultMaxEncodedRequestBytes  int64 = 1 << 20
	DefaultMaxEncodedResponseBytes int64 = 1 << 20
)

// Client dispatches bounded guest-agent protocol requests through an injected
// byte transport. Unix socket and vsock implementations can sit behind the
// transport without changing the protocol-facing client boundary.
type Client struct {
	transport        Transport
	maxRequestBytes  int64
	maxResponseBytes int64
}

// ClientOptions configures a host-side guest-agent protocol client.
type ClientOptions struct {
	Transport        Transport
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// Transport performs one encoded guest-agent request/response exchange.
type Transport interface {
	RoundTrip(context.Context, TransportRequest) (TransportResponse, error)
}

// TransportFunc adapts a function into a guest-agent transport.
type TransportFunc func(context.Context, TransportRequest) (TransportResponse, error)

// RoundTrip dispatches request through fn.
func (fn TransportFunc) RoundTrip(ctx context.Context, request TransportRequest) (TransportResponse, error) {
	if fn == nil {
		return TransportResponse{}, fmt.Errorf("guest agent transport is not configured")
	}
	return fn(ctx, request)
}

// TransportRequest is the encoded request handed to a future Unix or vsock
// transport implementation.
type TransportRequest struct {
	ProtocolVersion  ProtocolVersion
	Operation        Operation
	Encoded          []byte
	MaxResponseBytes int64
}

// TransportResponse is the encoded response returned by a transport.
type TransportResponse struct {
	Encoded []byte
}

// NewClient returns a host-side guest-agent client over an injected transport.
func NewClient(options ClientOptions) (*Client, error) {
	if !transportConfigured(options.Transport) {
		return nil, fmt.Errorf("guest agent transport is required")
	}
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = DefaultMaxEncodedRequestBytes
	}
	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxEncodedResponseBytes
	}
	return &Client{
		transport:        options.Transport,
		maxRequestBytes:  maxRequestBytes,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

// Readiness asks the guest agent whether it is ready for protocol operations.
func (client *Client) Readiness(ctx context.Context, request ReadinessRequest) (*ReadinessResponse, error) {
	request.ProtocolVersion = ProtocolVersionV1
	request.Operation = OperationReadiness
	if err := ValidateReadinessRequest(request); err != nil {
		return nil, err
	}
	var response ReadinessResponse
	if err := client.roundTrip(ctx, OperationReadiness, request.Timing, request, &response, func() error {
		return ValidateReadinessResponseForRequest(response, request)
	}); err != nil {
		return nil, err
	}
	return &response, nil
}

// Exec asks the guest agent to run a bounded command inside the guest.
func (client *Client) Exec(ctx context.Context, request ExecRequest) (*ExecResponse, error) {
	request.ProtocolVersion = ProtocolVersionV1
	request.Operation = OperationExec
	if err := ValidateExecRequest(request); err != nil {
		return nil, err
	}
	var response ExecResponse
	if err := client.roundTrip(ctx, OperationExec, request.Timing, request, &response, func() error {
		return ValidateExecResponse(response)
	}); err != nil {
		return nil, err
	}
	return &response, nil
}

// CopyIn asks the guest agent to receive a bounded payload at a guest path.
func (client *Client) CopyIn(ctx context.Context, request CopyInRequest) (*CopyInResponse, error) {
	request.ProtocolVersion = ProtocolVersionV1
	request.Operation = OperationCopyIn
	if err := ValidateCopyInRequest(request); err != nil {
		return nil, err
	}
	var response CopyInResponse
	if err := client.roundTrip(ctx, OperationCopyIn, request.Timing, request, &response, func() error {
		return validateCopyInSuccessForRequest(response, request)
	}); err != nil {
		return nil, err
	}
	return &response, nil
}

// CopyOut asks the guest agent to produce bounded payload content from a guest
// path.
func (client *Client) CopyOut(ctx context.Context, request CopyOutRequest) (*CopyOutResponse, error) {
	request.ProtocolVersion = ProtocolVersionV1
	request.Operation = OperationCopyOut
	if err := ValidateCopyOutRequest(request); err != nil {
		return nil, err
	}
	var response CopyOutResponse
	if err := client.roundTrip(ctx, OperationCopyOut, request.Timing, request, &response, func() error {
		return ValidateCopyOutResponse(response)
	}); err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) roundTrip(ctx context.Context, operation Operation, timing *TimingMetadata, request any, response any, validateResponse func() error) error {
	if client == nil || !transportConfigured(client.transport) {
		return NewProtocolError(ErrorCodeTransportFailure, operation, "transport", errors.New("guest agent client is not configured"))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return clientContextError(operation, err)
	}

	callCtx, cancel := contextWithTiming(ctx, timing)
	if cancel != nil {
		defer cancel()
	}
	if err := callCtx.Err(); err != nil {
		return clientContextError(operation, err)
	}

	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return NewProtocolError(ErrorCodeInvalidMetadata, operation, "request", fmt.Errorf("encode guest agent request: %w", err))
	}
	if int64(len(encodedRequest)) > client.maxRequestBytes {
		return NewProtocolError(ErrorCodeOversizedRequest, operation, "request", errors.New("encoded guest agent request exceeds configured size limit"))
	}

	transportResponse, err := client.transport.RoundTrip(callCtx, TransportRequest{
		ProtocolVersion:  ProtocolVersionV1,
		Operation:        operation,
		Encoded:          encodedRequest,
		MaxResponseBytes: client.maxResponseBytes,
	})
	if err != nil {
		if ctxErr := callCtx.Err(); ctxErr != nil {
			return clientContextError(operation, ctxErr)
		}
		return NewProtocolError(ErrorCodeTransportFailure, operation, "transport", err)
	}
	if err := callCtx.Err(); err != nil &&
		(operation != OperationCopyIn || !publishedCopyInOutcome(transportResponse.Encoded, client.maxResponseBytes, request)) {
		return clientContextError(operation, err)
	}

	encodedResponse := transportResponse.Encoded
	if int64(len(encodedResponse)) > client.maxResponseBytes {
		return NewProtocolError(ErrorCodeOversizedResponse, operation, "response", errors.New("encoded guest agent response exceeds configured size limit"))
	}
	if err := validateStrictJSONObject(encodedResponse, maxStrictJSONDepth); err != nil {
		return NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent response: %w", err))
	}
	if handled, err := operationlessResponseProtocolError(encodedResponse, operation); handled {
		return err
	}
	if err := validateResponseHeader(encodedResponse, operation); err != nil {
		return err
	}
	if err := strictUnmarshalObject(encodedResponse, response); err != nil {
		return NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent response: %w", err))
	}
	if err := responseProtocolError(encodedResponse, operation); err != nil {
		return err
	}
	if err := validateResponse(); err != nil {
		return err
	}
	return nil
}

func publishedCopyInOutcome(encoded []byte, maxResponseBytes int64, request any) bool {
	copyInRequest, ok := request.(CopyInRequest)
	if !ok {
		return false
	}
	if int64(len(encoded)) > maxResponseBytes {
		return false
	}
	if err := validateStrictJSONObject(encoded, maxStrictJSONDepth); err != nil {
		return false
	}
	if err := validateResponseHeader(encoded, OperationCopyIn); err != nil {
		return false
	}
	var probe struct {
		Error *ProtocolError `json:"error,omitempty"`
	}
	if err := json.Unmarshal(encoded, &probe); err != nil {
		return false
	}
	if probe.Error != nil {
		var response ErrorResponse
		if err := strictUnmarshalObject(encoded, &response); err != nil {
			return false
		}
		return ValidateErrorResponse(response) == nil &&
			response.Error.Code == ErrorCodeDurabilityUncertain
	}

	var response CopyInResponse
	if err := strictUnmarshalObject(encoded, &response); err != nil {
		return false
	}
	return validateCopyInSuccessForRequest(response, copyInRequest) == nil
}

func validateCopyInSuccessForRequest(response CopyInResponse, request CopyInRequest) error {
	if err := ValidateCopyInResponse(response); err != nil {
		return err
	}
	if response.Written.SizeBytes != request.Payload.SizeBytes {
		return newValidationError(ErrorCodeInvalidMetadata, OperationCopyIn, "written.sizeBytes", "copy acknowledgement size does not match request")
	}
	if response.Written.MaxBytes > request.Payload.MaxBytes {
		return newValidationError(ErrorCodeInvalidMetadata, OperationCopyIn, "written.maxBytes", "copy acknowledgement limit exceeds request")
	}
	if response.Written.Digest == "" || response.Written.Digest != request.Payload.Digest {
		return newValidationError(ErrorCodeInvalidMetadata, OperationCopyIn, "written.digest", "copy acknowledgement digest does not match request")
	}
	if response.Written.Encoding != PayloadEncodingBase64 {
		return newValidationError(ErrorCodeInvalidMetadata, OperationCopyIn, "written.encoding", "copy acknowledgement encoding is unsupported")
	}
	return nil
}

func contextWithTiming(ctx context.Context, timing *TimingMetadata) (context.Context, context.CancelFunc) {
	if timing == nil {
		return ctx, nil
	}
	if timing.TimeoutMillis > 0 {
		return context.WithTimeout(ctx, time.Duration(timing.TimeoutMillis)*time.Millisecond)
	}
	if timing.DeadlineUnixMillis > 0 {
		return context.WithDeadline(ctx, time.UnixMilli(timing.DeadlineUnixMillis))
	}
	return ctx, nil
}

func validateResponseHeader(encoded []byte, operation Operation) error {
	var header struct {
		ProtocolVersion ProtocolVersion `json:"protocolVersion"`
		Operation       Operation       `json:"operation"`
	}
	if err := json.Unmarshal(encoded, &header); err != nil {
		return NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent response header: %w", err))
	}
	return validateHeader(header.ProtocolVersion, header.Operation, operation)
}

func operationlessResponseProtocolError(encoded []byte, operation Operation) (bool, error) {
	var envelope struct {
		Operation Operation       `json:"operation"`
		Error     json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return true, NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent error response header: %w", err))
	}
	if envelope.Operation != "" || len(envelope.Error) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Error), []byte("null")) {
		return false, nil
	}

	var response ErrorResponse
	if err := strictUnmarshalObject(encoded, &response); err != nil {
		return true, NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent error response: %w", err))
	}
	if err := ValidateErrorResponse(response); err != nil {
		return true, malformedGuestErrorResponse(operation)
	}
	if !operationlessResponseErrorCodeAllowed(response.Error.Code) {
		return true, malformedGuestErrorResponse(operation)
	}
	return true, sanitizedResponseProtocolError(response.Error, operation)
}

func operationlessResponseErrorCodeAllowed(code ErrorCode) bool {
	switch code {
	case ErrorCodeUnsupportedProtocolVersion,
		ErrorCodeUnknownOperation,
		ErrorCodeMissingRequiredField,
		ErrorCodeOversizedRequest,
		ErrorCodeMalformedRequest,
		ErrorCodeInternalFailure:
		return true
	default:
		return false
	}
}

func responseProtocolError(encoded []byte, operation Operation) error {
	var envelope struct {
		ProtocolVersion ProtocolVersion `json:"protocolVersion"`
		Operation       Operation       `json:"operation"`
		Error           *ProtocolError  `json:"error,omitempty"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return NewProtocolError(ErrorCodeMalformedResponse, operation, "response", fmt.Errorf("decode guest agent response error: %w", err))
	}
	if envelope.Error == nil {
		return nil
	}
	if err := ValidateErrorResponse(ErrorResponse{
		ProtocolVersion: envelope.ProtocolVersion,
		Operation:       envelope.Operation,
		Error:           envelope.Error,
	}); err != nil {
		return malformedGuestErrorResponse(operation)
	}
	return sanitizedResponseProtocolError(envelope.Error, operation)
}

func malformedGuestErrorResponse(operation Operation) error {
	return NewProtocolError(
		ErrorCodeMalformedResponse,
		operation,
		"response",
		errors.New("guest agent error response is invalid"),
	)
}

func sanitizedResponseProtocolError(responseError *ProtocolError, operation Operation) error {
	responseOperation := sanitizeOperation(responseError.Operation)
	if responseOperation == "" {
		responseOperation = operation
	}
	return &ProtocolError{
		Code:      normalizeErrorCode(responseError.Code),
		Operation: responseOperation,
		Field:     sanitizeFieldName(responseError.Field),
		Message:   sanitizeProtocolErrorMessage(responseError.safeMessage()),
		Err:       ErrProtocolValidation,
	}
}

func clientContextError(operation Operation, err error) error {
	code := ErrorCodeRequestCanceled
	message := "guest agent request canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = ErrorCodeRequestTimeout
		message = "guest agent request timed out"
	}
	return &ProtocolError{
		Code:      code,
		Operation: operation,
		Field:     "context",
		Message:   message,
		Err:       err,
	}
}

func transportConfigured(transport Transport) bool {
	if transport == nil {
		return false
	}
	if fn, ok := transport.(TransportFunc); ok && fn == nil {
		return false
	}
	return true
}
