package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultClientDialTimeout  = 5 * time.Second
	defaultMaxResponseBytes   = 1 << 20
	maxClientErrorDetailBytes = 512
)

var (
	clientHostPathPattern         = regexp.MustCompile(`(?i)(/private)?/(Users|home|tmp|var/(folders|tmp)|run/user)/[^\s:'"]+`)
	clientRemoteTempPathPattern   = regexp.MustCompile(`(?i)/(workspace|workspaces|sandbox|remote)/[^\s:'"]*(/\.hal/tmp|/\.tmp|/tmp|/temp)[^\s:'"]*`)
	clientSecretAssignmentPattern = regexp.MustCompile(`(?i)\b([a-z0-9_-]*(token|secret|password|api[_-]?key))=\S+`)
)

// Client calls worker protocol operations through a fakeable local transport.
type Client struct {
	transport ClientTransport
	nextID    atomic.Uint64
}

// ClientOptions configures a local worker client.
type ClientOptions struct {
	SocketPath string
	Transport  ClientTransport

	DialTimeout      time.Duration
	MaxResponseBytes int64
}

// ClientTransport performs one worker protocol request/response exchange.
type ClientTransport interface {
	RoundTrip(context.Context, Request) (Response, error)
}

// ClientTransportFunc adapts a function into a ClientTransport.
type ClientTransportFunc func(context.Context, Request) (Response, error)

// RoundTrip dispatches req through fn.
func (fn ClientTransportFunc) RoundTrip(ctx context.Context, req Request) (Response, error) {
	if fn == nil {
		return Response{}, fmt.Errorf("worker client transport is not configured")
	}
	return fn(ctx, req)
}

// NewClient returns a client backed by an injected transport or a local Unix
// socket transport.
func NewClient(options ClientOptions) (*Client, error) {
	transport := options.Transport
	if transport == nil {
		socketPath := strings.TrimSpace(options.SocketPath)
		if socketPath == "" {
			return nil, fmt.Errorf("worker client socketPath is required")
		}
		transport = unixSocketClientTransport{
			socketPath:       socketPath,
			dialTimeout:      options.DialTimeout,
			maxResponseBytes: options.MaxResponseBytes,
		}
	}
	if !clientTransportConfigured(transport) {
		return nil, fmt.Errorf("worker client transport is required")
	}
	return &Client{transport: transport}, nil
}

// Status returns worker readiness through the local worker protocol.
func (client *Client) Status(ctx context.Context) (*Status, error) {
	resp, err := client.roundTrip(ctx, Request{Operation: OperationStatus})
	if err != nil {
		return nil, err
	}
	if resp.Status == nil {
		return nil, malformedClientResponseError(OperationStatus, "worker status response did not include status payload")
	}
	status := resp.Status.WithDefaults()
	return &status, nil
}

// Capabilities returns worker protocol capabilities through the local worker
// protocol.
func (client *Client) Capabilities(ctx context.Context) (*Capabilities, error) {
	resp, err := client.roundTrip(ctx, Request{Operation: OperationCapabilities})
	if err != nil {
		return nil, err
	}
	if resp.Capabilities == nil {
		return nil, malformedClientResponseError(OperationCapabilities, "worker capabilities response did not include capabilities payload")
	}
	capabilities := resp.Capabilities.WithDefaults()
	return &capabilities, nil
}

// Create creates a runtime target through the worker daemon.
func (client *Client) Create(ctx context.Context, driverID string, req CreateRequest) (*Target, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationCreate,
		DriverID:  driverID,
		Create:    &req,
	})
	if err != nil {
		return nil, err
	}
	return clientTargetResponse(resp)
}

// Start starts an existing runtime target through the worker daemon.
func (client *Client) Start(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationStart,
		DriverID:  driverID,
		Lifecycle: &req,
	})
	if err != nil {
		return nil, err
	}
	return clientTargetResponse(resp)
}

// Stop stops an existing runtime target through the worker daemon.
func (client *Client) Stop(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationStop,
		DriverID:  driverID,
		Lifecycle: &req,
	})
	if err != nil {
		return nil, err
	}
	return clientTargetResponse(resp)
}

// Delete removes an existing runtime target through the worker daemon.
func (client *Client) Delete(ctx context.Context, driverID string, req LifecycleRequest) error {
	_, err := client.roundTrip(ctx, Request{
		Operation: OperationDelete,
		DriverID:  driverID,
		Lifecycle: &req,
	})
	return err
}

// Inspect inspects an existing runtime target through the worker daemon.
func (client *Client) Inspect(ctx context.Context, driverID string, req InspectRequest) (*Target, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationInspect,
		DriverID:  driverID,
		Inspect:   &req,
	})
	if err != nil {
		return nil, err
	}
	return clientTargetResponse(resp)
}

// Exec runs a bounded command execution through the worker daemon.
func (client *Client) Exec(ctx context.Context, driverID string, req ExecRequest) (*ExecResponse, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationExec,
		DriverID:  driverID,
		Exec:      &req,
	})
	if err != nil {
		return nil, err
	}
	if resp.Exec == nil {
		return nil, malformedClientResponseError(OperationExec, "worker exec response did not include exec payload")
	}
	execResp := *resp.Exec
	sanitizeEmbeddedProtocolError(execResp.Error)
	return &execResp, nil
}

// CopyIn copies a bounded file payload into a worker target.
func (client *Client) CopyIn(ctx context.Context, driverID string, req CopyInRequest) (*CopyInResponse, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationCopyIn,
		DriverID:  driverID,
		CopyIn:    &req,
	})
	if err != nil {
		return nil, err
	}
	if resp.CopyIn == nil {
		return nil, malformedClientResponseError(OperationCopyIn, "worker copy_in response did not include copyIn payload")
	}
	copyInResp := *resp.CopyIn
	sanitizeEmbeddedProtocolError(copyInResp.Error)
	return &copyInResp, nil
}

// CopyOut copies a bounded file payload out of a worker target.
func (client *Client) CopyOut(ctx context.Context, driverID string, req CopyOutRequest) (*CopyOutResponse, error) {
	resp, err := client.roundTrip(ctx, Request{
		Operation: OperationCopyOut,
		DriverID:  driverID,
		CopyOut:   &req,
	})
	if err != nil {
		return nil, err
	}
	if resp.CopyOut == nil {
		return nil, malformedClientResponseError(OperationCopyOut, "worker copy_out response did not include copyOut payload")
	}
	copyOutResp := *resp.CopyOut
	sanitizeEmbeddedProtocolError(copyOutResp.Error)
	return &copyOutResp, nil
}

func (client *Client) roundTrip(ctx context.Context, req Request) (Response, error) {
	if client == nil || !clientTransportConfigured(client.transport) {
		return Response{}, fmt.Errorf("worker client is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Response{}, clientContextError(req.Operation, err)
	}

	req.ProtocolVersion = ProtocolVersion
	req.RequestID = client.nextRequestID(req.Operation)
	req = req.WithDefaults()
	if err := req.Validate(); err != nil {
		return Response{}, malformedClientResponseError(req.Operation, fmt.Sprintf("malformed worker request: %v", err))
	}

	resp, err := client.transport.RoundTrip(ctx, req)
	if err != nil {
		return Response{}, clientContextOrTransportError(req.Operation, err)
	}
	resp = resp.WithDefaults()
	if err := validateClientResponse(req, resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return Response{}, protocolClientError(resp)
	}
	return resp, nil
}

func clientTargetResponse(resp Response) (*Target, error) {
	if resp.Target == nil {
		return nil, malformedClientResponseError(resp.Operation, "worker response did not include target payload")
	}
	target := *resp.Target
	return &target, nil
}

func (client *Client) nextRequestID(operation string) string {
	seq := client.nextID.Add(1)
	return strings.TrimSpace(operation) + "-" + strconv.FormatUint(seq, 10)
}

func validateClientResponse(req Request, resp Response) error {
	if err := resp.Validate(); err != nil {
		return malformedClientResponseError(req.Operation, fmt.Sprintf("malformed worker response: %v", err))
	}
	if resp.RequestID != "" && resp.RequestID != req.RequestID {
		return malformedClientResponseError(req.Operation, "worker response requestId did not match request")
	}
	if resp.OK && resp.Operation != req.Operation {
		return malformedClientResponseError(req.Operation, "worker response operation did not match request")
	}
	if !resp.OK && resp.Operation != req.Operation && resp.Operation != OperationProtocolError {
		return malformedClientResponseError(req.Operation, "worker error response operation did not match request")
	}
	if err := validateClientIOResponseLimits(req, resp); err != nil {
		return malformedClientResponseError(req.Operation, fmt.Sprintf("malformed worker response: %v", err))
	}
	return nil
}

func validateClientIOResponseLimits(req Request, resp Response) error {
	if !resp.OK {
		return nil
	}
	switch req.Operation {
	case OperationExec:
		if req.Exec == nil || resp.Exec == nil {
			return nil
		}
		if err := validateClientOutputWithinLimit("exec stdout", resp.Exec.Stdout, req.Exec.StdoutLimitBytes); err != nil {
			return err
		}
		return validateClientOutputWithinLimit("exec stderr", resp.Exec.Stderr, req.Exec.StderrLimitBytes)
	case OperationCopyOut:
		if req.CopyOut == nil || resp.CopyOut == nil || resp.CopyOut.Payload == nil {
			return nil
		}
		return validateClientPayloadWithinLimit("copy_out payload", *resp.CopyOut.Payload, req.CopyOut.MaxPayloadBytes)
	default:
		return nil
	}
}

func validateClientOutputWithinLimit(field string, payload ExecOutputPayload, requestedLimit int64) error {
	field = workerIOValidationField(field, "exec output")
	if payload.LimitBytes > requestedLimit {
		return workerIOValidationError("%s limit exceeds requested limit of %d bytes", field, requestedLimit)
	}
	if payload.SizeBytes > requestedLimit {
		return workerIOValidationError("%s sizeBytes exceeds requested limit of %d bytes", field, requestedLimit)
	}
	return nil
}

func validateClientPayloadWithinLimit(field string, payload CopyFilePayload, requestedLimit int64) error {
	field = workerIOValidationField(field, "copy payload")
	if payload.LimitBytes > requestedLimit {
		return workerIOValidationError("%s limit exceeds requested limit of %d bytes", field, requestedLimit)
	}
	if payload.SizeBytes > requestedLimit {
		return workerIOValidationError("%s sizeBytes exceeds requested limit of %d bytes", field, requestedLimit)
	}
	return nil
}

func sanitizeEmbeddedProtocolError(protocolError *Error) {
	if protocolError == nil {
		return
	}
	protocolError.Message = sanitizeProtocolErrorDetail(protocolError.Message)
}

func clientContextOrTransportError(operation string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return clientContextError(operation, err)
	}
	return &ClientError{
		Operation: operation,
		Code:      ErrorCodeInternal,
		Message:   sanitizeProtocolErrorDetail(err.Error()),
		Err:       err,
	}
}

func clientContextError(operation string, err error) error {
	code := ErrorCodeRequestCanceled
	message := "worker request canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = ErrorCodeRequestTimeout
		message = "worker request timed out"
	}
	return &ClientError{
		Operation: operation,
		Code:      code,
		Message:   message,
		Err:       err,
	}
}

func malformedClientResponseError(operation, message string) error {
	return &ClientError{
		Operation: operation,
		Code:      ErrorCodeMalformedRequest,
		Message:   sanitizeProtocolErrorDetail(message),
	}
}

func protocolClientError(resp Response) error {
	protocolError := resp.Error
	if protocolError == nil {
		return malformedClientResponseError(resp.Operation, "worker error response did not include error payload")
	}
	return &ProtocolError{
		Operation: resp.Operation,
		Code:      protocolError.Code,
		Message:   sanitizeProtocolErrorDetail(protocolError.Message),
	}
}

func clientTransportConfigured(transport ClientTransport) bool {
	if transport == nil {
		return false
	}
	if fn, ok := transport.(ClientTransportFunc); ok && fn == nil {
		return false
	}
	return true
}

// ClientError describes a local client-side failure with sanitized detail.
type ClientError struct {
	Operation string
	Code      string
	Message   string
	Err       error
}

func (err *ClientError) Error() string {
	if err == nil {
		return ""
	}
	operation := strings.TrimSpace(err.Operation)
	if operation == "" {
		operation = "request"
	}
	message := strings.TrimSpace(err.Message)
	if message == "" && err.Err != nil {
		message = sanitizeProtocolErrorDetail(err.Err.Error())
	}
	if message == "" {
		message = "worker client request failed"
	}
	if code := strings.TrimSpace(err.Code); code != "" {
		return fmt.Sprintf("worker client %s failed: %s: %s", operation, code, message)
	}
	return fmt.Sprintf("worker client %s failed: %s", operation, message)
}

func (err *ClientError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// ProtocolError describes a non-OK worker protocol response with sanitized
// detail.
type ProtocolError struct {
	Operation string
	Code      string
	Message   string
}

func (err *ProtocolError) Error() string {
	if err == nil {
		return ""
	}
	operation := strings.TrimSpace(err.Operation)
	if operation == "" {
		operation = "request"
	}
	message := strings.TrimSpace(err.Message)
	if message == "" {
		message = "worker protocol request failed"
	}
	return fmt.Sprintf("worker protocol %s failed: %s: %s", operation, strings.TrimSpace(err.Code), message)
}

type unixSocketClientTransport struct {
	socketPath       string
	dialTimeout      time.Duration
	maxResponseBytes int64
}

func (transport unixSocketClientTransport) RoundTrip(ctx context.Context, req Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	socketPath := strings.TrimSpace(transport.socketPath)
	if socketPath == "" {
		return Response{}, fmt.Errorf("worker client socketPath is required")
	}

	dialer := net.Dialer{Timeout: transport.dialTimeout}
	if dialer.Timeout <= 0 {
		dialer.Timeout = defaultClientDialTimeout
	}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		return Response{}, fmt.Errorf("connect unix worker socket: %s", sanitizeProtocolErrorDetail(err.Error()))
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(req.WithDefaults()); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		return Response{}, fmt.Errorf("write worker request: %s", sanitizeProtocolErrorDetail(err.Error()))
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}

	maxResponseBytes := transport.maxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, maxResponseBytes)).Decode(&resp); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		return Response{}, fmt.Errorf("read worker response: %s", sanitizeProtocolErrorDetail(err.Error()))
	}
	return resp, nil
}

func sanitizeProtocolErrorDetail(detail string) string {
	detail = strings.Join(strings.Fields(detail), " ")
	detail = clientSecretAssignmentPattern.ReplaceAllString(detail, "$1=[redacted]")
	detail = clientHostPathPattern.ReplaceAllString(detail, "[redacted-path]")
	detail = clientRemoteTempPathPattern.ReplaceAllString(detail, "[redacted-path]")
	if len(detail) > maxClientErrorDetailBytes {
		detail = strings.TrimSpace(detail[:maxClientErrorDetailBytes]) + "..."
	}
	return detail
}
