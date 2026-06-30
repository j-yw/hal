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
	clientHostPathPattern         = regexp.MustCompile(`(?i)(/private)?/(Users|home|tmp|var/folders)/[^\s:'"]+`)
	clientSecretAssignmentPattern = regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)=\S+`)
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
	resp, err := client.roundTrip(ctx, OperationStatus)
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
	resp, err := client.roundTrip(ctx, OperationCapabilities)
	if err != nil {
		return nil, err
	}
	if resp.Capabilities == nil {
		return nil, malformedClientResponseError(OperationCapabilities, "worker capabilities response did not include capabilities payload")
	}
	capabilities := resp.Capabilities.WithDefaults()
	return &capabilities, nil
}

func (client *Client) roundTrip(ctx context.Context, operation string) (Response, error) {
	if client == nil || !clientTransportConfigured(client.transport) {
		return Response{}, fmt.Errorf("worker client is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Response{}, clientContextError(operation, err)
	}

	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       client.nextRequestID(operation),
		Operation:       operation,
	}
	resp, err := client.transport.RoundTrip(ctx, req)
	if err != nil {
		return Response{}, clientContextOrTransportError(operation, err)
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
	return nil
}

func clientContextOrTransportError(operation string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return clientContextError(operation, err)
	}
	return &ClientError{
		Operation: operation,
		Code:      ErrorCodeInternal,
		Message:   sanitizeClientErrorDetail(err.Error()),
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
		Message:   sanitizeClientErrorDetail(message),
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
		Message:   sanitizeClientErrorDetail(protocolError.Message),
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
		message = sanitizeClientErrorDetail(err.Err.Error())
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
		return Response{}, fmt.Errorf("connect unix worker socket: %s", sanitizeClientErrorDetail(err.Error()))
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
		return Response{}, fmt.Errorf("write worker request: %s", sanitizeClientErrorDetail(err.Error()))
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
		return Response{}, fmt.Errorf("read worker response: %s", sanitizeClientErrorDetail(err.Error()))
	}
	return resp, nil
}

func sanitizeClientErrorDetail(detail string) string {
	detail = strings.Join(strings.Fields(detail), " ")
	detail = clientSecretAssignmentPattern.ReplaceAllString(detail, "$1=[redacted]")
	detail = clientHostPathPattern.ReplaceAllString(detail, "[redacted-path]")
	if len(detail) > maxClientErrorDetailBytes {
		detail = strings.TrimSpace(detail[:maxClientErrorDetailBytes]) + "..."
	}
	return detail
}
