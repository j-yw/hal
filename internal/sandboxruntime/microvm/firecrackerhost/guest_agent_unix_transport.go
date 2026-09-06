package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const defaultGuestAgentUnixSocketDialTimeout = 5 * time.Second

type guestAgentUnixSocketTransportOptions struct {
	endpoint      string
	dialTimeout   time.Duration
	responseLimit int64
}

type guestAgentUnixSocketTransport struct {
	socketPath    string
	dialTimeout   time.Duration
	responseLimit int64
}

var _ guestagent.Transport = (*guestAgentUnixSocketTransport)(nil)

func newGuestAgentUnixSocketTransport(options guestAgentUnixSocketTransportOptions) (*guestAgentUnixSocketTransport, error) {
	socketPath, err := guestAgentUnixSocketPathFromEndpoint(options.endpoint)
	if err != nil {
		return nil, err
	}
	dialTimeout := options.dialTimeout
	if dialTimeout < 0 {
		return nil, guestagent.NewProtocolError(guestagent.ErrorCodeInvalidTimeout, "", "dialTimeout", fmt.Errorf("guest agent dial timeout must be greater than or equal to zero"))
	}
	if dialTimeout == 0 {
		dialTimeout = defaultGuestAgentUnixSocketDialTimeout
	}
	responseLimit := options.responseLimit
	if responseLimit < 0 {
		return nil, guestagent.NewProtocolError(guestagent.ErrorCodeInvalidMetadata, "", "responseLimit", fmt.Errorf("guest agent response limit must be greater than or equal to zero"))
	}
	return &guestAgentUnixSocketTransport{
		socketPath:    socketPath,
		dialTimeout:   dialTimeout,
		responseLimit: responseLimit,
	}, nil
}

func guestAgentUnixSocketPathFromEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeMissingRequiredField, "", "endpoint", fmt.Errorf("guest agent endpoint is required"))
	}

	lowerEndpoint := strings.ToLower(endpoint)
	switch {
	case strings.HasPrefix(lowerEndpoint, "unix://"):
		return validateGuestAgentUnixSocketPath(endpoint[len("unix://"):])
	case strings.HasPrefix(lowerEndpoint, "unix:"):
		return validateGuestAgentUnixSocketPath(endpoint[len("unix:"):])
	case strings.HasPrefix(endpoint, "/"):
		return validateGuestAgentUnixSocketPath(endpoint)
	default:
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeInvalidMetadata, "", "endpoint", fmt.Errorf("guest agent endpoint must be a local Unix socket endpoint"))
	}
}

func (transport *guestAgentUnixSocketTransport) RoundTrip(ctx context.Context, request guestagent.TransportRequest) (guestagent.TransportResponse, error) {
	if transport == nil || strings.TrimSpace(transport.socketPath) == "" {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, request.Operation, "transport", fmt.Errorf("guest agent Unix socket transport is not configured"))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return guestagent.TransportResponse{}, guestAgentUnixSocketContextError(request.Operation, err)
	}

	dialer := net.Dialer{Timeout: transport.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", transport.socketPath)
	if err != nil {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, request.Operation, "transport", fmt.Errorf("connect guest agent Unix socket: %w", err))
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

	if _, err := io.Copy(conn, bytes.NewReader(request.Encoded)); err != nil {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, request.Operation, "request", fmt.Errorf("write guest agent request: %w", err))
	}
	if closer, ok := conn.(*net.UnixConn); ok {
		_ = closer.CloseWrite()
	}

	limit := request.MaxResponseBytes
	if limit <= 0 {
		limit = transport.responseLimit
	}
	if limit <= 0 {
		limit = guestagent.DefaultMaxEncodedResponseBytes
	}
	encoded, err := io.ReadAll(io.LimitReader(conn, limit+1))
	if err != nil {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, request.Operation, "response", fmt.Errorf("read guest agent response: %w", err))
	}
	if int64(len(encoded)) > limit {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeOversizedResponse, request.Operation, "response", fmt.Errorf("encoded guest agent response exceeds configured size limit"))
	}
	return guestagent.TransportResponse{Encoded: encoded}, nil
}

func validateGuestAgentUnixSocketPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeMissingRequiredField, "", "endpoint", fmt.Errorf("guest agent Unix socket path is required"))
	}
	if strings.ContainsAny(path, "?#") || strings.Contains(path, "://") || guestAgentEndpointContainsControl(path) {
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeInvalidMetadata, "", "endpoint", fmt.Errorf("guest agent Unix socket endpoint is invalid"))
	}
	if !filepath.IsAbs(path) {
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeMalformedPath, "", "endpoint", fmt.Errorf("guest agent Unix socket path must be absolute"))
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return "", guestagent.NewProtocolError(guestagent.ErrorCodeMalformedPath, "", "endpoint", fmt.Errorf("guest agent Unix socket path must not be the filesystem root"))
	}
	return clean, nil
}

func guestAgentUnixSocketContextError(operation guestagent.Operation, err error) error {
	code := guestagent.ErrorCodeRequestCanceled
	message := "guest agent request canceled"
	if errors.Is(err, context.DeadlineExceeded) {
		code = guestagent.ErrorCodeRequestTimeout
		message = "guest agent request timed out"
	}
	return &guestagent.ProtocolError{
		Code:      code,
		Operation: operation,
		Field:     "context",
		Message:   message,
		Err:       err,
	}
}

func guestAgentEndpointContainsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
