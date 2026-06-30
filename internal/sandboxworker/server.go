package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

const defaultMaxRequestBytes int64 = 1 << 20

// RequestHandler dispatches a validated worker protocol request.
type RequestHandler interface {
	HandleRequest(context.Context, Request) Response
}

// RequestHandlerFunc adapts a function into a RequestHandler.
type RequestHandlerFunc func(context.Context, Request) Response

// HandleRequest dispatches req through fn.
func (fn RequestHandlerFunc) HandleRequest(ctx context.Context, req Request) Response {
	if fn == nil {
		return protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeInternal, "worker handler is not configured")
	}
	return fn(ctx, req)
}

// Server serves worker protocol requests over a local Unix socket.
type Server struct {
	socketPath      string
	handler         RequestHandler
	maxRequestBytes int64
}

// ServerOptions configures a local worker socket server.
type ServerOptions struct {
	SocketPath      string
	Handler         RequestHandler
	MaxRequestBytes int64
}

// NewServer returns a worker server configured for a local Unix socket.
func NewServer(options ServerOptions) (*Server, error) {
	socketPath := strings.TrimSpace(options.SocketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("worker server socketPath is required")
	}
	if !requestHandlerConfigured(options.Handler) {
		return nil, fmt.Errorf("worker server handler is required")
	}
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = defaultMaxRequestBytes
	}
	return &Server{
		socketPath:      socketPath,
		handler:         options.Handler,
		maxRequestBytes: maxRequestBytes,
	}, nil
}

func requestHandlerConfigured(handler RequestHandler) bool {
	if handler == nil {
		return false
	}
	if fn, ok := handler.(RequestHandlerFunc); ok && fn == nil {
		return false
	}
	return true
}

// ListenAndServe binds the configured Unix socket and serves until ctx is
// canceled or the listener fails.
func (server *Server) ListenAndServe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", server.socketPath)
	if err != nil {
		return fmt.Errorf("worker server listen unix socket: %w", err)
	}
	defer func() {
		_ = os.Remove(server.socketPath)
	}()
	return server.Serve(ctx, listener)
}

// Serve accepts Unix socket connections from listener and handles one JSON
// request/response exchange per connection.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil {
		return fmt.Errorf("worker server listener is required")
	}
	if addr := listener.Addr(); addr != nil && addr.Network() != "unix" {
		_ = listener.Close()
		return fmt.Errorf("worker server listener network %q is unsupported; unix is required", addr.Network())
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || isClosedNetworkError(err) {
				return nil
			}
			return fmt.Errorf("worker server accept unix connection: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			server.handleConnection(ctx, conn)
		}()
	}
}

func (server *Server) handleConnection(ctx context.Context, conn net.Conn) {
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

	req, errorResp := server.readRequest(conn)
	if errorResp != nil {
		server.writeResponse(conn, *errorResp)
		return
	}

	resp := server.handler.HandleRequest(ctx, req)
	resp = normalizeHandlerResponse(req, resp)
	if err := resp.Validate(); err != nil {
		resp = protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeInternal, "worker handler returned invalid response")
	}
	server.writeResponse(conn, resp)
}

func (server *Server) readRequest(r io.Reader) (Request, *Response) {
	var req Request
	decoder := json.NewDecoder(io.LimitReader(r, server.maxRequestBytes))
	if err := decoder.Decode(&req); err != nil {
		resp := protocolErrorResponse("", OperationProtocolError, ErrorCodeMalformedRequest, "malformed worker request")
		return Request{}, &resp
	}

	req = req.WithDefaults()
	if err := req.Validate(); err != nil {
		resp := protocolErrorResponse(req.RequestID, req.Operation, ErrorCodeMalformedRequest, fmt.Sprintf("malformed worker request: %v", err))
		return req, &resp
	}
	return req, nil
}

func (server *Server) writeResponse(w io.Writer, resp Response) {
	_ = json.NewEncoder(w).Encode(resp.WithDefaults())
}

func normalizeHandlerResponse(req Request, resp Response) Response {
	resp = resp.WithDefaults()
	if strings.TrimSpace(resp.RequestID) == "" {
		resp.RequestID = strings.TrimSpace(req.RequestID)
	}
	if strings.TrimSpace(resp.Operation) == "" {
		resp.Operation = req.Operation
	}
	return resp
}

func protocolErrorResponse(requestID, operation, code, message string) Response {
	operation = strings.TrimSpace(operation)
	if !validOperation(operation) {
		operation = OperationProtocolError
	}
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       operation,
		OK:              false,
		Error: &Error{
			Code:    strings.TrimSpace(code),
			Message: strings.TrimSpace(message),
		},
	}
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
