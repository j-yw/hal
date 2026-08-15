package sandboxworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const defaultMaxRequestBytes int64 = 1 << 20

var listenWorkerUnixSocket = func(ctx context.Context, socketPath string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
}

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
	if !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("worker server socketPath must be absolute")
	}
	if !requestHandlerConfigured(options.Handler) {
		return nil, fmt.Errorf("worker server handler is required")
	}
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = defaultMaxRequestBytes
	}
	return &Server{
		socketPath:      filepath.Clean(socketPath),
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
	parentProof, err := validateWorkerSocketPath(server.socketPath)
	if err != nil {
		return err
	}
	listener, err := listenWorkerUnixSocket(ctx, server.socketPath)
	if err != nil {
		return fmt.Errorf("worker server could not bind the Unix socket")
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("worker server listener is not a Unix socket")
	}
	unixListener.SetUnlinkOnClose(false)
	createdInfo, err := os.Lstat(server.socketPath)
	if err != nil || createdInfo.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return fmt.Errorf("worker server could not verify the Unix socket")
	}
	if err := validateWorkerSocketParentProof(parentProof); err != nil {
		_ = listener.Close()
		removeWorkerSocketIfSame(server.socketPath, createdInfo)
		return err
	}
	if err := os.Chmod(server.socketPath, 0o600); err != nil {
		_ = listener.Close()
		removeWorkerSocketIfSame(server.socketPath, createdInfo)
		return fmt.Errorf("worker server could not secure the Unix socket")
	}
	securedInfo, err := os.Lstat(server.socketPath)
	if err != nil || securedInfo.Mode()&os.ModeSocket == 0 ||
		securedInfo.Mode().Perm() != 0o600 || !os.SameFile(createdInfo, securedInfo) {
		_ = listener.Close()
		removeWorkerSocketIfSame(server.socketPath, createdInfo)
		return fmt.Errorf("worker server could not verify Unix socket security")
	}
	defer removeWorkerSocketIfSame(server.socketPath, securedInfo)
	defer listener.Close()
	return server.serve(ctx, listener, true)
}

// Serve accepts Unix socket connections from listener and handles one JSON
// request/response exchange per connection.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	return server.serve(ctx, listener, false)
}

func (server *Server) serve(ctx context.Context, listener net.Listener, filesystemBoundaryProven bool) error {
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
			return fmt.Errorf("worker server could not accept a Unix connection")
		}
		if err := validateWorkerPeerCredentials(conn, filesystemBoundaryProven); err != nil {
			_ = conn.Close()
			continue
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
	if err := decodeWorkerRequestInto(r, server.maxRequestBytes, &req); err != nil {
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
	_ = encodeWorkerResponse(w, resp.WithDefaults())
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
			Message: sanitizeProtocolErrorDetail(message),
		},
	}
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
