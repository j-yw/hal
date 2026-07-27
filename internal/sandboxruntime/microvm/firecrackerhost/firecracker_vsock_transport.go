package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const (
	L5GuestAgentPort       uint32 = 1024
	maxVsockHandshakeBytes int    = 64
)

type firecrackerVsockTransportOptions struct {
	socketPath       string
	guestPort        uint32
	expectedPeerPID  int
	handshakeTimeout time.Duration
	responseLimit    int64
	operationTimeout time.Duration
}

type firecrackerVsockTransport struct {
	socketPath       string
	guestPort        uint32
	expectedPeerPID  int
	handshakeTimeout time.Duration
	responseLimit    int64
	operationTimeout time.Duration
	socketIdentity   vsockSocketIdentity

	mu     sync.Mutex
	closed bool
	active map[*net.UnixConn]struct{}
}

func newFirecrackerVsockTransport(options firecrackerVsockTransportOptions) (*firecrackerVsockTransport, error) {
	if options.guestPort == 0 || options.guestPort == ^uint32(0) || options.expectedPeerPID <= 0 {
		return nil, errors.New("Firecracker vsock transport metadata is invalid")
	}
	path, err := validateGuestAgentUnixSocketPath(options.socketPath)
	if err != nil {
		return nil, errors.New("Firecracker vsock socket metadata is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Firecracker vsock socket is not privately owned")
	}
	if err := validateVsockSocketOwnership(path, info); err != nil {
		return nil, errors.New("Firecracker vsock socket is not privately owned")
	}
	identity, err := statVsockSocket(path)
	if err != nil {
		return nil, errors.New("Firecracker vsock socket identity is unavailable")
	}
	timeout := options.handshakeTimeout
	if timeout <= 0 {
		timeout = defaultGuestAgentUnixSocketDialTimeout
	}
	operationTimeout := options.operationTimeout
	if operationTimeout <= 0 {
		operationTimeout = 30 * time.Second
	}
	return &firecrackerVsockTransport{
		socketPath: path, guestPort: options.guestPort, expectedPeerPID: options.expectedPeerPID,
		handshakeTimeout: timeout, responseLimit: options.responseLimit,
		operationTimeout: operationTimeout, socketIdentity: identity,
		active: make(map[*net.UnixConn]struct{}),
	}, nil
}

func (transport *firecrackerVsockTransport) RoundTrip(ctx context.Context, request guestagent.TransportRequest) (guestagent.TransportResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return guestagent.TransportResponse{}, guestAgentUnixSocketContextError(request.Operation, err)
	}
	if int64(len(request.Encoded)) > guestagent.DefaultMaxEncodedRequestBytes {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeOversizedRequest, request.Operation, "request", errors.New("guest request exceeds limit"))
	}
	before, err := statVsockSocket(transport.socketPath)
	if err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	dialer := net.Dialer{Timeout: transport.handshakeTimeout}
	raw, err := dialer.DialContext(ctx, "unix", transport.socketPath)
	if err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, errors.New("unexpected connection type"))
	}
	if !transport.register(conn) {
		_ = conn.Close()
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, errors.New("Firecracker vsock session is closed"))
	}
	defer func() {
		transport.unregister(conn)
		_ = conn.Close()
	}()
	after, err := statVsockSocket(transport.socketPath)
	if err != nil || before != transport.socketIdentity || after != transport.socketIdentity {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, errors.New("Firecracker vsock socket identity changed"))
	}
	if err := verifyVsockPeer(conn, transport.expectedPeerPID); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	deadline := time.Now().Add(transport.handshakeTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := writeFull(conn, []byte("CONNECT "+strconv.FormatUint(uint64(transport.guestPort), 10)+"\n")); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	reader := bufio.NewReaderSize(conn, maxVsockHandshakeBytes)
	ack, err := reader.ReadSlice('\n')
	if err != nil || len(ack) > maxVsockHandshakeBytes || reader.Buffered() != 0 || !validVsockAck(string(ack)) {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, errors.New("invalid Firecracker vsock acknowledgement"))
	}
	operationDeadline := time.Now().Add(transport.operationTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(operationDeadline) {
		operationDeadline = callerDeadline
	}
	if err := conn.SetDeadline(operationDeadline); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	if err := writeFull(conn, request.Encoded); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	if err := conn.CloseWrite(); err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	limit := request.MaxResponseBytes
	if limit <= 0 {
		limit = transport.responseLimit
	}
	if limit <= 0 {
		limit = guestagent.DefaultMaxEncodedResponseBytes
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return guestagent.TransportResponse{}, transportFailure(request.Operation, ctx, err)
	}
	if int64(len(encoded)) > limit {
		return guestagent.TransportResponse{}, guestagent.NewProtocolError(guestagent.ErrorCodeOversizedResponse, request.Operation, "response", errors.New("guest response exceeds limit"))
	}
	return guestagent.TransportResponse{Encoded: encoded}, nil
}

func (transport *firecrackerVsockTransport) register(conn *net.UnixConn) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return false
	}
	transport.active[conn] = struct{}{}
	return true
}

func (transport *firecrackerVsockTransport) unregister(conn *net.UnixConn) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	delete(transport.active, conn)
}

func (transport *firecrackerVsockTransport) Close() {
	if transport == nil {
		return
	}
	transport.mu.Lock()
	if transport.closed {
		transport.mu.Unlock()
		return
	}
	transport.closed = true
	connections := make([]*net.UnixConn, 0, len(transport.active))
	for conn := range transport.active {
		connections = append(connections, conn)
	}
	transport.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func validVsockAck(value string) bool {
	if !strings.HasPrefix(value, "OK ") || !strings.HasSuffix(value, "\n") || strings.Contains(value, "\r") {
		return false
	}
	number := strings.TrimSuffix(strings.TrimPrefix(value, "OK "), "\n")
	if number == "" || (len(number) > 1 && number[0] == '0') {
		return false
	}
	for _, r := range number {
		if r < '0' || r > '9' {
			return false
		}
	}
	port, err := strconv.ParseUint(number, 10, 32)
	return err == nil && port > 0 && port < uint64(^uint32(0))
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func transportFailure(operation guestagent.Operation, ctx context.Context, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return guestAgentUnixSocketContextError(operation, ctx.Err())
	}
	return guestagent.NewProtocolError(guestagent.ErrorCodeTransportFailure, operation, "transport", sanitizedVsockCause{cause: cause})
}

type sanitizedVsockCause struct{ cause error }

func (sanitizedVsockCause) Error() string { return "Firecracker vsock transport failed" }
func (err sanitizedVsockCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

var _ guestagent.Transport = (*firecrackerVsockTransport)(nil)
