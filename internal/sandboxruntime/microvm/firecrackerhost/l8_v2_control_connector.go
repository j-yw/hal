package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type productionL8V2ControlConnector struct {
	bridge *ProductionVsockBridge
}

type productionL8V2ControlStream struct {
	conn      *net.UnixConn
	reader    *bufio.Reader
	wire      *firecrackerVsockTransport
	done      chan struct{}
	stopWatch chan struct{}
	watchDone chan struct{}
	once      sync.Once
	err       error
}

func (connector *productionL8V2ControlConnector) OpenL8V2Control(
	ctx context.Context,
	target sandboxruntime.Target,
) (l8V2ControlStream, error) {
	if connector == nil || connector.bridge == nil || connector.bridge.lifecycle == nil || l8V2ControlValueIsNil(ctx) {
		return nil, ErrL8V2ControlInvalid
	}
	bridge := connector.bridge
	active := bridge.sessionForTarget(target)
	if active == nil || active.wire == nil {
		return nil, ErrL8V2ControlUnavailable
	}
	request := firecracker.ProductionVsockSessionRequest{
		Handle:    firecracker.ProcessHandleMetadata{ID: active.handleID, Source: active.handleSource},
		RuntimeID: active.runtimeID,
	}
	if !bridge.SessionActive(request, active.generation) {
		return nil, ErrL8V2ControlUnavailable
	}
	process, err := bridge.lifecycle.resolveLiveProcessIdentity(request.Handle)
	if err != nil || process.handle.ID != active.handleID || process.done == nil {
		return nil, ErrL8V2ControlUnavailable
	}
	socketPath := filepath.Clean(process.paths.VsockSocketPath)
	if socketPath == "." || !filepath.IsAbs(socketPath) || secureFirecrackerVsockSocket(socketPath) != nil {
		return nil, ErrL8V2ControlUnavailable
	}
	before, err := statVsockSocket(socketPath)
	if err != nil || before != active.identity {
		return nil, ErrL8V2ControlUnavailable
	}
	dialer := net.Dialer{Timeout: session.HandshakeDeadline}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, ErrL8V2ControlUnavailable
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, ErrL8V2ControlUnavailable
	}
	if !active.wire.register(conn) {
		_ = conn.Close()
		return nil, ErrL8V2ControlUnavailable
	}
	owned := &productionL8V2ControlStream{
		conn: conn, reader: bufio.NewReaderSize(conn, maxVsockHandshakeBytes), wire: active.wire,
		done: make(chan struct{}), stopWatch: make(chan struct{}), watchDone: make(chan struct{}),
	}
	go owned.watchAuthority(process.done, active.wire.done)
	fail := func() (l8V2ControlStream, error) {
		_ = owned.Close()
		return nil, ErrL8V2ControlUnavailable
	}
	after, err := statVsockSocket(socketPath)
	if err != nil || after != active.identity || verifyVsockPeer(conn, process.pid) != nil {
		return fail()
	}
	deadline := time.Now().Add(session.HandshakeDeadline)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if conn.SetDeadline(deadline) != nil {
		return fail()
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = owned.Close() })
	defer stopCancellation()
	connect := "CONNECT " + strconv.FormatUint(uint64(session.ControlPort), 10) + "\n"
	if writeFull(conn, []byte(connect)) != nil {
		return fail()
	}
	ack, err := owned.reader.ReadSlice('\n')
	if err != nil || len(ack) > maxVsockHandshakeBytes || owned.reader.Buffered() != 0 || !validVsockAck(string(ack)) {
		return fail()
	}
	if !bridge.SessionActive(request, active.generation) {
		return fail()
	}
	current, err := statVsockSocket(socketPath)
	if err != nil || current != active.identity || conn.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	return owned, nil
}

func (stream *productionL8V2ControlStream) Read(destination []byte) (int, error) {
	if stream == nil || stream.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return stream.reader.Read(destination)
}

func (stream *productionL8V2ControlStream) Write(source []byte) (int, error) {
	if stream == nil || stream.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return stream.conn.Write(source)
}

func (stream *productionL8V2ControlStream) SetDeadline(deadline time.Time) error {
	if stream == nil || stream.conn == nil {
		return io.ErrClosedPipe
	}
	return stream.conn.SetDeadline(deadline)
}

func (stream *productionL8V2ControlStream) ProcessDone() <-chan struct{} {
	if stream == nil {
		return nil
	}
	return stream.done
}

func (stream *productionL8V2ControlStream) Close() error {
	if stream == nil {
		return nil
	}
	stream.once.Do(func() {
		if stream.stopWatch != nil {
			close(stream.stopWatch)
		}
		if stream.wire != nil && stream.conn != nil {
			wire := stream.wire
			conn := stream.conn
			wire.unregister(conn)
		}
		if stream.conn != nil {
			stream.err = stream.conn.Close()
			if errors.Is(stream.err, net.ErrClosed) {
				stream.err = nil
			}
		}
	})
	if stream.watchDone != nil {
		<-stream.watchDone
	}
	return stream.err
}

func (stream *productionL8V2ControlStream) watchAuthority(processDone, wireDone <-chan struct{}) {
	defer close(stream.watchDone)
	select {
	case <-processDone:
		close(stream.done)
	case <-wireDone:
		close(stream.done)
	case <-stream.stopWatch:
	}
}

var _ l8V2ControlConnector = (*productionL8V2ControlConnector)(nil)
var _ l8V2ControlStream = (*productionL8V2ControlStream)(nil)
