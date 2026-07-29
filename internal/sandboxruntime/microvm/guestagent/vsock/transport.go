package vsock

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

const (
	GuestAgentPort     uint32 = 1024
	defaultConnections int    = 1
	maximumConnections int    = 64
)

// Listener accepts guest-side AF_VSOCK streams.
type Listener interface {
	Accept(context.Context) (io.ReadWriteCloser, error)
	Close() error
}

type peerCloseWaiter interface {
	WaitPeerClosed(context.Context) error
}

// Options configure the bounded one-frame guest transport.
type Options struct {
	Listener       Listener
	MaxConnections int
}

// Transport dispatches one bounded request and response per accepted stream.
type Transport struct {
	listener       Listener
	maxConnections int

	mu     sync.Mutex
	active map[*trackedConnection]struct{}
}

type trackedConnection struct {
	io.ReadWriteCloser
	closeOnce sync.Once
	closeErr  error
}

// NewTransport constructs a guest transport around an already-bound listener.
func NewTransport(options Options) (*Transport, error) {
	if nilInterface(options.Listener) {
		return nil, errors.New("guest vsock listener is required")
	}
	maxConnections := options.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultConnections
	}
	if maxConnections < 1 || maxConnections > maximumConnections {
		return nil, errors.New("guest vsock maximum connections is invalid")
	}
	return &Transport{
		listener:       options.Listener,
		maxConnections: maxConnections,
		active:         make(map[*trackedConnection]struct{}),
	}, nil
}

// Serve accepts streams until cancellation and closes every accepted stream.
func (transport *Transport) Serve(ctx context.Context, limits server.Limits, handler server.Handler) error {
	if transport == nil || nilInterface(transport.listener) {
		return errors.New("guest vsock transport is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if nilInterface(handler) {
		return errors.New("guest vsock handler is required")
	}
	if limits.MaxRequestBytes < 1 || limits.MaxResponseBytes < 1 {
		return errors.New("guest vsock frame limits are invalid")
	}

	var connections sync.WaitGroup
	cancelClose := context.AfterFunc(ctx, func() {
		_ = transport.listener.Close()
		transport.closeActiveConnections()
	})
	defer func() {
		cancelClose()
		_ = transport.listener.Close()
		transport.closeActiveConnections()
		connections.Wait()
	}()

	admission := make(chan struct{}, transport.maxConnections)

	for {
		rawConnection, err := transport.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return errors.New("guest vsock accept failed")
		}
		if nilInterface(rawConnection) {
			return errors.New("guest vsock accepted an invalid connection")
		}
		connection := &trackedConnection{ReadWriteCloser: rawConnection}
		transport.track(connection)

		select {
		case admission <- struct{}{}:
		case <-ctx.Done():
			_ = connection.Close()
			transport.untrack(connection)
			return nil
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer func() { <-admission }()
			defer transport.untrack(connection)
			serveConnection(ctx, connection, limits, handler)
		}()
	}
}

func (transport *Transport) track(connection *trackedConnection) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.active[connection] = struct{}{}
}

func (transport *Transport) untrack(connection *trackedConnection) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	delete(transport.active, connection)
}

func (transport *Transport) closeActiveConnections() {
	transport.mu.Lock()
	connections := make([]*trackedConnection, 0, len(transport.active))
	for connection := range transport.active {
		connections = append(connections, connection)
	}
	transport.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (connection *trackedConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.ReadWriteCloser.Close()
	})
	return connection.closeErr
}

func (connection *trackedConnection) CloseWrite() error {
	if connection == nil {
		return nil
	}
	if halfCloser, ok := connection.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}

func (connection *trackedConnection) WaitPeerClosed(ctx context.Context) error {
	waiter, ok := connection.ReadWriteCloser.(peerCloseWaiter)
	if !ok {
		<-ctx.Done()
		return ctx.Err()
	}
	return waiter.WaitPeerClosed(ctx)
}

func serveConnection(ctx context.Context, connection io.ReadWriteCloser, limits server.Limits, handler server.Handler) {
	defer connection.Close()
	defer func() {
		_ = recover()
	}()

	request, err := io.ReadAll(io.LimitReader(connection, limits.MaxRequestBytes+1))
	if err != nil || int64(len(request)) > limits.MaxRequestBytes {
		return
	}
	handlerCtx, cancelHandler := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if waiter, ok := connection.(peerCloseWaiter); ok {
			if err := waiter.WaitPeerClosed(handlerCtx); err == nil || handlerCtx.Err() == nil {
				cancelHandler()
			}
			return
		}
		<-handlerCtx.Done()
	}()
	defer func() {
		cancelHandler()
		<-watcherDone
	}()

	response := handler.Handle(handlerCtx, server.Request{Encoded: request})
	if int64(len(response.Encoded)) > limits.MaxResponseBytes {
		return
	}
	if err := writeFull(connection, response.Encoded); err != nil {
		return
	}
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
