package vsock

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

const (
	DefaultGuestPort      uint32 = 1024
	DefaultMaxConnections int    = 1
)

type Listener interface {
	Accept(context.Context) (io.ReadWriteCloser, error)
	Close() error
}

type Options struct {
	Listener       Listener
	MaxConnections int
}

type Transport struct {
	listener       Listener
	maxConnections int
}

func NewTransport(options Options) (*Transport, error) {
	if options.Listener == nil {
		return nil, errors.New("guest vsock listener is required")
	}
	maxConnections := options.MaxConnections
	if maxConnections == 0 {
		maxConnections = DefaultMaxConnections
	}
	if maxConnections < 1 || maxConnections > 64 {
		return nil, errors.New("guest vsock connection limit is invalid")
	}
	return &Transport{listener: options.Listener, maxConnections: maxConnections}, nil
}

func (transport *Transport) Serve(ctx context.Context, limits server.Limits, handler server.Handler) error {
	if transport == nil || transport.listener == nil || handler == nil {
		return errors.New("guest vsock transport is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var wg sync.WaitGroup
	defer func() {
		_ = transport.listener.Close()
		wg.Wait()
	}()
	slots := make(chan struct{}, transport.maxConnections)
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := transport.listener.Accept(ctx)
		if err != nil {
			<-slots
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return errors.New("guest vsock accept failed")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			transport.serveConnection(ctx, limits, handler, conn)
		}()
	}
}

func (transport *Transport) serveConnection(ctx context.Context, limits server.Limits, handler server.Handler, conn io.ReadWriteCloser) {
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	defer closeConn()
	stop := context.AfterFunc(ctx, closeConn)
	defer stop()
	defer func() { _ = recover() }()
	maxRequest := limits.MaxRequestBytes
	if maxRequest <= 0 {
		return
	}
	encoded, err := io.ReadAll(io.LimitReader(conn, maxRequest+1))
	if err != nil || int64(len(encoded)) > maxRequest {
		return
	}
	response := handler.Handle(ctx, server.Request{Encoded: encoded})
	if limits.MaxResponseBytes <= 0 || int64(len(response.Encoded)) > limits.MaxResponseBytes {
		return
	}
	if err := writeAll(conn, response.Encoded); err != nil {
		return
	}
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

func writeAll(writer io.Writer, data []byte) error {
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
