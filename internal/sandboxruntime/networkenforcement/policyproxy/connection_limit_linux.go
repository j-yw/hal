//go:build linux

package policyproxy

import (
	"errors"
	"net"
	"sync"
)

// connectionLimitListener acquires capacity before calling the underlying
// listener. This bounds slow-header and other pre-handler connections rather
// than applying admission only after net/http has parsed a request.
type connectionLimitListener struct {
	net.Listener

	slots     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newConnectionLimitListener(listener net.Listener, limit int) *connectionLimitListener {
	return &connectionLimitListener{
		Listener: listener,
		slots:    make(chan struct{}, limit),
		closed:   make(chan struct{}),
	}
}

func (l *connectionLimitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &connectionLimitConn{
		Conn: conn,
		release: func() {
			<-l.slots
		},
	}, nil
}

func (l *connectionLimitListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type connectionLimitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *connectionLimitConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

func (c *connectionLimitConn) CloseWrite() error {
	closeWriter, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return closeWriter.CloseWrite()
}

func (c *connectionLimitConn) CloseRead() error {
	closeReader, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return closeReader.CloseRead()
}
