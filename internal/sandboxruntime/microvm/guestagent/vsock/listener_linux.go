//go:build linux

package vsock

import (
	"context"
	"errors"
	"io"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxListener struct {
	fd   int
	once sync.Once
}

func NewListener(port uint32) (Listener, error) {
	if port == 0 || port == ^uint32(0) {
		return nil, errors.New("guest vsock port is invalid")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("guest vsock socket unavailable")
	}
	listener := &linuxListener{fd: fd}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = listener.Close()
		return nil, errors.New("guest vsock bind failed")
	}
	if err := unix.Listen(fd, 64); err != nil {
		_ = listener.Close()
		return nil, errors.New("guest vsock listen failed")
	}
	return listener, nil
}

func (listener *linuxListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		fd, _, err := unix.Accept4(listener.fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err == nil {
			return &linuxConn{fd: fd}, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		poll := []unix.PollFd{{Fd: int32(listener.fd), Events: unix.POLLIN}}
		_, err = unix.Poll(poll, 50)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return nil, err
		}
	}
}

func (listener *linuxListener) Close() error {
	var err error
	listener.once.Do(func() { err = unix.Close(listener.fd) })
	return err
}

type linuxConn struct {
	fd   int
	once sync.Once
}

func (conn *linuxConn) Read(data []byte) (int, error) {
	for {
		n, err := unix.Read(conn.fd, data)
		if errors.Is(err, unix.EAGAIN) {
			if err := pollGuestConn(conn.fd, unix.POLLIN); err != nil {
				return 0, err
			}
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}

func (conn *linuxConn) Write(data []byte) (int, error) {
	for {
		n, err := unix.Write(conn.fd, data)
		if errors.Is(err, unix.EAGAIN) {
			if err := pollGuestConn(conn.fd, unix.POLLOUT); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func pollGuestConn(fd int, events int16) error {
	poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
	for {
		_, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func (conn *linuxConn) Close() error {
	var err error
	conn.once.Do(func() { err = unix.Close(conn.fd) })
	return err
}

func (conn *linuxConn) CloseWrite() error {
	if conn == nil {
		return errors.New("guest vsock connection is unavailable")
	}
	return unix.Shutdown(conn.fd, unix.SHUT_WR)
}
