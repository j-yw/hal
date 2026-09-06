//go:build linux

package vsock

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	acceptPollMillis    = 100
	peerClosePollMillis = 10
)

type linuxListener struct {
	fd        atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

type linuxConnection struct {
	file      *os.File
	fd        int
	closeOnce sync.Once
	closeErr  error
}

// ListenLinux binds the fixed production guest-agent AF_VSOCK port.
func ListenLinux() (Listener, error) {
	fd, err := unix.Socket(
		unix.AF_VSOCK,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errors.New("guest AF_VSOCK socket is unavailable")
	}
	listener := &linuxListener{}
	listener.fd.Store(int64(fd))
	if err := unix.Bind(fd, &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_ANY,
		Port: GuestAgentPort,
	}); err != nil {
		_ = listener.Close()
		return nil, errors.New("guest AF_VSOCK bind failed")
	}
	if err := unix.Listen(fd, maximumConnections); err != nil {
		_ = listener.Close()
		return nil, errors.New("guest AF_VSOCK listen failed")
	}
	return listener, nil
}

func (listener *linuxListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	if listener == nil || listener.fd.Load() < 0 {
		return nil, errors.New("guest AF_VSOCK listener is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		listenerFD := int(listener.fd.Load())
		if listenerFD < 0 {
			return nil, errors.New("guest AF_VSOCK listener is closed")
		}
		fd, _, err := unix.Accept4(listenerFD, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err == nil {
			return &linuxConnection{
				file: os.NewFile(uintptr(fd), "guest-vsock-stream"),
				fd:   fd,
			}, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("guest AF_VSOCK accept failed")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		poll := []unix.PollFd{{Fd: int32(listenerFD), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, acceptPollMillis); err != nil && !errors.Is(err, unix.EINTR) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("guest AF_VSOCK poll failed")
		}
	}
}

func (listener *linuxListener) Close() error {
	if listener == nil {
		return nil
	}
	listener.closeOnce.Do(func() {
		fd := int(listener.fd.Swap(-1))
		if fd >= 0 {
			listener.closeErr = unix.Close(fd)
		}
	})
	return listener.closeErr
}

func (connection *linuxConnection) Read(value []byte) (int, error) {
	return connection.file.Read(value)
}

func (connection *linuxConnection) Write(value []byte) (int, error) {
	return connection.file.Write(value)
}

func (connection *linuxConnection) CloseWrite() error {
	if connection == nil {
		return nil
	}
	return unix.Shutdown(connection.fd, unix.SHUT_WR)
}

func (connection *linuxConnection) WaitPeerClosed(ctx context.Context) error {
	if connection == nil || connection.fd < 0 {
		return errors.New("guest AF_VSOCK connection is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(connection.fd)}}
		_, err := unix.Poll(poll, peerClosePollMillis)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("guest AF_VSOCK peer-close poll failed")
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil
		}
	}
}

func (connection *linuxConnection) Close() error {
	if connection == nil || connection.file == nil {
		return nil
	}
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.file.Close()
	})
	return connection.closeErr
}
