//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

// Context methods run outside client/completion bookkeeping locks. In
// particular a typed-nil or panicking caller cannot admit protocol work.
func minimalJailerCallerCurrent(ctx context.Context) (current bool) {
	defer func() {
		if recover() != nil {
			current = false
		}
	}()
	if ctx == nil {
		return false
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return minimalCleanupContextCurrent(ctx)
}

// A selected exchange retains its own descriptor until its interrupter has
// joined. Neither context cancellation nor client close closes a live FD number.
type minimalJailerIO struct {
	ctx         context.Context
	file        *os.File
	stop, done  chan struct{}
	shutdownErr error
	ops         minimalJailerSocketOps
}

func newMinimalJailerIO(ctx context.Context, socket *os.File, selectedOps *minimalJailerSocketOps) (*minimalJailerIO, error) {
	if !minimalJailerCallerCurrent(ctx) || socket == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	ops := minimalJailerSocketOps{sendmsg: unix.Sendmsg, recvmsg: unix.Recvmsg}
	if selectedOps != nil {
		if selectedOps.sendmsg == nil || selectedOps.recvmsg == nil {
			return nil, errL8RuntimeOwnerInvalid
		}
		ops = *selectedOps
	}
	file, err := duplicateJailerRecoveryFile(socket)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	stream := &minimalJailerIO{ctx: ctx, file: file, ops: ops, stop: make(chan struct{}), done: make(chan struct{})}
	fd := int(file.Fd())
	go func() {
		defer close(stream.done)
		select {
		case <-ctx.Done():
			stream.shutdownErr = unix.Shutdown(fd, unix.SHUT_RDWR)
		case <-stream.stop:
		}
	}()
	return stream, nil
}

func (stream *minimalJailerIO) close() error {
	close(stream.stop)
	<-stream.done
	closeErr := stream.file.Close()
	if stream.shutdownErr != nil || closeErr != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (stream *minimalJailerIO) exchange(packet l8RuntimeOwnerPacketV1) (l8RuntimeOwnerPacketV1, error) {
	if !minimalJailerCallerCurrent(stream.ctx) {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	budget := l8RuntimeOwnerHandshakeTimeout
	if deadline, ok := stream.ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline))
	}
	if budget < time.Microsecond || setL8RuntimeOwnerSocketTimeout(int(stream.file.Fd()), budget) != nil || !minimalJailerCallerCurrent(stream.ctx) {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	return stream.exchangeOnce(packet)
}

// The selected connector never enters a blocking connect syscall. AF_UNIX may
// return EAGAIN for a full accept queue; retry only that same retained endpoint
// under one original five-second/caller bound. No process or owner is started.
func connectMinimalJailerSocket(ctx context.Context, fd int, path string) error {
	if !minimalJailerCallerCurrent(ctx) {
		return errL8RuntimeOwnerInvalid
	}
	deadline := time.Now().Add(l8RuntimeOwnerHandshakeTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	for {
		if !minimalJailerCallerCurrent(ctx) || !time.Now().Before(deadline) {
			return errL8RuntimeOwnerInvalid
		}
		err := unix.Connect(fd, &unix.SockaddrUnix{Name: path})
		if err == nil || err == unix.EISCONN {
			if unix.SetNonblock(fd, false) != nil || !minimalJailerCallerCurrent(ctx) || !time.Now().Before(deadline) {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		}
		wait := min(10*time.Millisecond, time.Until(deadline))
		if wait <= 0 {
			return errL8RuntimeOwnerInvalid
		}
		switch err {
		case unix.EAGAIN:
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errL8RuntimeOwnerInvalid
			case <-timer.C:
			}
		case unix.EINPROGRESS, unix.EALREADY, unix.EINTR:
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			_, pollErr := unix.Poll(poll, int((wait+time.Millisecond-1)/time.Millisecond))
			if pollErr != nil && pollErr != unix.EINTR {
				return errL8RuntimeOwnerInvalid
			}
			if poll[0].Revents != 0 {
				status, statusErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if statusErr != nil || status != 0 {
					return errL8RuntimeOwnerInvalid
				}
			}
		default:
			return errL8RuntimeOwnerInvalid
		}
	}
}
