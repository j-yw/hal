//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func waitMinimalJailerConnect(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	buffer := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "[select]") && strings.Contains(stack, "firecrackerhost.connectMinimalJailerSocket") {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("actual full-backlog connect did not reach bounded retry")
		}
	}
}

// This exercises only actual nonblocking AF_UNIX backlog behavior. It does not
// claim the caller-UID fixture passed production root socket/peer validation.
func TestMinimalJailerFinalizationActualBacklogConnectBound(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "close", "becomes_available"} {
		t.Run(mode, func(t *testing.T) {
			_, client, completion := minimalJailerFinalizedFixture(t)
			directory, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			path := "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10) + "/socket"
			newSocket := func() int {
				t.Helper()
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				return fd
			}
			listener := newSocket()
			defer unix.Close(listener)
			if unix.Bind(listener, &unix.SockaddrUnix{Name: path}) != nil || unix.Listen(listener, 0) != nil {
				t.Fatal("private ordinary backlog fixture")
			}
			filler := newSocket()
			defer unix.Close(filler)
			if unix.Connect(filler, &unix.SockaddrUnix{Name: path}) != nil {
				t.Fatal("one queued connection prerequisite")
			}
			candidate := os.NewFile(uintptr(newSocket()), "selected-backlog-candidate")
			defer candidate.Close()
			if err := unix.Connect(int(candidate.Fd()), &unix.SockaddrUnix{Name: path}); !errors.Is(err, unix.EAGAIN) {
				t.Fatal("actual accept backlog was not full", err)
			}
			budget := time.Minute
			if mode == "deadline" {
				budget = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			client.ops.connectMinimal = func(ctx context.Context, _ *os.File, _ firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
				return candidate, connectMinimalJailerSocket(ctx, int(candidate.Fd()), path)
			}
			result := make(chan error, 1)
			go func() {
				if mode == "becomes_available" {
					// The lower helper's success is not a protocol handshake.
					result <- connectMinimalJailerSocket(ctx, int(candidate.Fd()), path)
					return
				}
				result <- completion.commit(ctx)
			}()
			joined := false
			defer func() {
				cancel()
				if !joined {
					_ = joinMinimalJailerResult(t, result)
				}
			}()
			waitMinimalJailerConnect(t)
			var closed chan error
			switch mode {
			case "cancel":
				cancel()
			case "close":
				closed = make(chan error, 1)
				go func() { closed <- client.close() }()
			case "becomes_available":
				accepted, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
				if err != nil {
					t.Fatal("free the one ordinary queued connection", err)
				}
				_ = unix.Close(accepted)
			}
			err = joinMinimalJailerResult(t, result)
			joined = true
			if (err == nil) != (mode == "becomes_available") {
				t.Fatal("backlog result ignored availability/cancellation", err)
			}
			if closed != nil && joinMinimalJailerResult(t, closed) != nil {
				t.Fatal("Close did not join the actual connector")
			}
			if mode == "becomes_available" {
				flags, err := unix.FcntlInt(candidate.Fd(), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_NONBLOCK != 0 {
					t.Fatal("successful helper did not restore the existing blocking exchange mode")
				}
			} else if _, err := candidate.Stat(); err == nil {
				t.Fatal("failed connector's partial returned socket was not closed after join")
			}
			if completion.state.acknowledged {
				t.Fatal("transport availability became Commit proof")
			}
		})
	}
}
