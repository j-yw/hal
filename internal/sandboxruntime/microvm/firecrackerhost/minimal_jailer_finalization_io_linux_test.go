//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func minimalJailerFinalizedFixture(t *testing.T) (*jailerRecoveryWireFixture, *jailerRecoveryClient, *minimalJailerFinalization) {
	t.Helper()
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	completion, err := client.finalizeMinimalCleanup(context.Background())
	if err != nil || completion == nil {
		t.Fatal("actual Finalize prerequisite", err)
	}
	f.waitConnection()
	return f, client, completion
}

// A bounded stack observation distinguishes actual blocked exchange I/O from
// merely entering a fake connector. No stack bytes leave the test process.
func waitMinimalJailerExchange(t *testing.T, syscallName string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	buffer := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "firecrackerhost.(*minimalJailerIO).exchange") &&
				strings.Contains(stack, "firecrackerhost.(*jailerRecoveryClient).authenticateWithMinimal") &&
				strings.Contains(strings.ToLower(stack), syscallName) {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("selected exchange did not reach actual blocked", syscallName)
		}
	}
}

func joinMinimalJailerResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("selected task did not join within the fixture bound")
		return nil
	}
}

func TestMinimalJailerFinalizationBlockedActualExchangeJoins(t *testing.T) {
	for _, direction := range []string{"sendmsg", "recvmsg"} {
		for _, loss := range []string{"cancel", "deadline", "close"} {
			t.Run(direction+"/"+loss, func(t *testing.T) {
				f, client, completion := minimalJailerFinalizedFixture(t)
				sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				socket := os.NewFile(uintptr(sockets[0]), "selected-blocked-exchange")
				defer socket.Close()
				defer unix.Close(sockets[1])
				if direction == "sendmsg" {
					if unix.SetsockoptInt(sockets[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096) != nil {
						t.Fatal("bounded send buffer prerequisite")
					}
					full := false
					for count := 0; count < 128; count++ {
						_, err := unix.SendmsgN(sockets[0], make([]byte, 1024), nil, nil, unix.MSG_DONTWAIT)
						if errors.Is(err, unix.EAGAIN) {
							full = true
							break
						}
						if err != nil {
							t.Fatal("fill ordinary fixture queue", err)
						}
					}
					if !full {
						t.Fatal("actual send queue did not fill within its bound")
					}
				}
				// This peer deliberately supplies no handshake response. Queue
				// filler is not a protocol packet or runtime authority.
				client.ops.connectMinimal = func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
					return socket, nil
				}
				budget := time.Minute
				if loss == "deadline" {
					budget = time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), budget)
				defer cancel()
				operation := make(chan error, 1)
				go func() { operation <- completion.commit(ctx) }()
				joined := false
				defer func() {
					cancel()
					_ = unix.Shutdown(sockets[1], unix.SHUT_RDWR)
					if !joined {
						_ = joinMinimalJailerResult(t, operation)
					}
				}()
				waitMinimalJailerExchange(t, direction)
				if !client.mu.TryLock() {
					t.Fatal("selected I/O holds client mutex")
				}
				client.mu.Unlock()
				completion.state.mu.Lock()
				attempt := completion.state.active
				completion.state.mu.Unlock()
				if attempt == nil {
					t.Fatal("blocked actual exchange lost its admitted attempt")
				}
				var closed chan error
				if loss == "cancel" {
					cancel()
				} else if loss == "close" {
					closed = make(chan error, 1)
					go func() { closed <- client.close() }()
				}
				operationErr := joinMinimalJailerResult(t, operation)
				joined = true
				if operationErr == nil {
					t.Fatal("interrupted handshake returned Commit success")
				}
				if closed != nil && joinMinimalJailerResult(t, closed) != nil {
					t.Fatal("selected Close failed after joining its blocked exchange")
				}
				select {
				case <-attempt.done:
				default:
					t.Fatal("operation result preceded attempt join")
				}
				if attempt.stream != nil || completion.state.active != nil || completion.state.acknowledged {
					t.Fatal("interruption retained live exchange or fabricated ACK")
				}
				if _, err := socket.Stat(); err == nil {
					t.Fatal("owned returned connector socket survived joined failure")
				}
				if _, err := unix.FcntlInt(uintptr(sockets[1]), unix.F_GETFD, 0); err != nil {
					t.Fatal("client disposed the independent peer", err)
				}
				if record, err := f.owned.store.Load(context.Background()); err != nil || record.State != "finalized" || f.owned.store.selected.retired {
					t.Fatal("failed reauthentication changed retained finalization", err)
				}
				if loss != "close" {
					client.ops.connectMinimal = f.ops.connectMinimal
					if completion.commit(context.Background()) != nil {
						t.Fatal("explicit same-owner retry failed after canceled exchange")
					}
					f.waitConnection()
				}
			})
		}
	}
}
