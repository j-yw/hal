//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// Keep the actual handshake/FSM/store. Only the ordinary fixture peer's reply
// is modified after the real operation, so lost replies cannot become proof.
func minimalJailerReplyFaultFixture(t *testing.T, opcode uint16, mode string) (*jailerRecoveryWireFixture, *bool) {
	t.Helper()
	f := newJailerRecoveryWireFixture(t)
	enabled := true // Changed by the test only after the exact peer has joined.
	f.ops.connect = func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
		sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(sockets[0]), "selected-reply-fault")
		done := make(chan struct{})
		f.mu.Lock()
		f.lastDone = done
		f.mu.Unlock()
		go func() {
			defer close(done)
			defer unix.Close(sockets[1])
			request, err := receiveL8RuntimeOwnerSeqpacket(sockets[1])
			closeL8RuntimeOwnerFiles(request.Files)
			if err != nil {
				return
			}
			result, err := f.owner.AdmitController(context.Background(), 0, request)
			if err != nil {
				return
			}
			defer f.owner.ControllerLost(context.Background())
			if sendL8RuntimeOwnerControlResult(sockets[1], result) != nil {
				return
			}
			for {
				request, err = receiveL8RuntimeOwnerSeqpacket(sockets[1])
				closeL8RuntimeOwnerFiles(request.Files)
				if err != nil {
					return
				}
				f.mu.Lock()
				f.operations = append(f.operations, request.Packet.Opcode)
				f.mu.Unlock()
				result, err = f.owner.HandleController(context.Background(), request)
				if err != nil {
					return
				}
				if enabled && request.Packet.Opcode == opcode {
					if mode == "drop" {
						return
					}
					wire, err := encodeL8RuntimeOwnerPacket(result.Packet)
					if err != nil {
						return
					}
					switch mode {
					case "sequence":
						binary.BigEndian.PutUint64(wire[16:24], result.Packet.Sequence+1)
					case "opcode":
						binary.BigEndian.PutUint16(wire[10:12], l8RuntimeOwnerOpcodeInspect)
					case "status":
						binary.BigEndian.PutUint16(wire[12:14], l8RuntimeOwnerStatusInvalidState)
					case "body":
						wire[len(wire)-1] ^= 1
					case "trailing":
						wire = append(wire, 0)
					case "short":
						wire = wire[:len(wire)-1]
					default:
						return
					}
					_, _ = unix.SendmsgN(sockets[1], wire, nil, nil, 0)
					return
				}
				if sendL8RuntimeOwnerControlResult(sockets[1], result) != nil || result.Exit {
					return
				}
			}
		}()
		t.Cleanup(func() { _ = file.Close(); <-done })
		return file, nil
	}
	return f, &enabled
}

func TestMinimalJailerFinalizationActualReplyFailuresDoNotCommit(t *testing.T) {
	for _, opcode := range []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize} {
		for _, mode := range []string{"drop", "sequence", "opcode", "status", "body", "trailing", "short"} {
			name := map[uint16]string{l8RuntimeOwnerOpcodeStopReap: "stop", l8RuntimeOwnerOpcodeFinalize: "finalize"}[opcode]
			t.Run(name+"/"+mode, func(t *testing.T) {
				f, enabled := minimalJailerReplyFaultFixture(t, opcode, mode)
				client := f.fresh(t)
				completion, err := client.finalizeMinimalCleanup(context.Background())
				f.waitConnection()
				if err == nil || completion == nil || completion.state.ready || completion.state.acknowledged || client.socket != nil || completion.state.active != nil {
					t.Fatal("invalid actual reply produced usable finalization or retained a session")
				}
				f.mu.Lock()
				operations := slices.Clone(f.operations)
				f.mu.Unlock()
				if !slices.Contains(operations, opcode) || slices.Contains(operations, l8RuntimeOwnerOpcodeCommit) || f.owned.store.selected.retired {
					t.Fatal("fault did not reach its actual operation or prematurely committed", operations)
				}
				if completion.commit(context.Background()) == nil {
					t.Fatal("pending handle guessed finalization from the surviving record")
				}
				if opcode == l8RuntimeOwnerOpcodeFinalize && mode == "body" && !completion.state.quarantined {
					t.Fatal("validly decoded contradictory Finalize ACK did not latch quarantine")
				}
				if completion.state.quarantined {
					// A decoded contradictory ACK is sticky. Restoring transport
					// cannot erase it; it is not an ordinary unavailable reply.
					*enabled = false
					if _, err := client.finalizeMinimalCleanup(context.Background()); err == nil {
						t.Fatal("restored replies erased contradictory finalization")
					}
					return
				}
				*enabled = false
				again, err := client.finalizeMinimalCleanup(context.Background())
				f.waitConnection()
				if err != nil || again != completion || !again.state.ready {
					t.Fatal("explicit same-owner retry did not resume actual cleanup", err)
				}
				f.mu.Lock()
				operations = slices.Clone(f.operations)
				f.mu.Unlock()
				stops := 0
				for _, operation := range operations {
					if operation == l8RuntimeOwnerOpcodeStopReap {
						stops++
					}
				}
				if stops != 1 || slices.Contains(operations, l8RuntimeOwnerOpcodeCommit) {
					t.Fatal("retry repeated Stop or auto-committed", operations)
				}
			})
		}
	}
}

func TestMinimalJailerFinalizationLostOrCorruptCommitAckStaysUnresolved(t *testing.T) {
	for _, mode := range []string{"drop", "sequence", "opcode", "status", "body", "trailing", "short"} {
		t.Run(mode, func(t *testing.T) {
			f, enabled := minimalJailerReplyFaultFixture(t, l8RuntimeOwnerOpcodeCommit, mode)
			client := f.fresh(t)
			completion, err := client.finalizeMinimalCleanup(context.Background())
			f.waitConnection()
			if err != nil || completion == nil {
				t.Fatal("actual retained Finalize prerequisite", err)
			}
			if completion.commit(context.Background()) == nil {
				t.Fatal("invalid Commit reply inferred acknowledgment")
			}
			f.waitConnection()
			if !f.owned.store.selected.retired || completion.state.acknowledged {
				t.Fatal("actual retirement/lost-ACK boundary was not reached")
			}
			*enabled = false
			if completion.commit(context.Background()) == nil || completion.state.acknowledged {
				t.Fatal("missing record was promoted to cached success")
			}
		})
	}
}
