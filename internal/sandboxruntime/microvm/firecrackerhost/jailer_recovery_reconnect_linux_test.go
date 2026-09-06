//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Actual new-client code, canonical ordinary-file records and seqpacket wire;
// host/process/peer observations and the VM lifecycle are deliberately fake.
type jailerRecoveryWireFixture struct {
	mu         sync.Mutex
	owner      *l8RuntimeOwnerSupervisor
	owned      *l8RuntimeOwnerLinuxRuntime
	ops        jailerRecoveryReconnectOps
	operations []uint16
	dropCommit bool
}

func newJailerRecoveryWireFixture(t *testing.T) *jailerRecoveryWireFixture {
	t.Helper()
	owned, _, _, _ := jailerRecoveryRuntimeFixture(t)
	f := &jailerRecoveryWireFixture{owned: owned}
	next := byte(20)
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: owned.store, GenesisRecord: owned.genesis, ExpectedUID: 0, CommitKey: make([]byte, 32), CommitID: jailerRecoveryCommitID, RandomToken: func() (string, error) { next++; return l8RuntimeOwnerTestToken(next), nil }, StartChild: owned.startChild, ContainChild: owned.containChild, ReinspectAbsence: owned.reinspectAbsence, CloseNamespaces: owned.closeNamespaces})
	if err != nil {
		t.Fatal(err)
	}
	f.owner = owner
	_, err = owner.HandleBootstrap(context.Background(), 0, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: make([]byte, 32)}, Files: make([]*os.File, 2)})
	if err != nil {
		t.Fatal(err)
	}
	f.ops = jailerRecoveryReconnectOps{
		directory: func(*os.File) error { return nil },
		bootID:    func() (string, error) { return owned.genesis.HostBootID, nil },
		inspect: func(pid uint32) (l8RuntimeOwnerProcessObservation, error) {
			return l8RuntimeOwnerProcessObservation{PID: pid, StartTime: owned.genesis.SupervisorStartTime}, nil
		},
		connect: func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
			sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return nil, err
			}
			file := os.NewFile(uintptr(sockets[0]), "fresh-client-wire")
			done := make(chan struct{})
			go func() { defer close(done); defer unix.Close(sockets[1]); f.serve(sockets[1]) }()
			t.Cleanup(func() { _ = file.Close(); <-done })
			return file, nil
		},
	}
	return f
}

func (f *jailerRecoveryWireFixture) serve(fd int) {
	request, err := receiveL8RuntimeOwnerSeqpacket(fd)
	if err != nil {
		return
	}
	closeL8RuntimeOwnerFiles(request.Files)
	result, err := f.owner.AdmitController(context.Background(), 0, request)
	if err != nil {
		return
	}
	defer f.owner.ControllerLost(context.Background())
	if sendL8RuntimeOwnerControlResult(fd, result) != nil {
		return
	}
	for {
		request, err = receiveL8RuntimeOwnerSeqpacket(fd)
		if err != nil {
			return
		}
		closeL8RuntimeOwnerFiles(request.Files)
		f.mu.Lock()
		f.operations = append(f.operations, request.Packet.Opcode)
		drop := f.dropCommit && request.Packet.Opcode == l8RuntimeOwnerOpcodeCommit
		f.mu.Unlock()
		result, err = f.owner.HandleController(context.Background(), request)
		if err != nil || drop {
			return
		}
		if sendL8RuntimeOwnerControlResult(fd, result) != nil || result.Exit {
			return
		}
	}
}

func (f *jailerRecoveryWireFixture) fresh(t *testing.T) *jailerRecoveryClient {
	t.Helper()
	// Only the independently expected job tuple and trusted directory cross
	// this constructor. No initiating client, config, manager or lease is used.
	fd, err := unix.FcntlInt(uintptr(f.owned.store.directoryFD), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "fresh-daemon-owner-directory")
	defer directory.Close()
	client, err := reconnectJailerRecoverySupervisorWithOps(context.Background(), directory, f.owned.selected.config.Job, f.ops)
	if err != nil || client == nil {
		t.Fatalf("fresh daemon cannot authenticate surviving owner: %v", err)
	}
	t.Cleanup(func() { _ = client.close() })
	return client
}

func TestJailerRecoveryFreshDaemonClientUsesSurvivingOwner(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	if err := client.stopAndCommit(context.Background()); err != nil {
		t.Fatalf("fresh cleanup: %v", err)
	}
	f.mu.Lock()
	got := slices.Clone(f.operations)
	f.mu.Unlock()
	if !slices.Equal(got, []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit}) {
		t.Fatalf("cleanup operations %v", got)
	}
}

func TestJailerRecoveryFreshClientResumesFinalizingAndFinalized(t *testing.T) {
	for _, state := range []string{"finalizing", "finalized"} {
		t.Run(state, func(t *testing.T) {
			f := newJailerRecoveryWireFixture(t)
			if state == "finalizing" {
				f.owner.opts.CloseNamespaces = func() error { return errors.New("fixture finalization interrupted") }
			}
			first := f.fresh(t)
			if state == "finalized" {
				f.mu.Lock()
				f.dropCommit = true
				f.mu.Unlock()
			}
			// For finalized, stop after a persisted finalization instead of allowing
			// commit retirement; the transport test below covers actual ACK loss.
			if state == "finalized" {
				f.owner.opts.Store = &jailerRecoveryRejectCommitStore{l8RuntimeOwnerRecordStore: f.owned.store}
			}
			if err := first.stopAndCommit(context.Background()); err == nil {
				t.Fatal("interruption fixture reported success")
			}
			_ = first.close()
			f.owner.opts.CloseNamespaces = f.owned.closeNamespaces
			f.owner.opts.Store = f.owned.store
			f.mu.Lock()
			f.dropCommit = false
			f.operations = nil
			f.mu.Unlock()
			fresh := f.fresh(t)
			if err := fresh.stopAndCommit(context.Background()); err != nil {
				t.Fatalf("fresh %s retry: %v", state, err)
			}
			f.mu.Lock()
			got := slices.Clone(f.operations)
			f.mu.Unlock()
			if !slices.Equal(got, []uint16{l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit}) {
				t.Fatalf("%s retry repeated stop: %v", state, got)
			}
		})
	}
}

type jailerRecoveryRejectCommitStore struct{ l8RuntimeOwnerRecordStore }

func (*jailerRecoveryRejectCommitStore) RetireFinalized(context.Context, uint64, string) error {
	return errors.New("fixture commit unavailable")
}

func TestJailerRecoveryMissingRecordAndLostCommitAckStayUnresolved(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	client := f.fresh(t)
	f.mu.Lock()
	f.dropCommit = true
	f.mu.Unlock()
	if err := client.stopAndCommit(context.Background()); err == nil {
		t.Fatal("lost commit reply inferred success")
	}
	_ = client.close()
	fd, err := unix.FcntlInt(uintptr(f.owned.store.directoryFD), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "fresh-daemon-missing-record")
	defer directory.Close()
	if next, err := reconnectJailerRecoverySupervisorWithOps(context.Background(), directory, f.owned.selected.config.Job, f.ops); err == nil || next != nil {
		t.Fatal("missing record became completed recovery")
	}
}
