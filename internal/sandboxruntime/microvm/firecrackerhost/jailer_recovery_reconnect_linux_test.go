//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
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
	lastDone   <-chan struct{}
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
			f.mu.Lock()
			f.lastDone = done
			f.mu.Unlock()
			go func() { defer close(done); defer unix.Close(sockets[1]); f.serve(sockets[1]) }()
			t.Cleanup(func() { _ = file.Close(); <-done })
			return file, nil
		},
	}
	return f
}

func (f *jailerRecoveryWireFixture) waitConnection() {
	f.mu.Lock()
	done := f.lastDone
	f.mu.Unlock()
	if done != nil {
		<-done
	}
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
			first := f.fresh(t)
			if err := first.stopAndCommit(context.Background()); err == nil {
				t.Fatal("interruption fixture reported success")
			}
			_ = first.close()
			f.waitConnection()
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
	f.waitConnection()
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

func TestJailerRecoveryFreshClientRejectsUntrustedOrStaleInputs(t *testing.T) {
	for _, name := range []string{"job", "runtime_generation", "directory", "closed_directory", "boot", "pid", "start_time", "zombie", "missing_process", "socket_peer", "nil_socket", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newJailerRecoveryWireFixture(t)
			fd, err := unix.FcntlInt(uintptr(f.owned.store.directoryFD), unix.F_DUPFD_CLOEXEC, 10)
			if err != nil {
				t.Fatal(err)
			}
			directory := os.NewFile(uintptr(fd), "fresh-fixture-directory")
			defer directory.Close()
			expected := f.owned.selected.config.Job
			ops := f.ops
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "job":
				expected.ExecutionID = "wrong-job"
			case "runtime_generation":
				expected.RuntimeGeneration = "wrong-generation"
			case "directory":
				ops.directory = func(*os.File) error { return errors.New("untrusted directory") }
			case "closed_directory":
				_ = directory.Close()
			case "boot":
				ops.bootID = func() (string, error) { return "00000000-0000-0000-0000-000000000099", nil }
			case "pid", "start_time", "zombie", "missing_process":
				ops.inspect = func(pid uint32) (l8RuntimeOwnerProcessObservation, error) {
					actual, _ := f.ops.inspect(pid)
					switch name {
					case "pid":
						actual.PID++
					case "start_time":
						actual.StartTime++
					case "zombie":
						actual.state = 'Z'
					case "missing_process":
						return actual, errors.New("gone")
					}
					return actual, nil
				}
			case "socket_peer":
				ops.connect = func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
					return nil, errors.New("wrong peer/socket identity")
				}
			case "nil_socket":
				ops.connect = func(*os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) { return nil, nil }
			case "canceled":
				cancel()
			}
			client, err := reconnectJailerRecoverySupervisorWithOps(ctx, directory, expected, ops)
			if client != nil {
				_ = client.close()
			}
			if err == nil || client != nil {
				t.Fatal("untrusted fresh reconnect accepted")
			}
			if f.owned.store.selected.terminal || f.owned.selected.coordinator.generation == nil {
				t.Fatal("rejected reconnect changed resource ownership")
			}
		})
	}
}

func TestJailerRecoveryCleanupRecordRejectsMalformedAuthority(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	file, err := openJailerRecoveryRecordFile(f.owned.store.directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	expected := f.owned.selected.config.Job
	if _, err := decodeJailerRecoveryCleanupRecord(payload, expected); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"version", "unknown", "alias", "duplicate", "null", "digest", "reservation", "uid", "config", "checkpoint", "legacy_owner", "oversize"} {
		t.Run(name, func(t *testing.T) {
			var disk jailerRecoveryDiskRecord
			_ = json.Unmarshal(payload, &disk)
			switch name {
			case "version":
				disk.Version = "firecracker-runtime-owner-v1"
			case "digest":
				disk.ConfigCorrelation = "untrusted"
			case "reservation":
				disk.Reservation = nil
			case "uid":
				disk.Reservation.UID = 0
			case "config":
				disk.Reservation.Config = "bad"
			case "checkpoint":
				disk.Owner = []byte(strings.Replace(string(disk.Owner), `"state":"running"`, `"state":"absent"`, 1))
			case "legacy_owner":
				disk.Owner = []byte(strings.Replace(string(disk.Owner), `{`, `{"vsockGeneration":"invented",`, 1))
			}
			bad, _ := json.Marshal(disk)
			switch name {
			case "unknown":
				bad = append([]byte(`{"unexpected":0,`), bad[1:]...)
			case "alias":
				bad = []byte(strings.Replace(string(bad), `"version"`, `"Version"`, 1))
			case "duplicate":
				bad = append([]byte(`{"version":"duplicate",`), bad[1:]...)
			case "null":
				bad = []byte(strings.Replace(string(bad), `"cleanupCheckpoint":false`, `"cleanupCheckpoint":null`, 1))
			case "oversize":
				bad = bytes.Repeat([]byte(" "), l8RuntimeOwnerRecordLimit+1)
			}
			if _, err := decodeJailerRecoveryCleanupRecord(bad, expected); err == nil {
				t.Fatal("malformed selected record accepted")
			}
		})
	}
}

func TestJailerRecoveryFreshClientCancellationCloseAndStaleSession(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	first := f.fresh(t)
	staleSession := first.session
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if first.stopAndCommit(ctx) == nil {
		t.Fatal("canceled cleanup succeeded")
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	f.waitConnection()
	if first.stopAndCommit(context.Background()) == nil {
		t.Fatal("closed client reclaimed authority")
	}
	second := f.fresh(t)
	body, _ := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: staleSession})
	if _, err := jailerRecoveryClientExchange(context.Background(), int(second.socket.Fd()), l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: body}); err == nil {
		t.Fatal("stale session reached cleanup")
	}
	_ = second.close()
	f.waitConnection()
	if f.owned.store.selected.terminal || f.owned.selected.coordinator.generation == nil {
		t.Fatal("rejected session changed ownership")
	}
	last := f.fresh(t)
	if err := last.stopAndCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestJailerRecoveryFreshConstructorRejectsMalformedCurrentRecord(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	if _, err := f.owned.store.selected.file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.FcntlInt(uintptr(f.owned.store.directoryFD), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), "malformed-owner-record")
	defer directory.Close()
	client, err := reconnectJailerRecoverySupervisorWithOps(context.Background(), directory, f.owned.selected.config.Job, f.ops)
	if client != nil {
		_ = client.close()
	}
	if err == nil || client != nil {
		t.Fatal("malformed disk record authenticated")
	}
	if f.owned.store.selected.terminal || f.owned.selected.coordinator.generation == nil {
		t.Fatal("malformed record released resources")
	}
}
