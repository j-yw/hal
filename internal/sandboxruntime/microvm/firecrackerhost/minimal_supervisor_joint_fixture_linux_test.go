//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

// This extends only fixture setup before bootstrap. It retains the accepted
// original FSM/lifecycle/manager and adds a real ordinary cleanup listener.
// Parent/self observations are real read-only observations of a fake topology,
// not proof of an exec'ed supervisor or root/Jailer/native authority.
type minimalSupervisorJointFixture struct {
	*minimalOriginalManagerFixture
	producer  *minimalControlProducerLaunch
	done      chan struct{}
	err       error
	contained atomic.Int32
	listener  atomic.Pointer[minimalControllerGuestListener]
	private   atomic.Bool
}

// The actual manager's stale-socket preflight precedes this existing injected
// starter boundary. Only this new fixture wraps the original fake starter;
// parent creation, manager/FSM, cgroup launch FD and process stay unchanged.
type minimalSupervisorJointStarter struct {
	fixture *minimalSupervisorJointFixture
}

func (starter *minimalSupervisorJointStarter) startStrictJailerNamespaceProcess(ctx context.Context, request strictJailerNamespaceProcessStartRequest) (HostProcess, error) {
	f := starter.fixture
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: f.paths.VsockSocketPath})
	if listener != nil {
		listener.SetUnlinkOnClose(false)
		// Retain even a partial listener before any later fallible setup. The
		// original fixture owns its private directory through all rescue joins.
		f.listener.Store(&minimalControllerGuestListener{listener: listener})
	}
	if err != nil || listener == nil || os.Chmod(f.paths.VsockSocketPath, 0o600) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	info, err := os.Lstat(f.paths.VsockSocketPath)
	parent, parentErr := statStrictJailerPrivateStateDir(f.paths.StateDir, uint32(os.Geteuid()))
	f.tracked.ownerStarter.mu.Lock()
	started := f.tracked.ownerStarter.started
	f.tracked.ownerStarter.mu.Unlock()
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || parentErr != nil || parent != f.parent ||
		f.tracked.calls != 0 || started || ctx.Err() != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	f.private.Store(true) // Historical fixture ordering, never runtime authority.
	return f.tracked.startStrictJailerNamespaceProcess(ctx, request)
}

func withMinimalSupervisorJointFixture(t *testing.T, use func(*minimalSupervisorJointFixture)) {
	t.Helper()
	withMinimalOriginalManagerFixture(t, func(original *minimalOriginalManagerFixture) {
		f := &minimalSupervisorJointFixture{minimalOriginalManagerFixture: original, done: make(chan struct{})}
		if original.owned.selected.attempted || original.owned.listenerFD != -1 {
			t.Fatal("joint setup must precede all original launch/serving")
		}
		original.lifecycle.runner.starter = &minimalSupervisorJointStarter{fixture: f}
		observation, err := inspectL8RuntimeOwnerProcess(original.owned.genesis.SupervisorPID)
		if err != nil {
			t.Fatal("read-only original fixture parent observation", err)
		}
		defer observation.Close()
		// Both sides retain this observation before genesis is ever created.
		original.owned.genesis.SupervisorStartTime = observation.StartTime
		original.owner.opts.GenesisRecord = original.owned.genesis
		original.owner.opts.RandomToken = randomL8RuntimeOwnerToken
		original.owner.opts.commitID = jailerRecoveryCommitID
		original.owner.opts.ContainChild = func() (l8RuntimeOwnerAbsenceObservation, error) {
			f.contained.Add(1)
			return original.owned.containChild()
		}
		original.owner.opts.ReinspectAbsence = original.owned.reinspectAbsence
		original.owner.opts.DuplicateNamespaces = original.owned.duplicateNamespaces
		original.owner.opts.CloseNamespaces = original.owned.closeNamespaces
		original.owner.opts.AbortStartingZero = original.owned.closeNamespaces
		fd, key, err := openL8RuntimeOwnerReconnectListener(original.owned.store.directoryFD, original.owned.genesis.ReconnectListenerIdentity)
		if err != nil {
			t.Fatal("ordinary cleanup listener", err)
		}
		original.owned.listenerFD, original.owned.listenerKey = fd, key
		defer func() {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(original.owned.store.directoryFD, key, 0)
			original.owned.listenerFD, original.owned.listenerKey = -1, ""
		}()
		parent, err := unix.FcntlInt(uintptr(original.peer), unix.F_DUPFD_CLOEXEC, 10)
		if err != nil {
			t.Fatal(err)
		}
		parentFile := os.NewFile(uintptr(parent), "joint-producer-original")
		defer parentFile.Close()
		directoryFD, err := unix.FcntlInt(uintptr(original.owned.store.directoryFD), unix.F_DUPFD_CLOEXEC, 10)
		if err != nil {
			t.Fatal(err)
		}
		directory := os.NewFile(uintptr(directoryFD), "joint-producer-directory")
		defer directory.Close()
		config := original.admission.config
		config.Control.Prelaunch = maps.Clone(config.Control.Prelaunch)
		f.producer = &minimalControlProducerLaunch{original: parentFile, directory: directory, config: config, supervisor: observation}
		// Test rescue only: revoke existing preparation, interrupt the ordinary
		// accept syscall without FD reuse, and join before admission returns.
		// This is not evidence that the unavailable closeIO barrier works.
		started := false
		defer func() {
			original.owned.minimalPreparation.revoke()
			if listener := f.listener.Load(); listener != nil {
				_ = listener.Close()
			}
			_ = unix.Shutdown(fd, unix.SHUT_RDWR)
			if started {
				minimalJointAwait(t, f.done, "explicit serving rescue")
				serving := f.serving(t)
				serving.mu.Lock()
				controller := serving.controller
				serving.mu.Unlock()
				if controller != nil {
					minimalControllerRequireJoined(t, controller, f.admission.controllerKey)
				}
				t.Log("explicit test rescue joined serving/controller and cleared borrowed key; not selected cleanup-barrier evidence")
			}
			// Setup can finish after the first rescue snapshot. Join first, then
			// close the retained partial listener before fixture ownership ends.
			if listener := f.listener.Load(); listener != nil {
				_ = listener.Close()
			}
		}()
		started = true
		go func() {
			defer close(f.done)
			f.err = original.owned.serveMinimalControlSupervisor(original.owner, original.admission)
		}()
		if err := sendL8RuntimeOwnerSeqpacket(original.peer, original.packet, original.files); err != nil {
			t.Fatal("actual original BootstrapStart", err)
		}
		for _, socket := range []int{original.gatePeer, original.peer} {
			if setL8RuntimeOwnerSocketTimeout(socket, time.Second) != nil {
				t.Fatal("bounded bootstrap observation")
			}
		}
		gate, gateErr := receiveL8RuntimeOwnerSeqpacket(original.gatePeer)
		defer closeL8RuntimeOwnerFiles(gate.Files)
		reply, replyErr := receiveL8RuntimeOwnerSeqpacket(original.peer)
		defer closeL8RuntimeOwnerFiles(reply.Files)
		record, recordErr := original.owned.store.Load(context.Background())
		if gateErr != nil || gate.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease || len(gate.Files) != 0 ||
			replyErr != nil || reply.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || len(reply.Files) != 0 ||
			len(reply.Packet.Body) != 8 || binary.BigEndian.Uint64(reply.Packet.Body) != 2 || recordErr != nil || record.Revision != 2 {
			t.Fatal("new serving entry did not reach actual gate/revision-2 reply", gateErr, replyErr, recordErr)
		}
		if !f.private.Load() || f.listener.Load() == nil {
			t.Fatal("original launch advanced before the same listener became private")
		}
		t.Log("same listener was 0600 in the exact original parent before tracked launch, release and controller")
		use(f)
	})
}

func (f *minimalSupervisorJointFixture) serving(t *testing.T) *minimalControlSupervisorServing {
	t.Helper()
	f.owned.mu.Lock()
	serving := f.owned.minimalServing
	f.owned.mu.Unlock()
	if serving == nil || serving.owned != f.owned || serving.owner != f.owner || serving.admission != f.admission {
		t.Fatal("original concrete serving object not retained")
	}
	return serving
}

// Start only the real shared guest; the host controller is constructed by the
// new serving entry, never by this helper or a substitute manager fixture.
func (f *minimalSupervisorJointFixture) guest(t *testing.T, fault *minimalControllerPeerFault) (*minimalJointBackend, *minimalJointVerifier, <-chan struct{}, func()) {
	t.Helper()
	listener := f.listener.Load()
	if listener == nil || !f.private.Load() {
		t.Fatal("shared guest cannot adopt an unprepared fixture listener")
	}
	fc, err := readMinimalControlFirecrackerConfig(f.admission.borrowed[6], f.admission.config.Config)
	if err != nil {
		t.Fatal(err)
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(fc.BootSource.BootArgs)
	if err != nil || !present {
		t.Fatal("actual shared guest boot", err)
	}
	var accepted minimalcontrol.Listener = listener
	if fault != nil {
		accepted = &minimalControllerPeerListener{base: listener, fault: fault}
	}
	ctx, cancel := context.WithCancel(f.owned.minimalPreparation.ctx)
	transport, err := minimalcontrol.NewWorkloadTransport(minimalcontrol.BootstrapOptions{Listener: accepted, Boot: boot,
		OwnerDone: ctx.Done(), Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	backend := &minimalJointBackend{exec: func(context.Context, server.ExecPlan) (server.ExecResult, error) {
		return server.ExecResult{ExitCode: 7, Stdout: []byte("same supervisor work pair\n")}, nil
	}}
	verifier := &minimalJointVerifier{}
	guest, err := server.New(server.Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: verifier,
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = guest.Serve(ctx) }()
	return backend, verifier, done, func() {
		cancel()
		_ = listener.Close()
		minimalJointAwait(t, done, "explicit shared guest rescue")
		if backend.closes.Load() != 1 {
			t.Error("guest backend cleanup not joined exactly once")
		}
	}
}

func (f *minimalSupervisorJointFixture) cleanup(t *testing.T) (int, string) {
	t.Helper()
	record, err := f.owned.store.Load(context.Background())
	if err != nil || record.ControllerState != "unclaimed" {
		t.Fatal("original cleanup record unavailable", err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := "/proc/self/fd/" + strconv.Itoa(f.owned.store.directoryFD) + "/" + f.owned.listenerKey
	if unix.Connect(fd, &unix.SockaddrUnix{Name: path}) != nil || setL8RuntimeOwnerSocketTimeout(fd, time.Second) != nil {
		_ = unix.Close(fd)
		t.Fatal("ordinary original cleanup connection")
	}
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration,
		RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
	if err != nil || sendL8RuntimeOwnerSeqpacket(fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}, nil) != nil {
		_ = unix.Close(fd)
		t.Fatal("original cleanup authentication send", err)
	}
	response, err := receiveL8RuntimeOwnerSeqpacket(fd)
	defer closeL8RuntimeOwnerFiles(response.Files)
	ack, ackErr := decodeL8RuntimeOwnerHandshakeAck(response.Packet.Body)
	if err != nil || ackErr != nil || len(response.Files) != 0 || response.Packet.Opcode != l8RuntimeOwnerOpcodeHandshake || response.Packet.Status != l8RuntimeOwnerStatusOK {
		_ = unix.Close(fd)
		t.Fatal("actual cleanup authentication", err, ackErr)
	}
	return fd, ack.ControllerSessionGeneration
}

func minimalSupervisorJointExchange(fd int, session string, sequence uint64, opcode uint16) (l8RuntimeOwnerReceivedPacketV1, error) {
	body, err := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: session})
	if err != nil || sendL8RuntimeOwnerSeqpacket(fd, l8RuntimeOwnerPacketV1{Opcode: opcode, Sequence: sequence, Body: body}, nil) != nil {
		return l8RuntimeOwnerReceivedPacketV1{}, errors.New("fixture cleanup send failed")
	}
	return receiveL8RuntimeOwnerSeqpacket(fd)
}
