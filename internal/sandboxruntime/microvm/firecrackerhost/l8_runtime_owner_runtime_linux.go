//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

const (
	l8RuntimeOwnerReconnectPrefix = ".runtime-owner-"
	l8RuntimeOwnerReconnectSuffix = ".sock"
	l8RuntimeOwnerRequiredSeals   = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
)

type l8RuntimeOwnerLinuxRuntime struct {
	config      l8RuntimeOwnerSupervisorConfigV1
	store       *l8RuntimeOwnerLinuxRecordStore
	genesis     firecrackerRuntimeOwnerRecordV1
	commitKey   []byte
	listenerFD  int
	listenerKey string
	configFD    int
	assetFDs    [2]int

	mu         sync.Mutex
	namespaces [2]*os.File
	child      *l8RuntimeOwnerLinuxChild
	contain    l8RuntimeOwnerContainmentController
}

type l8RuntimeOwnerLinuxRecordStore struct {
	directoryFD int
	seed        sandboxruntime.JobCredentialIdentitySeed
	bootID      string
}

func runL8RuntimeOwnerSupervisorLinux(fds [6]int) error {
	owned, err := newL8RuntimeOwnerLinuxRuntime(fds)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer owned.close()
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store:               owned.store,
		GenesisRecord:       owned.genesis,
		ExpectedUID:         owned.config.DaemonUID,
		RandomToken:         randomL8RuntimeOwnerToken,
		StartChild:          owned.startChild,
		ContainChild:        owned.containChild,
		ReinspectAbsence:    owned.reinspectAbsence,
		DuplicateNamespaces: owned.duplicateNamespaces,
		CloseNamespaces:     owned.closeNamespaces,
		AbortStartingZero:   owned.closeNamespaces,
		CommitKey:           owned.commitKey,
	})
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer clear(owner.opts.CommitKey)
	if err := owned.serveBootstrap(owner, fds[0]); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := owned.serveControllers(owner); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func runL8RuntimeOwnerChildGateLinux(fds [6]int) error {
	if validateL8RuntimeOwnerSeqpacketFD(fds[0]) != nil {
		return errL8RuntimeOwnerInvalid
	}
	config, err := readL8RuntimeOwnerSupervisorConfigFD(fds[1])
	if err != nil || validateL8RuntimeOwnerNamespacePair(fds[2], fds[3]) != nil ||
		validateL8RuntimeOwnerAssetFD(fds[4], config.Kernel) != nil || validateL8RuntimeOwnerAssetFD(fds[5], config.Rootfs) != nil {
		return errL8RuntimeOwnerInvalid
	}
	parentPID := os.Getppid()
	if parentPID <= 1 {
		return errL8RuntimeOwnerInvalid
	}
	return runL8RuntimeOwnerChildGate(l8RuntimeOwnerChildGateOps{
		ArmPdeathsigAndVerifyParent: func() error {
			if unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil || os.Getppid() != parentPID {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		SendArmed: func() error {
			return sendL8RuntimeOwnerSeqpacket(fds[0], l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, nil)
		},
		AwaitRelease: func() error {
			if setL8RuntimeOwnerSocketTimeout(fds[0], l8RuntimeOwnerHandshakeTimeout) != nil {
				return errL8RuntimeOwnerInvalid
			}
			received, err := receiveL8RuntimeOwnerSeqpacket(fds[0])
			if err != nil {
				return errL8RuntimeOwnerInvalid
			}
			defer closeL8RuntimeOwnerFiles(received.Files)
			if validateL8RuntimeOwnerPacketRole(received.Packet, true, len(received.Files)) != nil || received.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		RemapAndExec: func() error {
			return remapAndExecL8RuntimeOwnerChild(config, [4]int{fds[2], fds[3], fds[4], fds[5]}, l8RuntimeOwnerFDRemapOps{
				DuplicateAtLeast: func(fd, minimum int) (int, error) {
					return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, minimum)
				},
				Dup3:      unix.Dup3,
				Close:     unix.Close,
				CloseFrom: func(first int) error { return unix.CloseRange(uint(first), ^uint(0), 0) },
				Exec:      unix.Exec,
			})
		},
	})
}

func newL8RuntimeOwnerLinuxRuntime(fds [6]int) (*l8RuntimeOwnerLinuxRuntime, error) {
	if validateL8RuntimeOwnerSeqpacketFD(fds[0]) != nil || validateL8RuntimeOwnerDirectoryFD(fds[1]) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	config, err := readL8RuntimeOwnerSupervisorConfigFD(fds[2])
	if err != nil || config.DaemonUID != uint32(os.Geteuid()) ||
		validateL8RuntimeOwnerAssetFD(fds[3], config.Kernel) != nil || validateL8RuntimeOwnerAssetFD(fds[4], config.Rootfs) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	keyFD, err := unix.FcntlInt(uintptr(fds[5]), unix.F_DUPFD_CLOEXEC, 9)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	key, err := loadL8RuntimeOwnerStableKeyFD(keyFD, config.DaemonUID, realL8RuntimeOwnerKeyFDOps())
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	keepKey := false
	defer func() {
		if !keepKey {
			clear(key)
		}
	}()
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	supervisor, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer supervisor.Close()
	supervisorGeneration, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	listenerIdentity, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	reconnectSecret, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	listenerFD, listenerKey, err := openL8RuntimeOwnerReconnectListener(fds[1], listenerIdentity)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	seedDigest, err := l8RuntimeOwnerSeedDigest(config.Seed)
	if err != nil {
		_ = unix.Close(listenerFD)
		_ = unix.Unlinkat(fds[1], listenerKey, 0)
		return nil, errL8RuntimeOwnerInvalid
	}
	owned := &l8RuntimeOwnerLinuxRuntime{
		config:      config,
		store:       &l8RuntimeOwnerLinuxRecordStore{directoryFD: fds[1], seed: config.Seed, bootID: bootID},
		commitKey:   key,
		listenerFD:  listenerFD,
		listenerKey: listenerKey,
		configFD:    fds[2],
		assetFDs:    [2]int{fds[3], fds[4]},
	}
	owned.genesis = l8RuntimeOwnerGenesisRecord(config.Seed, bootID, supervisorGeneration, listenerIdentity, reconnectSecret, supervisor, seedDigest)
	keepKey = true
	return owned, nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) close() {
	if owned == nil {
		return
	}
	owned.mu.Lock()
	child := owned.child
	owned.mu.Unlock()
	if child != nil {
		_ = child.abort()
		_ = child.close()
	}
	_ = owned.closeNamespaces()
	if owned.listenerFD >= 0 {
		_ = unix.Close(owned.listenerFD)
		owned.listenerFD = -1
	}
	if owned.listenerKey != "" && owned.store != nil {
		_ = unix.Unlinkat(owned.store.directoryFD, owned.listenerKey, 0)
	}
	for index := range owned.commitKey {
		owned.commitKey[index] = 0
	}
}

func (owned *l8RuntimeOwnerLinuxRuntime) serveBootstrap(owner *l8RuntimeOwnerSupervisor, fd int) error {
	if owner == nil || setL8RuntimeOwnerSocketTimeout(fd, l8RuntimeOwnerHandshakeTimeout) != nil {
		return errL8RuntimeOwnerInvalid
	}
	uid, err := l8RuntimeOwnerPeerUID(fd)
	if err != nil || uid != owned.config.DaemonUID {
		return errL8RuntimeOwnerInvalid
	}
	received, err := receiveL8RuntimeOwnerSeqpacket(fd)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	transferred := false
	defer func() {
		if !transferred {
			closeL8RuntimeOwnerFiles(received.Files)
		}
	}()
	if validateL8RuntimeOwnerPacketRole(received.Packet, false, len(received.Files)) != nil || received.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapStart {
		return errL8RuntimeOwnerInvalid
	}
	correlation, err := decodeL8RuntimeOwnerNamespaceCorrelation(received.Packet.Body)
	if err != nil || validateL8RuntimeOwnerNamespaceFiles(received.Files, correlation) != nil {
		return errL8RuntimeOwnerInvalid
	}
	owned.mu.Lock()
	if owned.namespaces[0] != nil || owned.namespaces[1] != nil {
		owned.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	copy(owned.namespaces[:], received.Files)
	owned.mu.Unlock()
	transferred = true
	result, err := owner.HandleBootstrap(context.Background(), uid, received)
	if err != nil || sendL8RuntimeOwnerControlResult(fd, result) != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) serveControllers(owner *l8RuntimeOwnerSupervisor) error {
	for {
		fd, _, err := unix.Accept4(owned.listenerFD, unix.SOCK_CLOEXEC)
		if err != nil {
			return errL8RuntimeOwnerInvalid
		}
		exit, controllerErr := owned.serveController(owner, fd)
		_ = unix.Close(fd)
		if controllerErr != nil {
			continue
		}
		if exit {
			return nil
		}
	}
}

func (owned *l8RuntimeOwnerLinuxRuntime) serveController(owner *l8RuntimeOwnerSupervisor, fd int) (bool, error) {
	if owner == nil || setL8RuntimeOwnerSocketTimeout(fd, l8RuntimeOwnerHandshakeTimeout) != nil {
		return false, errL8RuntimeOwnerInvalid
	}
	uid, err := l8RuntimeOwnerPeerUID(fd)
	if err != nil || uid != owned.config.DaemonUID {
		_ = sendL8RuntimeOwnerReject(fd)
		return false, errL8RuntimeOwnerInvalid
	}
	received, err := receiveL8RuntimeOwnerSeqpacket(fd)
	if err != nil {
		_ = sendL8RuntimeOwnerReject(fd)
		return false, errL8RuntimeOwnerInvalid
	}
	defer closeL8RuntimeOwnerFiles(received.Files)
	if validateL8RuntimeOwnerPacketRole(received.Packet, false, len(received.Files)) != nil || received.Packet.Opcode != l8RuntimeOwnerOpcodeHandshake {
		_ = sendL8RuntimeOwnerReject(fd)
		return false, errL8RuntimeOwnerInvalid
	}
	result, err := owner.AdmitController(context.Background(), uid, received)
	if err != nil {
		_ = sendL8RuntimeOwnerReject(fd)
		return false, errL8RuntimeOwnerInvalid
	}
	if sendL8RuntimeOwnerControlResult(fd, result) != nil || setL8RuntimeOwnerSocketTimeout(fd, 0) != nil {
		_ = owner.ControllerLost(context.Background())
		return false, errL8RuntimeOwnerInvalid
	}
	for {
		request, err := receiveL8RuntimeOwnerSeqpacket(fd)
		if err != nil {
			_ = owner.ControllerLost(context.Background())
			return false, errL8RuntimeOwnerInvalid
		}
		if validateL8RuntimeOwnerPacketRole(request.Packet, false, len(request.Files)) != nil {
			closeL8RuntimeOwnerFiles(request.Files)
			_ = sendL8RuntimeOwnerReject(fd)
			_ = owner.ControllerLost(context.Background())
			return false, errL8RuntimeOwnerInvalid
		}
		response, handleErr := owner.HandleController(context.Background(), request)
		closeL8RuntimeOwnerFiles(request.Files)
		if handleErr != nil || sendL8RuntimeOwnerControlResult(fd, response) != nil {
			_ = sendL8RuntimeOwnerReject(fd)
			_ = owner.ControllerLost(context.Background())
			return false, errL8RuntimeOwnerInvalid
		}
		if request.Packet.Opcode == l8RuntimeOwnerOpcodeClose {
			return false, nil
		}
		if response.Exit {
			return true, nil
		}
	}
}

func (owned *l8RuntimeOwnerLinuxRuntime) startChild() (l8RuntimeOwnerStartedChild, error) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if owned.child != nil || owned.namespaces[0] == nil || owned.namespaces[1] == nil {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	child, err := startL8RuntimeOwnerLinuxChild(owned.configFD, owned.namespaces, owned.assetFDs)
	if err != nil {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	owned.child = child
	return l8RuntimeOwnerStartedChild{
		Observation: child.observation,
		Release:     child.release,
		Abort:       child.abort,
	}, nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) containChild() (l8RuntimeOwnerAbsenceObservation, error) {
	owned.mu.Lock()
	child := owned.child
	owned.mu.Unlock()
	if child == nil {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	return owned.contain.Stop(l8RuntimeOwnerContainmentOps{
		RecordStopping:  func() (uint64, error) { return 1, nil },
		Terminate:       func() error { return child.signal(syscall.SIGTERM) },
		Wait:            child.wait,
		Kill:            func() error { return child.signal(syscall.SIGKILL) },
		RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { return 1, nil },
		RecordUncertain: func() (uint64, error) { return 1, nil },
		Now:             time.Now,
	})
}

func (owned *l8RuntimeOwnerLinuxRuntime) reinspectAbsence() (l8RuntimeOwnerAbsenceObservation, error) {
	owned.mu.Lock()
	child := owned.child
	owned.mu.Unlock()
	if child == nil {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerHandshakeTimeout)
	defer cancel()
	reaped, err := child.wait(ctx)
	if err != nil || !reaped {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: time.Now()}, nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) duplicateNamespaces() ([]int, error) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	result := make([]int, 0, 2)
	for _, namespace := range owned.namespaces {
		if namespace == nil {
			for _, fd := range result {
				_ = unix.Close(fd)
			}
			return nil, errL8RuntimeOwnerInvalid
		}
		fd, err := unix.FcntlInt(namespace.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			for _, opened := range result {
				_ = unix.Close(opened)
			}
			return nil, errL8RuntimeOwnerInvalid
		}
		result = append(result, fd)
	}
	return result, nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) closeNamespaces() error {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	var failed bool
	for index, namespace := range owned.namespaces {
		if namespace != nil {
			failed = namespace.Close() != nil || failed
			owned.namespaces[index] = nil
		}
	}
	if failed {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (store *l8RuntimeOwnerLinuxRecordStore) Load(ctx context.Context) (firecrackerRuntimeOwnerRecordV1, error) {
	record, present, err := store.withLock(ctx, unix.LOCK_SH, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		return readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
	})
	if err != nil || !present {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return record, nil
}

func (store *l8RuntimeOwnerLinuxRecordStore) RecordAbsent(ctx context.Context) (bool, error) {
	_, present, err := store.withLock(ctx, unix.LOCK_SH, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		return readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
	})
	if err != nil {
		return false, errL8RuntimeOwnerInvalid
	}
	return !present, nil
}

func (store *l8RuntimeOwnerLinuxRecordStore) CreateGenesis(ctx context.Context, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	record, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		_, present, readErr := readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
		if readErr != nil || present || next.Revision != 0 || next.State != "starting" || next.ControllerState != "none" {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		if writeL8RuntimeOwnerRecordAt(store.directoryFD, next, store.seed, store.bootID) != nil {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		return next, true, nil
	})
	return record, err
}

func (store *l8RuntimeOwnerLinuxRecordStore) Transition(ctx context.Context, expected uint64, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	record, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		current, present, readErr := readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
		if readErr != nil || !present || current.Revision != expected || !validL8RuntimeOwnerTransition(current, next) {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		if writeL8RuntimeOwnerRecordAt(store.directoryFD, next, store.seed, store.bootID) != nil {
			observed, observedPresent, observedErr := readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
			if observedErr != nil || !observedPresent || observed != next {
				return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
			}
		}
		return next, true, nil
	})
	return record, err
}

func (store *l8RuntimeOwnerLinuxRecordStore) RetireStartingZero(ctx context.Context, expected uint64) error {
	return store.retire(ctx, func(record firecrackerRuntimeOwnerRecordV1) bool {
		return expected == 0 && record.Revision == 0 && record.State == "starting" && record.ControllerState == "none" && record.FirecrackerPID == 0
	})
}

func (store *l8RuntimeOwnerLinuxRecordStore) RetireFinalized(ctx context.Context, expected uint64, commitID string) error {
	return store.retire(ctx, func(record firecrackerRuntimeOwnerRecordV1) bool {
		return record.State == "finalized" && record.Revision == expected && record.FinalizedCommitID == commitID
	})
}

func (store *l8RuntimeOwnerLinuxRecordStore) retire(ctx context.Context, accept func(firecrackerRuntimeOwnerRecordV1) bool) error {
	_, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		record, present, readErr := readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
		if readErr != nil || !present || accept == nil || !accept(record) || unix.Unlinkat(store.directoryFD, l8RuntimeOwnerRecordName, 0) != nil || unix.Fsync(store.directoryFD) != nil {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		return record, false, nil
	})
	return err
}

func (store *l8RuntimeOwnerLinuxRecordStore) withLock(ctx context.Context, operation int, fn func() (firecrackerRuntimeOwnerRecordV1, bool, error)) (firecrackerRuntimeOwnerRecordV1, bool, error) {
	if store == nil || store.directoryFD < 0 || fn == nil || ctx == nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	for {
		lockErr := unix.Flock(store.directoryFD, operation|unix.LOCK_NB)
		if lockErr == nil {
			break
		}
		if !errors.Is(lockErr, unix.EWOULDBLOCK) && !errors.Is(lockErr, unix.EAGAIN) {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		select {
		case <-ctx.Done():
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		case <-time.After(10 * time.Millisecond):
		}
	}
	record, present, err := fn()
	if unix.Flock(store.directoryFD, unix.LOCK_UN) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	return record, present, err
}

func writeL8RuntimeOwnerRecordAt(directoryFD int, record firecrackerRuntimeOwnerRecordV1, seed sandboxruntime.JobCredentialIdentitySeed, bootID string) error {
	payload, err := encodeFirecrackerRuntimeOwnerRecordV1(record, seed, bootID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	temporary := ".runtime-owner-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	remove := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if remove {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if unix.Fchmod(fd, 0o600) != nil || writeL8RuntimeOwnerRecordPayload(fd, payload) != nil || unix.Fsync(fd) != nil || unix.Close(fd) != nil {
		fd = -1
		return errL8RuntimeOwnerInvalid
	}
	fd = -1
	if unix.Renameat(directoryFD, temporary, directoryFD, l8RuntimeOwnerRecordName) != nil {
		return errL8RuntimeOwnerInvalid
	}
	remove = false
	if unix.Fsync(directoryFD) != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func l8RuntimeOwnerGenesisRecord(seed sandboxruntime.JobCredentialIdentitySeed, bootID, supervisorGeneration, listenerIdentity, reconnectSecret string, supervisor l8RuntimeOwnerProcessObservation, seedDigest [32]byte) firecrackerRuntimeOwnerRecordV1 {
	return firecrackerRuntimeOwnerRecordV1{
		ContractVersion:              l8RuntimeOwnerContractVersion,
		State:                        "starting",
		ControllerState:              "none",
		HostBootID:                   bootID,
		SeedCorrelationDigest:        hex.EncodeToString(seedDigest[:]),
		SupervisorGeneration:         supervisorGeneration,
		SupervisorPID:                supervisor.PID,
		SupervisorStartTime:          supervisor.StartTime,
		SandboxID:                    seed.SandboxID,
		ExecutionID:                  seed.ExecutionID,
		WorkerID:                     seed.WorkerID,
		HostID:                       seed.HostID,
		RuntimeDriver:                seed.RuntimeDriver,
		RuntimeID:                    seed.RuntimeID,
		RuntimeGeneration:            seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration,
		VsockGeneration:              seed.VsockGeneration,
		NetworkPlanID:                seed.NetworkPlanID,
		PolicySnapshotID:             seed.PolicySnapshotID,
		ProxySessionID:               seed.ProxySessionID,
		ProxyGenerationID:            seed.ProxyGenerationID,
		TopologyGenerationID:         seed.TopologyGenerationID,
		RuleGenerationID:             seed.RuleGenerationID,
		ReconnectListenerIdentity:    listenerIdentity,
		ReconnectSecret:              reconnectSecret,
	}
}

func randomL8RuntimeOwnerToken() (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", errL8RuntimeOwnerInvalid
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func readL8RuntimeOwnerSupervisorConfigFD(fd int) (l8RuntimeOwnerSupervisorConfigV1, error) {
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, l8RuntimeOwnerSupervisorConfigLimit)
	if err != nil || identity.Size <= 0 {
		return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, identity.Size)
	read, err := unix.Pread(fd, payload, 0)
	if err != nil || read != len(payload) {
		return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
	}
	return decodeL8RuntimeOwnerSupervisorConfig(payload)
}

func validateL8RuntimeOwnerAssetFD(fd int, expected l8RuntimeOwnerDescriptorIdentityV1) error {
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, 0)
	if err != nil || identity.Size <= 0 || identity.Device != expected.Device || identity.Inode != expected.Inode {
		return errL8RuntimeOwnerInvalid
	}
	digest := sha256.New()
	buffer := make([]byte, 128<<10)
	var offset int64
	for offset < identity.Size {
		limit := int64(len(buffer))
		if remaining := identity.Size - offset; remaining < limit {
			limit = remaining
		}
		read, err := unix.Pread(fd, buffer[:limit], offset)
		if err != nil || read <= 0 {
			return errL8RuntimeOwnerInvalid
		}
		_, _ = digest.Write(buffer[:read])
		offset += int64(read)
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected.Digest {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func validateL8RuntimeOwnerSealedRegularFD(fd int, sizeLimit int64) (l8RuntimeOwnerKeyIdentity, error) {
	var stat unix.Stat_t
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	access, accessErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	seals, sealErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if unix.Fstat(fd, &stat) != nil || flagErr != nil || accessErr != nil || sealErr != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || flags&unix.FD_CLOEXEC == 0 || access&unix.O_ACCMODE != unix.O_RDONLY ||
		seals != l8RuntimeOwnerRequiredSeals || stat.Size < 0 || sizeLimit > 0 && stat.Size > sizeLimit {
		return l8RuntimeOwnerKeyIdentity{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerKeyIdentity{Regular: true, Size: stat.Size, Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func validateL8RuntimeOwnerDirectoryFD(fd int) error {
	var stat unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) || flags&unix.FD_CLOEXEC == 0 {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func validateL8RuntimeOwnerSeqpacketFD(fd int) error {
	typeValue, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeValue != unix.SOCK_SEQPACKET {
		return errL8RuntimeOwnerInvalid
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func validateL8RuntimeOwnerNamespacePair(userFD, networkFD int) error {
	userIdentity, userErr := l8RuntimeOwnerStatNamespaceFD(userFD)
	networkIdentity, networkErr := l8RuntimeOwnerStatNamespaceFD(networkFD)
	if userErr != nil || networkErr != nil || userIdentity == networkIdentity {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func l8RuntimeOwnerStatNamespaceFD(fd int) (l8RuntimeOwnerNSIdentity, error) {
	var stat unix.Stat_t
	var statfs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &statfs) != nil || statfs.Type != unix.NSFS_MAGIC {
		return l8RuntimeOwnerNSIdentity{}, errL8RuntimeOwnerInvalid
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return l8RuntimeOwnerNSIdentity{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func realL8RuntimeOwnerKeyFDOps() l8RuntimeOwnerKeyFDOps {
	return l8RuntimeOwnerKeyFDOps{
		Stat: func(fd int) (l8RuntimeOwnerKeyIdentity, error) {
			var stat unix.Stat_t
			if unix.Fstat(fd, &stat) != nil {
				return l8RuntimeOwnerKeyIdentity{}, errL8RuntimeOwnerInvalid
			}
			return l8RuntimeOwnerKeyIdentity{
				Regular: stat.Mode&unix.S_IFMT == unix.S_IFREG,
				Mode:    uint32(stat.Mode & 0o777),
				UID:     stat.Uid,
				Links:   uint64(stat.Nlink),
				Size:    stat.Size,
				Device:  uint64(stat.Dev),
				Inode:   stat.Ino,
			}, nil
		},
		Pread: unix.Pread,
		Close: unix.Close,
	}
}

func openL8RuntimeOwnerReconnectListener(directoryFD int, identity string) (int, string, error) {
	if !validL8RuntimeOwnerToken(identity) {
		return -1, "", errL8RuntimeOwnerInvalid
	}
	name := l8RuntimeOwnerReconnectPrefix + identity + l8RuntimeOwnerReconnectSuffix
	path := "/proc/self/fd/" + strconv.Itoa(directoryFD) + "/" + name
	if len(path) >= len(unix.RawSockaddrUnix{}.Path) {
		return -1, "", errL8RuntimeOwnerInvalid
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, "", errL8RuntimeOwnerInvalid
	}
	failed := true
	defer func() {
		if failed {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(directoryFD, name, 0)
		}
	}()
	if unix.Bind(fd, &unix.SockaddrUnix{Name: path}) != nil || unix.Fchmodat(directoryFD, name, 0o600, 0) != nil || unix.Listen(fd, 1) != nil {
		return -1, "", errL8RuntimeOwnerInvalid
	}
	failed = false
	return fd, name, nil
}

func sendL8RuntimeOwnerControlResult(fd int, result l8RuntimeOwnerControlResult) error {
	if validateL8RuntimeOwnerPacketRole(result.Packet, true, len(result.Files)) != nil {
		for _, opened := range result.Files {
			_ = unix.Close(opened)
		}
		return errL8RuntimeOwnerInvalid
	}
	files := make([]*os.File, 0, len(result.Files))
	for index, opened := range result.Files {
		file := os.NewFile(uintptr(opened), "runtime-owner-response-right")
		if file == nil {
			for _, owned := range files {
				_ = owned.Close()
			}
			for _, remaining := range result.Files[index:] {
				_ = unix.Close(remaining)
			}
			return errL8RuntimeOwnerInvalid
		}
		files = append(files, file)
	}
	defer closeL8RuntimeOwnerFiles(files)
	if sendL8RuntimeOwnerSeqpacket(fd, result.Packet, files) != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func sendL8RuntimeOwnerReject(fd int) error {
	return sendL8RuntimeOwnerSeqpacket(fd, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeReject, Status: l8RuntimeOwnerStatusRejected}, nil)
}

func setL8RuntimeOwnerSocketTimeout(fd int, timeout time.Duration) error {
	value := unix.NsecToTimeval(timeout.Nanoseconds())
	if timeout == 0 {
		value = unix.Timeval{}
	}
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &value) != nil || unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &value) != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
