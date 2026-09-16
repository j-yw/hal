//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"golang.org/x/sys/unix"
)

// The selected producer retains these resources before launch. There is no
// constructor from an event, raw work FD, reconnect client or readiness flag.
type minimalControlProducerLaunch struct {
	original   *os.File
	directory  *os.File
	config     minimalControlSupervisorConfig
	supervisor l8RuntimeOwnerProcessObservation
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	socket     *os.File
	conn       *net.UnixConn
	digest     [32]byte
	record     firecrackerRuntimeOwnerRecordV1
	retired    bool
	started    bool
	bootstrap  chan struct{}
	adopted    chan struct{}
	done       chan struct{}
	reader     chan struct{}
	watcher    chan struct{}
	candidate  *minimalControlWorkCandidate
	ordinal    uint64
	active     *minimalProducerWork
	writers    sync.WaitGroup
}

type minimalControlWorkCandidate struct {
	self       *minimalControlWorkCandidate
	launch     *minimalControlProducerLaunch
	event      minimalControlReadinessEventV1
	inspection minimalInspectionLifetime // Guarded by launch.mu; never resets H.
}

type minimalProducerWork struct {
	header   minimalWorkHeader
	done     chan struct{}
	response []byte
	received bool
}

// The original launch scope calls start before sending BootstrapStart. Its
// sole reader validates both revision 2 and RD2, then remains the EOF reader.
func (launch *minimalControlProducerLaunch) start(ctx context.Context) error {
	if launch == nil || !minimalWorkloadContextCurrent(ctx) || launch.original == nil || launch.directory == nil ||
		!launch.supervisor.pidfdOwned || !l8RuntimeOwnerProcessAlive(launch.supervisor.pidfd) ||
		validateL8RuntimeOwnerDirectoryFD(int(launch.directory.Fd())) != nil || validateL8RuntimeOwnerSeqpacketFD(int(launch.original.Fd())) != nil {
		return errL8RuntimeOwnerInvalid
	}
	payload, err := json.Marshal(launch.config)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	config, _, err := decodeMinimalControlSupervisorConfig(payload)
	if err != nil || !time.Now().Before(time.Unix(0, config.Control.PreparationDeadlineUnixNano)) {
		return errL8RuntimeOwnerInvalid
	}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if launch.started || launch.retired {
		return errL8RuntimeOwnerInvalid
	}
	file, err := duplicateJailerRecoveryFile(launch.original)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	var original, duplicate unix.Stat_t
	if unix.Fstat(int(launch.original.Fd()), &original) != nil || unix.Fstat(int(file.Fd()), &duplicate) != nil || original.Dev != duplicate.Dev || original.Ino != duplicate.Ino {
		_ = file.Close()
		return errL8RuntimeOwnerInvalid
	}
	launch.socket = file
	launch.config, launch.digest = config, sha256.Sum256(payload)
	launch.ctx, launch.cancel = context.WithCancel(ctx)
	launch.bootstrap, launch.adopted, launch.done = make(chan struct{}), make(chan struct{}), make(chan struct{})
	launch.watcher = make(chan struct{})
	launch.started = true
	go func() {
		defer close(launch.done)
		defer launch.retire()
		defer func() { _ = recover() }()
		launch.readOriginal()
	}()
	go func() {
		defer close(launch.watcher)
		<-launch.ctx.Done()
		launch.retire()
	}()
	return nil
}

func (launch *minimalControlProducerLaunch) awaitBootstrap(ctx context.Context) error {
	if launch == nil || !minimalWorkloadContextCurrent(ctx) || !launch.started {
		return errL8RuntimeOwnerInvalid
	}
	select {
	case <-ctx.Done():
		return errL8RuntimeOwnerInvalid
	case <-launch.done:
		return errL8RuntimeOwnerInvalid
	case <-launch.bootstrap:
		return nil
	}
}

func (launch *minimalControlProducerLaunch) awaitWork(ctx context.Context) (*minimalControlWorkCandidate, error) {
	if launch == nil || !minimalWorkloadContextCurrent(ctx) || !launch.started {
		return nil, errL8RuntimeOwnerInvalid
	}
	select {
	case <-ctx.Done():
		return nil, errL8RuntimeOwnerInvalid
	case <-launch.done:
		return nil, errL8RuntimeOwnerInvalid
	case <-launch.adopted:
	}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if launch.retired || launch.ctx.Err() != nil || !minimalWorkloadContextCurrent(ctx) {
		return nil, errL8RuntimeOwnerInvalid
	}
	return launch.candidate, nil // Candidate only, never a publication-ready result.
}

func (launch *minimalControlProducerLaunch) readOriginal() {
	fd := int(launch.socket.Fd())
	remaining := time.Until(time.Unix(0, launch.config.Control.PreparationDeadlineUnixNano))
	if remaining < time.Microsecond || setL8RuntimeOwnerSocketTimeout(fd, remaining) != nil {
		return
	}
	bootstrap, err := receiveL8RuntimeOwnerSeqpacket(fd)
	defer closeL8RuntimeOwnerFiles(bootstrap.Files)
	if err != nil || len(bootstrap.Files) != 0 || bootstrap.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished ||
		bootstrap.Packet.Status != l8RuntimeOwnerStatusOK || len(bootstrap.Packet.Body) != 8 || binary.BigEndian.Uint64(bootstrap.Packet.Body) != 2 {
		return
	}
	file, err := openJailerRecoveryRecordFile(int(launch.directory.Fd()))
	if err != nil {
		return
	}
	payload, readErr := io.ReadAll(io.NewSectionReader(file, 0, l8RuntimeOwnerRecordLimit+1))
	closeErr := file.Close()
	record, decodeErr := decodeJailerRecoveryCleanupRecord(payload, launch.config.Job)
	if readErr != nil || closeErr != nil || decodeErr != nil || record.Revision != 2 || record.State != "running" ||
		record.SeedCorrelationDigest != hex.EncodeToString(launch.digest[:]) || record.SupervisorPID != launch.supervisor.PID ||
		record.SupervisorStartTime != launch.supervisor.StartTime || !l8RuntimeOwnerProcessAlive(launch.supervisor.pidfd) || launch.ctx.Err() != nil {
		return
	}
	launch.record = record
	close(launch.bootstrap)
	remaining = time.Until(time.Unix(0, launch.config.Control.PreparationDeadlineUnixNano))
	if remaining < time.Microsecond || setL8RuntimeOwnerSocketTimeout(fd, remaining) != nil {
		return
	}
	event, endpoint, err := receiveMinimalWorkReady(fd)
	if endpoint != nil {
		defer endpoint.Close()
	}
	if err != nil || launch.validateWorkReady(event) != nil {
		return
	}
	conn, err := minimalWorkEndpointConn(endpoint)
	if err != nil {
		return
	}
	launch.mu.Lock()
	launch.conn = conn // Own the descriptor before any later rejection.
	if launch.retired || launch.ctx.Err() != nil || !time.Now().Before(time.Unix(0, launch.config.Control.PreparationDeadlineUnixNano)) || setL8RuntimeOwnerSocketTimeout(fd, 0) != nil {
		launch.mu.Unlock()
		return
	}
	candidate := &minimalControlWorkCandidate{launch: launch, event: event}
	candidate.self = candidate
	launch.candidate, launch.reader = candidate, make(chan struct{})
	launch.mu.Unlock()
	go func() {
		defer close(launch.reader)
		defer launch.retire()
		defer func() { _ = recover() }()
		launch.readResponses()
	}()
	close(launch.adopted)
	// Any further original-channel bytes, rights, EOF or error revoke this
	// original launch. No reconnect or event can reissue the work endpoint.
	extra, _ := receiveL8RuntimeOwnerSeqpacket(fd)
	closeL8RuntimeOwnerFiles(extra.Files)
}

func (launch *minimalControlProducerLaunch) validateWorkReady(event minimalControlReadinessEventV1) error {
	if event.configSHA256 != launch.digest || event.supervisorGeneration != launch.record.SupervisorGeneration ||
		launch.ctx.Err() != nil || !l8RuntimeOwnerProcessAlive(launch.supervisor.pidfd) {
		return errL8RuntimeOwnerInvalid
	}
	c, job := launch.config.Control, launch.config.Job
	nonce, ok := minimalControlConfigBase64(c.BootNonce)
	image, err := hex.DecodeString(launch.config.Rootfs.SHA256)
	if !ok || err != nil || len(image) != 32 {
		return errL8RuntimeOwnerInvalid
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: job.RuntimeID, RuntimeGeneration: job.RuntimeGeneration, BootGeneration: c.Prelaunch["bootGeneration"],
		ImageGeneration: c.Prelaunch["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce,
		FirecrackerProcessGeneration: event.processGeneration, VsockGeneration: strconv.FormatUint(event.transportGeneration, 10)}
	copy(identity.ImageSHA256[:], image)
	fields := maps.Clone(c.Prelaunch)
	fields["processGeneration"], fields["vsockGeneration"] = identity.FirecrackerProcessGeneration, identity.VsockGeneration
	binding, err := minimalcontrol.NewBinding(identity, fields)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	digest, err := binding.Digest(event.sessionID)
	if err != nil || digest != "sha256-"+hex.EncodeToString(event.readinessBindingSHA256[:]) {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (launch *minimalControlProducerLaunch) retire() {
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if launch.cancel != nil {
		launch.cancel()
	}
	launch.retired = true
	if launch.socket != nil {
		_ = unix.Shutdown(int(launch.socket.Fd()), unix.SHUT_RDWR)
	}
	if launch.conn != nil {
		_ = launch.conn.Close()
	}
}

// Original caller only; endpoint readers and operation cancellation never join
// this compound owner. The caller keeps all original inputs through this join.
func (launch *minimalControlProducerLaunch) close() {
	launch.retire()
	if launch.started {
		<-launch.done
		<-launch.watcher
		if launch.reader != nil {
			<-launch.reader
		}
		launch.writers.Wait()
	}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if launch.socket != nil {
		_ = launch.socket.Close()
		launch.socket = nil
	}
}

func (candidate *minimalControlWorkCandidate) RoundTrip(ctx context.Context, request guestagent.TransportRequest) (result guestagent.TransportResponse, resultErr error) {
	if candidate == nil || candidate.self != candidate || candidate.launch == nil || !minimalWorkloadContextCurrent(ctx) || !validMinimalWorkloadRequest(request) {
		return result, errL8RuntimeOwnerInvalid
	}
	launch := candidate.launch
	if !l8RuntimeOwnerProcessAlive(launch.supervisor.pidfd) {
		launch.retire()
		return result, errL8RuntimeOwnerInvalid
	}
	launch.mu.Lock()
	if launch.retired || launch.ctx.Err() != nil || launch.candidate != candidate || !minimalWorkloadContextCurrent(ctx) || launch.ordinal == math.MaxUint64 {
		launch.mu.Unlock()
		return result, errL8RuntimeOwnerInvalid
	}
	if launch.active != nil {
		launch.mu.Unlock()
		return result, guestagent.NewProtocolError(guestagent.ErrorCodeServerBusy, request.Operation, "transport", errL8RuntimeOwnerInvalid)
	}
	var inspectionStart time.Time
	var cancelInspection context.CancelFunc
	if request.Operation == minimalInspectionOperation {
		inspectionStart = time.Now()
		if candidate.inspection.hardExpiry != 0 && !candidate.inspection.current(inspectionStart) {
			launch.mu.Unlock()
			launch.retire()
			return result, errL8RuntimeOwnerInvalid
		}
		// The caller's earlier deadline is inherited automatically. Keep this
		// one absolute budget through decoding and final cancellation joins.
		ctx, cancelInspection = context.WithDeadline(ctx, inspectionStart.Add(minimalInspectionTimeout))
	}
	launch.ordinal++
	op := &minimalProducerWork{header: minimalWorkHeader{direction: minimalWorkRequest, operation: request.Operation, ordinal: launch.ordinal,
		maximum: request.MaxResponseBytes, session: candidate.event.sessionID, binding: candidate.event.readinessBindingSHA256}, done: make(chan struct{})}
	launch.active = op
	launch.writers.Add(1)
	launch.mu.Unlock()
	defer launch.writers.Done() // Join the whole admitted call, not only its write.
	if cancelInspection != nil {
		defer cancelInspection()
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(interrupted); launch.retire() })
	defer func() {
		if !stop() {
			<-interrupted
		}
		if cancelInspection != nil {
			if resultErr == nil && !candidate.acceptInspection(ctx, inspectionStart, op) {
				resultErr = errL8RuntimeOwnerInvalid
			}
			if resultErr != nil {
				launch.retire()
				<-launch.reader
				result = guestagent.TransportResponse{}
			}
		}
		launch.mu.Lock()
		if launch.active == op {
			launch.active = nil
		}
		if resultErr != nil {
			clear(op.response)
		}
		launch.mu.Unlock()
	}()
	func() {
		defer func() {
			if recover() != nil {
				launch.retire()
			}
		}()
		if !minimalWorkloadContextCurrent(ctx) || writeMinimalWorkFrame(launch.conn, op.header, request.Encoded) != nil {
			launch.retire()
		}
	}()
	select {
	case <-op.done:
	case <-ctx.Done():
		launch.retire()
	case <-launch.ctx.Done():
	}
	if !minimalWorkloadContextCurrent(ctx) {
		launch.retire()
	}
	if launch.ctx.Err() != nil {
		<-launch.reader // Close has interrupted the reader; never drain after loss.
	}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if !op.received {
		return result, errL8RuntimeOwnerInvalid
	}
	// No drain: only the sole reader's already-complete, exactly correlated
	// response survives retirement. Client retains semantic CopyIn decisions.
	return guestagent.TransportResponse{Encoded: op.response}, nil
}

// Called after the actual request writer and its cancellation callback joined,
// while the same admitted operation still excludes any competing call. The sole
// response reader has completed/correlated this frame, not its continuing task.
func (candidate *minimalControlWorkCandidate) acceptInspection(ctx context.Context, admitted time.Time, op *minimalProducerWork) bool {
	launch := candidate.launch
	if !minimalWorkloadContextCurrent(ctx) || !l8RuntimeOwnerProcessAlive(launch.supervisor.pidfd) {
		return false
	}
	reply, err := decodeMinimalHostInspection(op.response, launch.config.Control.Prelaunch["topologyGenerationId"], launch.config.Job.RuntimeGeneration)
	if err != nil {
		return false
	}
	launch.mu.Lock()
	defer launch.mu.Unlock()
	if candidate.self != candidate || launch.candidate != candidate || launch.active != op || !op.received ||
		launch.retired || launch.ctx.Err() != nil || !minimalWorkloadContextCurrent(ctx) ||
		op.header.session != candidate.event.sessionID || op.header.binding != candidate.event.readinessBindingSHA256 {
		return false
	}
	pin, err := candidate.inspection.accept(admitted, time.Now(), reply.HardExpiryUnixNano, reply.RemainingLifetimeNanos)
	if err != nil {
		return false
	}
	candidate.inspection = pin
	return true
}

func (launch *minimalControlProducerLaunch) readResponses() {
	for {
		var first [1]byte
		if _, err := io.ReadFull(launch.conn, first[:]); err != nil {
			return
		}
		launch.mu.Lock()
		op := launch.active
		valid := !launch.retired && op != nil && !op.received
		launch.mu.Unlock()
		if !valid {
			return
		}
		_, payload, err := readMinimalWorkFrame(launch.conn, first[0], func(header minimalWorkHeader) bool {
			want := op.header
			want.direction = minimalWorkResponse
			return header == want
		})
		if err != nil {
			return
		}
		launch.mu.Lock()
		if launch.active != op || op.received {
			launch.mu.Unlock()
			clear(payload)
			return
		}
		op.response, op.received = payload, true
		close(op.done)
		launch.mu.Unlock()
	}
}
