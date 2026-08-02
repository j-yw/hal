package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

var errProductionVsockNotReady = errors.New("Firecracker vsock socket is not ready")

const (
	defaultProductionVsockTimeout      = 30 * time.Second
	defaultProductionVsockPollInterval = 25 * time.Millisecond
)

// ProductionVsockBridgeOptions configures the host-owned L5 bridge. The
// lifecycle manager is mandatory because raw PID and socket paths are resolved
// only from the process generation tracked at launch.
type ProductionVsockBridgeOptions struct {
	Lifecycle                *ProcessLifecycleManager
	Timeout                  time.Duration
	PollInterval             time.Duration
	GuestPort                uint32
	OperationTime            time.Duration
	RequireIsolationProof    bool
	RequireNetworkProof      bool
	IsolationProofGeneration string
}

// ProductionVsockBridge owns live Firecracker UDS sessions. No socket path,
// host PID, or inode leaves this in-memory boundary.
type ProductionVsockBridge struct {
	lifecycle                *ProcessLifecycleManager
	timeout                  time.Duration
	pollInterval             time.Duration
	guestPort                uint32
	operationTime            time.Duration
	requireIsolationProof    bool
	requireNetworkProof      bool
	isolationProofGeneration string

	mu       sync.RWMutex
	next     uint64
	sessions map[string]*productionVsockSession
}

type productionVsockSession struct {
	runtimeID                string
	handleID                 string
	handleSource             string
	generation               string
	isolationProofGeneration string
	isolationRuntimeID       string
	identity                 vsockSocketIdentity
	wire                     *firecrackerVsockTransport
	readiness                GuestAgentReadinessClient
	transport                *GuestAgentTransport
}

type productionVsockL7Proof struct {
	runtimeID                string
	handleID                 string
	handleSource             string
	bridgeGeneration         string
	isolationProofGeneration string
}

var _ firecracker.ProductionVsockBridge = (*ProductionVsockBridge)(nil)

func NewProductionVsockBridge(options ProductionVsockBridgeOptions) *ProductionVsockBridge {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultProductionVsockTimeout
	}
	interval := options.PollInterval
	if interval <= 0 {
		interval = defaultProductionVsockPollInterval
	}
	port := options.GuestPort
	if port == 0 {
		port = L5GuestAgentPort
	}
	return &ProductionVsockBridge{
		lifecycle: options.Lifecycle, timeout: timeout, pollInterval: interval,
		guestPort: port, operationTime: options.OperationTime,
		requireIsolationProof:    options.RequireIsolationProof || options.RequireNetworkProof,
		requireNetworkProof:      options.RequireNetworkProof,
		isolationProofGeneration: strings.TrimSpace(options.IsolationProofGeneration),
		sessions:                 make(map[string]*productionVsockSession),
	}
}

func (bridge *ProductionVsockBridge) ActivateSession(ctx context.Context, req firecracker.ProductionVsockSessionRequest) (firecracker.GuestReadinessResult, string, error) {
	if bridge == nil || bridge.lifecycle == nil {
		return firecracker.GuestReadinessResult{}, "", errors.New("Firecracker production vsock bridge is unavailable")
	}
	ctx = nonNilContext(ctx)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, bridge.timeout)
		defer cancel()
	}
	identity, err := bridge.lifecycle.resolveLiveProcessIdentity(req.Handle)
	if err != nil || identity.handle.ID != strings.TrimSpace(req.Handle.ID) {
		return firecracker.GuestReadinessResult{}, "", errors.New("Firecracker process identity is unavailable")
	}
	socketPath := filepath.Clean(strings.TrimSpace(req.SocketPath))
	if socketPath == "." || !filepath.IsAbs(socketPath) ||
		filepath.Clean(identity.paths.VsockSocketPath) != socketPath ||
		filepath.Base(identity.paths.StateDir) != strings.TrimSpace(req.RuntimeID) {
		return firecracker.GuestReadinessResult{}, "", errors.New("Firecracker vsock socket identity is unavailable")
	}

	for {
		if err := ctx.Err(); err != nil {
			return firecracker.GuestReadinessResult{}, "", err
		}
		select {
		case <-identity.done:
			return firecracker.GuestReadinessResult{}, "", errors.New("Firecracker process exited before guest readiness")
		default:
		}
		if err := secureFirecrackerVsockSocket(socketPath); err != nil {
			if !errors.Is(err, errProductionVsockNotReady) {
				return firecracker.GuestReadinessResult{}, "", err
			}
		} else {
			wire, createErr := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
				socketPath: socketPath, guestPort: bridge.guestPort, expectedPeerPID: identity.pid,
				handshakeTimeout: bridge.timeout, operationTimeout: bridge.operationTime,
			})
			if createErr != nil {
				return firecracker.GuestReadinessResult{}, "", createErr
			}
			client, clientErr := guestagent.NewClient(guestagent.ClientOptions{Transport: wire})
			if clientErr != nil {
				return firecracker.GuestReadinessResult{}, "", clientErr
			}
			readinessRequest, requestErr := bridge.readinessRequest(req.RuntimeID)
			if requestErr != nil {
				return firecracker.GuestReadinessResult{}, "", requestErr
			}
			response, readinessErr := client.Readiness(ctx, readinessRequest)
			switch {
			case readinessErr != nil && !transientProductionVsockError(readinessErr):
				return firecracker.GuestReadinessResult{}, "", readinessErr
			case readinessErr == nil && response != nil && response.Ready && response.Status == guestagent.ReadinessStatusReady:
				guestTransport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})
				proofGeneration, proofRuntimeID := "", ""
				if response.IsolationProof != nil {
					proofGeneration = response.IsolationProof.Generation
					proofRuntimeID = response.IsolationProof.RuntimeGeneration
				}
				generation := bridge.activate(req.RuntimeID, identity.handle, wire, client, guestTransport, proofGeneration, proofRuntimeID)
				go bridge.invalidateAfterExit(req.RuntimeID, identity.handle.ID, generation, identity.done)
				result := firecracker.NewGuestReadinessResult(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				)
				if response.IsolationProof != nil && response.IsolationProof.Status == guestagent.IsolationProofStatusVerified {
					result.IsolationProofGeneration = response.IsolationProof.Generation
					result.IsolationRuntimeGeneration = response.IsolationProof.RuntimeGeneration
				}
				return firecracker.SanitizeGuestReadinessResult(result), generation, nil
			}
		}
		timer := time.NewTimer(bridge.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return firecracker.GuestReadinessResult{}, "", ctx.Err()
		case <-identity.done:
			if !timer.Stop() {
				<-timer.C
			}
			return firecracker.GuestReadinessResult{}, "", errors.New("Firecracker process exited before guest readiness")
		case <-timer.C:
		}
	}
}

func (bridge *ProductionVsockBridge) readinessRequest(runtimeID string) (guestagent.ReadinessRequest, error) {
	request := guestagent.ReadinessRequest{}
	if bridge == nil || !bridge.requireIsolationProof {
		return request, nil
	}
	request.ProtocolVersion = guestagent.ProtocolVersionV1
	request.Operation = guestagent.OperationReadiness
	request.IsolationProof = &guestagent.IsolationProofRequest{
		Generation:          bridge.isolationProofGeneration,
		RuntimeGeneration:   strings.TrimSpace(runtimeID),
		RequireNetworkProof: bridge.requireNetworkProof,
	}
	if err := guestagent.ValidateReadinessRequest(request); err != nil {
		return guestagent.ReadinessRequest{}, errors.New("Firecracker L7 readiness proof binding is invalid")
	}
	return request, nil
}

func secureFirecrackerVsockSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return errProductionVsockNotReady
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return errors.New("Firecracker vsock socket is unavailable")
	}
	// Ownership and the private parent are checked before the full
	// owner/mode/type/dev/inode identity is captured by the constructor.
	if err := validateVsockSocketOwnership(path, info); err != nil {
		return errors.New("Firecracker vsock socket is not privately owned")
	}
	return nil
}

func transientProductionVsockError(err error) bool {
	return errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, errFirecrackerVsockGuestPortUnavailable)
}

func (bridge *ProductionVsockBridge) activate(
	runtimeID string,
	handle firecracker.ProcessHandleMetadata,
	wire *firecrackerVsockTransport,
	readiness GuestAgentReadinessClient,
	transport *GuestAgentTransport,
	isolationProofGeneration string,
	isolationRuntimeID string,
) string {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	bridge.next++
	generation := "vsock-session-" + fixedGeneration(bridge.next)
	if previous := bridge.sessions[runtimeID]; previous != nil && previous.wire != nil {
		previous.wire.Close()
	}
	bridge.sessions[runtimeID] = &productionVsockSession{
		runtimeID: runtimeID, handleID: handle.ID, handleSource: handle.Source, generation: generation,
		isolationProofGeneration: strings.TrimSpace(isolationProofGeneration), isolationRuntimeID: strings.TrimSpace(isolationRuntimeID),
		identity: wire.socketIdentity, wire: wire, readiness: readiness, transport: transport,
	}
	return generation
}

// refreshL7Proof repeats the exact proof-required readiness exchange across
// the still-active process/socket session. Only opaque generations leave this
// boundary; raw guest, socket, process, and topology values remain private.
func (bridge *ProductionVsockBridge) refreshL7Proof(
	ctx context.Context,
	target sandboxruntime.Target,
	expectedTopologyGeneration string,
) (productionVsockL7Proof, error) {
	if bridge == nil || !bridge.requireIsolationProof || !bridge.requireNetworkProof ||
		strings.TrimSpace(expectedTopologyGeneration) == "" || bridge.isolationProofGeneration != strings.TrimSpace(expectedTopologyGeneration) {
		return productionVsockL7Proof{}, errL7RuntimeController
	}
	session := bridge.sessionForTarget(target)
	if session == nil || session.readiness == nil ||
		session.isolationProofGeneration != bridge.isolationProofGeneration ||
		session.isolationRuntimeID != session.runtimeID ||
		!bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
			Handle: firecracker.ProcessHandleMetadata{ID: session.handleID, Source: session.handleSource}, RuntimeID: session.runtimeID,
		}, session.generation) {
		return productionVsockL7Proof{}, errL7RuntimeController
	}
	request, err := bridge.readinessRequest(session.runtimeID)
	if err != nil {
		return productionVsockL7Proof{}, errL7RuntimeController
	}
	response, err := session.readiness.Readiness(nonNilContext(ctx), request)
	if err != nil || response == nil || response.Error != nil ||
		guestagent.ValidateReadinessResponseForRequest(*response, request) != nil ||
		!response.Ready || response.Status != guestagent.ReadinessStatusReady || response.IsolationProof == nil ||
		response.IsolationProof.Status != guestagent.IsolationProofStatusVerified ||
		response.IsolationProof.Generation != session.isolationProofGeneration ||
		response.IsolationProof.RuntimeGeneration != session.isolationRuntimeID ||
		response.IsolationProof.Network == nil ||
		response.IsolationProof.Network.Status != guestagent.IsolationProofStatusVerified {
		return productionVsockL7Proof{}, errL7RuntimeController
	}
	if !bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: session.handleID, Source: session.handleSource}, RuntimeID: session.runtimeID,
	}, session.generation) {
		return productionVsockL7Proof{}, errL7RuntimeController
	}
	return productionVsockL7Proof{
		runtimeID: session.runtimeID, handleID: session.handleID, handleSource: session.handleSource,
		bridgeGeneration: session.generation, isolationProofGeneration: session.isolationProofGeneration,
	}, nil
}

func fixedGeneration(value uint64) string {
	const digits = "0123456789"
	buf := [12]byte{}
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i] = digits[value%10]
		value /= 10
	}
	return string(buf[:])
}

func (bridge *ProductionVsockBridge) SessionActive(req firecracker.ProductionVsockSessionRequest, generation string) bool {
	session := bridge.session(req.RuntimeID)
	if session == nil ||
		session.handleID != strings.TrimSpace(req.Handle.ID) ||
		session.handleSource != strings.TrimSpace(req.Handle.Source) ||
		session.generation != generation {
		return false
	}
	identity, err := bridge.lifecycle.resolveLiveProcessIdentity(req.Handle)
	if err != nil || identity.handle.ID != session.handleID {
		bridge.invalidate(req.RuntimeID, session.handleID, session.generation)
		return false
	}
	current, err := statVsockSocket(identity.paths.VsockSocketPath)
	if err != nil || current != session.identity {
		bridge.invalidate(req.RuntimeID, session.handleID, session.generation)
		return false
	}
	return true
}

func (bridge *ProductionVsockBridge) InvalidateSession(req firecracker.ProductionVsockSessionRequest, generation string) {
	bridge.invalidate(req.RuntimeID, strings.TrimSpace(req.Handle.ID), generation)
}

func (bridge *ProductionVsockBridge) invalidateAfterExit(runtimeID, handleID, generation string, done <-chan struct{}) {
	if done == nil {
		return
	}
	<-done
	bridge.invalidate(runtimeID, handleID, generation)
}

func (bridge *ProductionVsockBridge) invalidate(runtimeID, handleID, generation string) {
	if bridge == nil {
		return
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	active := bridge.sessions[runtimeID]
	if active != nil && active.handleID == handleID && active.generation == generation {
		delete(bridge.sessions, runtimeID)
		if active.wire != nil {
			active.wire.Close()
		}
	}
}

func (bridge *ProductionVsockBridge) sessionForTarget(target sandboxruntime.Target) *productionVsockSession {
	runtimeID := strings.TrimSpace(target.Runtime.RuntimeID)
	if runtimeID == "" {
		runtimeID = strings.TrimSpace(target.ID)
	}
	session := bridge.session(runtimeID)
	if session == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil ||
		session.handleID != strings.TrimSpace(target.Runtime.Metadata.ProcessLaunch.ProcessID) ||
		session.handleSource != strings.TrimSpace(target.Runtime.Metadata.ProcessLaunch.ProcessIDSource) {
		return nil
	}
	return session
}

func (bridge *ProductionVsockBridge) session(runtimeID string) *productionVsockSession {
	if bridge == nil {
		return nil
	}
	bridge.mu.RLock()
	defer bridge.mu.RUnlock()
	session := bridge.sessions[strings.TrimSpace(runtimeID)]
	if session == nil {
		return nil
	}
	copy := *session
	return &copy
}

func (bridge *ProductionVsockBridge) Exec(ctx context.Context, req firecracker.GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	session := bridge.sessionForTarget(req.Target)
	if session == nil || !bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: sessionHandleID(session), Source: sessionHandleSource(session)}, RuntimeID: runtimeIDFromTarget(req.Target),
	}, sessionGeneration(session)) {
		return nil, errors.New("Firecracker production vsock session is unavailable")
	}
	result, err := session.transport.Exec(ctx, req)
	if shouldInvalidateProductionVsockSession(err) {
		bridge.invalidate(session.runtimeID, session.handleID, session.generation)
	}
	return result, err
}

func shouldInvalidateProductionVsockSession(err error) bool {
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

func (bridge *ProductionVsockBridge) CopyIn(ctx context.Context, req firecracker.GuestCopyRequest) error {
	session := bridge.sessionForTarget(req.Target)
	if session == nil || !bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: sessionHandleID(session), Source: sessionHandleSource(session)}, RuntimeID: runtimeIDFromTarget(req.Target),
	}, sessionGeneration(session)) {
		return errors.New("Firecracker production vsock session is unavailable")
	}
	err := session.transport.CopyIn(ctx, req)
	if shouldInvalidateProductionVsockSession(err) {
		bridge.invalidate(session.runtimeID, session.handleID, session.generation)
	}
	return err
}

func (bridge *ProductionVsockBridge) CopyOut(ctx context.Context, req firecracker.GuestCopyRequest) error {
	session := bridge.sessionForTarget(req.Target)
	if session == nil || !bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: sessionHandleID(session), Source: sessionHandleSource(session)}, RuntimeID: runtimeIDFromTarget(req.Target),
	}, sessionGeneration(session)) {
		return errors.New("Firecracker production vsock session is unavailable")
	}
	err := session.transport.CopyOut(ctx, req)
	if shouldInvalidateProductionVsockSession(err) {
		bridge.invalidate(session.runtimeID, session.handleID, session.generation)
	}
	return err
}

func runtimeIDFromTarget(target sandboxruntime.Target) string {
	if value := strings.TrimSpace(target.Runtime.RuntimeID); value != "" {
		return value
	}
	return strings.TrimSpace(target.ID)
}

func sessionHandleID(session *productionVsockSession) string {
	if session == nil {
		return ""
	}
	return session.handleID
}

func sessionGeneration(session *productionVsockSession) string {
	if session == nil {
		return ""
	}
	return session.generation
}

func sessionHandleSource(session *productionVsockSession) string {
	if session == nil {
		return ""
	}
	return session.handleSource
}
