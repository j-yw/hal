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
	Lifecycle     *ProcessLifecycleManager
	Timeout       time.Duration
	PollInterval  time.Duration
	GuestPort     uint32
	OperationTime time.Duration
}

// ProductionVsockBridge owns live Firecracker UDS sessions. No socket path,
// host PID, or inode leaves this in-memory boundary.
type ProductionVsockBridge struct {
	lifecycle     *ProcessLifecycleManager
	timeout       time.Duration
	pollInterval  time.Duration
	guestPort     uint32
	operationTime time.Duration

	mu       sync.RWMutex
	next     uint64
	sessions map[string]*productionVsockSession
}

type productionVsockSession struct {
	runtimeID    string
	handleID     string
	handleSource string
	generation   string
	identity     vsockSocketIdentity
	wire         *firecrackerVsockTransport
	transport    *GuestAgentTransport
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
		sessions: make(map[string]*productionVsockSession),
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
		filepath.Clean(identity.paths.VsockSocketPath) != socketPath {
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
			response, readinessErr := client.Readiness(ctx, guestagent.ReadinessRequest{})
			switch {
			case readinessErr != nil && !transientProductionVsockError(readinessErr):
				return firecracker.GuestReadinessResult{}, "", readinessErr
			case readinessErr == nil && response != nil && response.Ready && response.Status == guestagent.ReadinessStatusReady:
				guestTransport := NewGuestAgentTransport(GuestAgentTransportOptions{Client: client})
				generation := bridge.activate(req.RuntimeID, identity.handle, wire, guestTransport)
				go bridge.invalidateAfterExit(req.RuntimeID, identity.handle.ID, generation, identity.done)
				return firecracker.NewGuestReadinessResult(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				), generation, nil
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

func secureFirecrackerVsockSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return errProductionVsockNotReady
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("Firecracker vsock socket is unavailable")
	}
	// Ownership and the private parent are checked before chmod, then the full
	// owner/mode/type/dev/inode identity is captured again by the constructor.
	if err := validateVsockSocketOwnership(path, info); err != nil {
		return errors.New("Firecracker vsock socket is not privately owned")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.New("Firecracker vsock socket permissions could not be secured")
	}
	return nil
}

func transientProductionVsockError(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

func (bridge *ProductionVsockBridge) activate(runtimeID string, handle firecracker.ProcessHandleMetadata, wire *firecrackerVsockTransport, transport *GuestAgentTransport) string {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	bridge.next++
	generation := "vsock-session-" + fixedGeneration(bridge.next)
	if previous := bridge.sessions[runtimeID]; previous != nil && previous.wire != nil {
		previous.wire.Close()
	}
	bridge.sessions[runtimeID] = &productionVsockSession{
		runtimeID: runtimeID, handleID: handle.ID, handleSource: handle.Source, generation: generation,
		identity: wire.socketIdentity, wire: wire, transport: transport,
	}
	return generation
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
	if session == nil || session.handleID != strings.TrimSpace(req.Handle.ID) || session.generation != generation {
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
		session.handleID != strings.TrimSpace(target.Runtime.Metadata.ProcessLaunch.ProcessID) {
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
	if err != nil {
		bridge.invalidate(session.runtimeID, session.handleID, session.generation)
	}
	return result, err
}

func (bridge *ProductionVsockBridge) CopyIn(ctx context.Context, req firecracker.GuestCopyRequest) error {
	session := bridge.sessionForTarget(req.Target)
	if session == nil || !bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: sessionHandleID(session), Source: sessionHandleSource(session)}, RuntimeID: runtimeIDFromTarget(req.Target),
	}, sessionGeneration(session)) {
		return errors.New("Firecracker production vsock session is unavailable")
	}
	err := session.transport.CopyIn(ctx, req)
	if err != nil {
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
	if err != nil {
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
