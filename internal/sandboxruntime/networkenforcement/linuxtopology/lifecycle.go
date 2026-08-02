package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type Lifecycle struct {
	mu         sync.Mutex
	config     Config
	supported  bool
	production bool
	ownership  OwnershipStore
	active     map[string]*Session
	stopped    map[string]Metadata
}

type Session struct {
	mu        sync.Mutex
	identity  Identity
	mapping   Mapping
	metadata  Metadata
	keeper    ProcessHandle
	mapper    ProcessHandle
	namespace *NamespaceHandle
	losses    chan Loss
	lossOnce  sync.Once
	stopping  bool
	borrows   sync.WaitGroup
	ownership OwnershipLease
}

func New(input Config) (*Lifecycle, error) {
	config := input
	if config.CleanupTimeout == 0 {
		config.CleanupTimeout = defaultCleanupTimeout
	}
	if config.InspectionTimeout == 0 {
		config.InspectionTimeout = defaultInspectionTimeout
	}
	if config.InspectionInterval == 0 {
		config.InspectionInterval = defaultInspectionInterval
	}
	if config.OutputLimit == 0 {
		config.OutputLimit = defaultOutputLimit
	}
	config.Environment = append([]string(nil), config.Environment...)

	lifecycle := &Lifecycle{
		config:  config,
		active:  make(map[string]*Session),
		stopped: make(map[string]Metadata),
	}
	if !config.Enabled {
		return lifecycle, nil
	}
	if !validToolPaths(config.Tools) || !validEnvironment(config.Environment) ||
		config.CleanupTimeout <= 0 || config.CleanupTimeout > time.Minute ||
		config.InspectionTimeout <= 0 || config.InspectionTimeout > time.Minute ||
		config.InspectionInterval <= 0 || config.InspectionInterval > time.Second ||
		config.OutputLimit <= 0 || config.OutputLimit > maxOutputLimit {
		return nil, ErrInvalidTools
	}

	defaults := config.Starter == nil || config.Runner == nil || config.OpenNamespaces == nil
	supported, starter, runner, opener := platformDependencies()
	lifecycle.supported = supported
	lifecycle.production = defaults
	if config.Starter == nil {
		config.Starter = starter
	}
	if config.Runner == nil {
		config.Runner = runner
	}
	if config.OpenNamespaces == nil {
		config.OpenNamespaces = opener
	}
	if config.Reachability == nil {
		config.Reachability = commandReachabilityProber{runner: config.Runner, tools: config.Tools, limit: config.OutputLimit}
	}
	if config.Ownership == nil {
		if defaults && supported {
			store, err := newFileOwnershipStore(config.StateDir)
			if err != nil {
				return nil, ErrInvalidTools
			}
			config.Ownership = store
		} else {
			config.Ownership = newMemoryOwnershipStore()
		}
	}
	if defaults && supported && !executableToolPaths(config.Tools) {
		return nil, ErrInvalidTools
	}
	lifecycle.config = config
	lifecycle.ownership = config.Ownership
	return lifecycle, nil
}

func (l *Lifecycle) Start(ctx context.Context, request StartRequest) (*Session, error) {
	if l == nil || !l.config.Enabled {
		return nil, ErrDisabled
	}
	if !l.supported {
		return nil, ErrUnsupported
	}
	if !validIdentity(request.Identity) {
		return nil, ErrInvalidIdentity
	}
	if !validMapping(request.Mapping) {
		return nil, ErrInvalidMapping
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrStartFailed
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if stopped, ok := l.stopped[request.Identity.SandboxID]; ok &&
		stopped.Identity.TopologyGenerationID == request.Identity.TopologyGenerationID {
		return nil, ErrStaleGeneration
	}
	if current := l.active[request.Identity.SandboxID]; current != nil {
		current.mu.Lock()
		sameIdentity := current.identity == request.Identity
		sameMapping := current.mapping == request.Mapping
		status := current.metadata.Status
		current.mu.Unlock()
		if sameIdentity && sameMapping && status == StatusPrepared {
			return current, nil
		}
		if current.identity.TopologyGenerationID == request.Identity.TopologyGenerationID {
			return nil, ErrIdentityMismatch
		}
		return nil, ErrTopologyCollision
	}
	lease, err := l.ownership.Acquire(ctx, request.Identity)
	if err != nil {
		return nil, sanitizeOwnershipError(err)
	}
	if err := lease.Reconcile(ctx); err != nil {
		_ = lease.Release()
		if errors.Is(err, ErrStaleGeneration) {
			return nil, ErrStaleGeneration
		}
		return nil, ErrStaleTopologyUnverified
	}

	keeper, err := l.config.Starter.Start(ctx, l.keeperSpec())
	if err != nil || keeper == nil || keeper.PID() <= 0 {
		_ = lease.Release()
		return nil, ErrStartFailed
	}
	if err := lease.Record(ctx, keeper, nil, nil); err != nil {
		return l.failStart(request, lease, keeper, nil, nil, ErrStartFailed)
	}

	owned, err := l.openInitialNamespaces(ctx, keeper)
	if err != nil {
		return l.failStart(request, lease, keeper, nil, nil, ErrStartFailed)
	}
	if err := lease.Record(ctx, keeper, nil, owned); err != nil {
		return l.failStart(request, lease, keeper, nil, owned, ErrStartFailed)
	}

	if !processIdentityCurrent(keeper) {
		return l.failStart(request, lease, keeper, nil, owned, ErrStartFailed)
	}
	if err := lease.ArmMapping(ctx, keeper, owned); err != nil {
		return l.failStart(request, lease, keeper, nil, owned, ErrStartFailed)
	}
	mappingSpec := l.mappingSpec(request.Mapping, keeper.PID())
	mapper, startErr := l.config.Starter.Start(ctx, mappingSpec)
	if startErr != nil || mapper == nil || mapper.PID() <= 0 {
		return l.failStart(request, lease, keeper, nil, owned, ErrStartFailed)
	}
	// Persist the mapper before any further fallible validation. A mapper that
	// survives rollback must always be discoverable by restart reconciliation.
	if err := lease.Record(ctx, keeper, mapper, owned); err != nil {
		return l.failStart(request, lease, keeper, mapper, owned, ErrStartFailed)
	}
	current, namespaceErr := l.config.OpenNamespaces(keeper.PID())
	if namespaceErr != nil || !processIdentityCurrent(keeper) || !current.Correlates(owned) {
		if current != nil {
			_ = current.Close()
		}
		return l.failStart(request, lease, keeper, mapper, owned, ErrStartFailed)
	}
	_ = current.Close()
	if err := l.inspect(ctx, keeper, mapper, owned, request.Identity, request.Mapping); err != nil {
		return l.failStart(request, lease, keeper, mapper, owned, ErrInspectionFailed)
	}
	if processDone(keeper) || processDone(mapper) {
		return l.failStart(request, lease, keeper, mapper, owned, ErrStartFailed)
	}

	session := &Session{
		identity: request.Identity,
		mapping:  request.Mapping,
		metadata: Metadata{
			Identity: request.Identity, Status: StatusPrepared,
			StructuralInspected: true, MappingReachable: true,
		},
		keeper:    keeper,
		mapper:    mapper,
		namespace: owned,
		losses:    make(chan Loss, 1),
		ownership: lease,
	}
	l.active[request.Identity.SandboxID] = session
	go session.watch(ProcessRoleKeeper, keeper)
	go session.watch(ProcessRoleMapping, mapper)
	return session, nil
}

func (l *Lifecycle) Stop(_ context.Context, identity Identity) (Metadata, error) {
	if l == nil || !l.config.Enabled {
		return Metadata{}, ErrDisabled
	}
	if !l.supported {
		return Metadata{}, ErrUnsupported
	}
	if !validIdentity(identity) {
		return Metadata{}, ErrInvalidIdentity
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	session := l.active[identity.SandboxID]
	if session == nil {
		if stopped, ok := l.stopped[identity.SandboxID]; ok {
			if stopped.Identity == identity {
				return stopped, nil
			}
			return Metadata{}, ErrStaleGeneration
		}
		return Metadata{}, ErrStaleGeneration
	}
	if session.identity.TopologyGenerationID != identity.TopologyGenerationID {
		return Metadata{}, ErrStaleGeneration
	}
	if session.identity != identity {
		return Metadata{}, ErrIdentityMismatch
	}

	session.mu.Lock()
	session.stopping = true
	session.metadata.Status = StatusStopping
	session.metadata.StructuralInspected = false
	session.metadata.MappingReachable = false
	mapper := session.mapper
	owned := session.namespace
	keeper := session.keeper
	session.mu.Unlock()

	cleanupErr := session.waitForBorrows(l.config.CleanupTimeout)
	if cleanupErr == nil {
		cleanupErr = l.cleanup(mapper, owned, keeper)
	}
	if cleanupErr == nil {
		cleanupErr = finalizeOwnership(session.ownership, identity)
	}
	session.mu.Lock()
	if cleanupErr != nil {
		session.metadata.Status = StatusCleanupIncomplete
		session.metadata.StructuralInspected = false
		session.metadata.MappingReachable = false
		metadata := session.metadata
		session.mu.Unlock()
		return metadata, ErrCleanupIncomplete
	}
	session.mapper = nil
	session.keeper = nil
	session.namespace = nil
	session.metadata.Status = StatusStopped
	session.metadata.StructuralInspected = false
	session.metadata.MappingReachable = false
	metadata := session.metadata
	session.mu.Unlock()
	delete(l.active, identity.SandboxID)
	l.stopped[identity.SandboxID] = metadata
	return metadata, nil
}

func (l *Lifecycle) keeperSpec() ProcessSpec {
	return ProcessSpec{
		Role: ProcessRoleKeeper,
		Path: l.config.Tools.Unshare,
		Args: []string{
			"--user", "--map-current-user", "--net",
			"--", l.config.Tools.Keeper, "infinity",
		},
		Env:         append([]string(nil), l.config.Environment...),
		OutputLimit: l.config.OutputLimit,
	}
}

func (l *Lifecycle) mappingSpec(mapping Mapping, keeperPID int) ProcessSpec {
	keeperRoot := filepath.Join("/proc", strconv.Itoa(keeperPID), "ns")
	return ProcessSpec{
		Role: ProcessRoleMapping,
		Path: l.config.Tools.Pasta,
		Args: []string{
			"--foreground", "--quiet",
			"--config-net",
			"--no-copy-routes",
			"--address", "192.0.2.3/24",
			"--gateway", "192.0.2.1",
			"--address", "fd00:6861:6c::2/64",
			"--gateway", "fd00:6861:6c::1",
			"--userns", filepath.Join(keeperRoot, "user"),
			"--netns", filepath.Join(keeperRoot, "net"),
			"--map-host-loopback", mapping.GuestProxyAddress,
			"--no-map-gw",
			"-t", "none", "-u", "none", "-T", "none", "-U", "none",
			"-I", mapping.NamespaceInterface,
		},
		Env:         append([]string(nil), l.config.Environment...),
		ExtraFiles:  nil,
		OutputLimit: l.config.OutputLimit,
	}
}

func (l *Lifecycle) openInitialNamespaces(ctx context.Context, keeper ProcessHandle) (*NamespaceHandle, error) {
	if !l.production {
		return l.config.OpenNamespaces(keeper.PID())
	}
	deadline := time.Now().Add(l.config.InspectionTimeout)
	for {
		handle, err := l.config.OpenNamespaces(keeper.PID())
		if err == nil {
			return handle, nil
		}
		if time.Now().After(deadline) || processDone(keeper) {
			return nil, ErrStartFailed
		}
		if err := waitInterval(ctx, l.config.InspectionInterval); err != nil {
			return nil, ErrStartFailed
		}
	}
}

func (l *Lifecycle) inspect(parent context.Context, keeper, mapper ProcessHandle, owned *NamespaceHandle, identity Identity, mapping Mapping) error {
	ctx, cancel := context.WithTimeout(parent, l.config.InspectionTimeout)
	defer cancel()
	for {
		if processDone(keeper) || processDone(mapper) {
			return ErrInspectionFailed
		}
		current, err := l.config.OpenNamespaces(keeper.PID())
		if err == nil {
			correlated := current.Correlates(owned)
			_ = current.Close()
			if correlated {
				outputs := make([][]byte, 0, 4)
				valid := true
				for _, kind := range []inspectionKind{inspectionLinks, inspectionAddresses, inspectionIPv4Routes, inspectionIPv6Routes} {
					files, fileErr := owned.extraFiles()
					if fileErr != nil {
						valid = false
						break
					}
					output, runErr := l.config.Runner.Run(ctx, l.inspectionSpec(kind, files))
					closeFiles(files)
					if runErr != nil || int64(len(output)) > l.config.OutputLimit {
						valid = false
						break
					}
					outputs = append(outputs, output)
				}
				var addressEvidence interfaceAddressEvidence
				addressesValid := false
				if valid && len(outputs) == 4 {
					addressEvidence, addressesValid = inspectAddressEvidence(outputs[1], mapping.NamespaceInterface)
				}
				if valid && len(outputs) == 4 &&
					validLinkInspection(outputs[0], mapping.NamespaceInterface) && addressesValid &&
					validRouteInspection(outputs[2], outputs[3], mapping.NamespaceInterface, addressEvidence) &&
					l.config.Reachability.Probe(ctx, owned, identity, mapping) == nil &&
					!processDone(keeper) && !processDone(mapper) {
					return nil
				}
			}
		}
		if err := waitInterval(ctx, l.config.InspectionInterval); err != nil {
			return ErrInspectionFailed
		}
	}
}

func (l *Lifecycle) rollback(mapper ProcessHandle, owned *NamespaceHandle, keeper ProcessHandle) error {
	return l.cleanup(mapper, owned, keeper)
}

func (l *Lifecycle) failStart(
	request StartRequest,
	lease OwnershipLease,
	keeper, mapper ProcessHandle,
	owned *NamespaceHandle,
	primary error,
) (*Session, error) {
	var recoveryRecordErr error
	if mapper != nil {
		// The initial post-launch record may have failed. Before retaining live
		// ownership or closing namespace evidence, make one independent bounded
		// attempt to establish the durable restart-recovery record.
		recordCtx, cancel := context.WithTimeout(context.Background(), l.config.CleanupTimeout)
		recoveryRecordErr = lease.Record(recordCtx, keeper, mapper, owned)
		cancel()
	}
	cleanupErr := l.rollback(mapper, owned, keeper)
	if cleanupErr != nil {
		cleanupErr = errors.Join(cleanupErr, recoveryRecordErr)
	}
	if cleanupErr == nil {
		cleanupErr = finalizeOwnership(lease, request.Identity)
	}
	if cleanupErr == nil {
		l.stopped[request.Identity.SandboxID] = Metadata{Identity: request.Identity, Status: StatusStopped}
		return nil, primary
	}
	session := &Session{
		identity: request.Identity, mapping: request.Mapping,
		metadata: Metadata{Identity: request.Identity, Status: StatusCleanupIncomplete},
		keeper:   keeper, mapper: mapper, namespace: owned,
		losses: make(chan Loss, 1), ownership: lease, stopping: true,
	}
	l.active[request.Identity.SandboxID] = session
	return session, ErrCleanupIncomplete
}

func finalizeOwnership(lease OwnershipLease, identity Identity) error {
	if err := lease.Retire(identity); err != nil {
		return err
	}
	return lease.Release()
}

func sanitizeOwnershipError(err error) error {
	switch {
	case errors.Is(err, ErrTopologyCollision):
		return ErrTopologyCollision
	case errors.Is(err, ErrStaleGeneration):
		return ErrStaleGeneration
	case errors.Is(err, ErrInvalidIdentity):
		return ErrInvalidIdentity
	default:
		return ErrCleanupIncomplete
	}
}

func (l *Lifecycle) cleanup(mapper ProcessHandle, owned *NamespaceHandle, keeper ProcessHandle) error {
	ctx, cancel := context.WithTimeout(context.Background(), l.config.CleanupTimeout)
	defer cancel()
	var result error
	if mapper != nil {
		result = errors.Join(result, mapper.Terminate(ctx))
	}
	if owned != nil {
		result = errors.Join(result, owned.Close())
	}
	if keeper != nil {
		result = errors.Join(result, keeper.Terminate(ctx))
	}
	return result
}

func (s *Session) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

func (s *Session) MarshalJSON() ([]byte, error) { return json.Marshal(s.Metadata()) }

func (s *Session) Losses() <-chan Loss {
	if s == nil {
		return nil
	}
	return s.losses
}

func (s *Session) NamespaceHandle() (*NamespaceHandle, error) {
	if s == nil {
		return nil, ErrStopped
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.namespace == nil || s.stopping || s.metadata.Status != StatusPrepared ||
		!s.metadata.StructuralInspected || !s.metadata.MappingReachable {
		return nil, ErrStopped
	}
	s.borrows.Add(1)
	handle, err := s.namespace.Duplicate()
	if err != nil {
		s.borrows.Done()
		return nil, err
	}
	handle.release = s.borrows.Done
	return handle, nil
}

func (s *Session) waitForBorrows(timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		s.borrows.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return ErrCleanupIncomplete
	}
}

func (s *Session) watch(role ProcessRole, process ProcessHandle) {
	<-process.Done()
	s.mu.Lock()
	if s.stopping || s.metadata.Status == StatusStopped || s.metadata.Status == StatusCleanupIncomplete {
		s.mu.Unlock()
		return
	}
	s.metadata.Status = StatusLost
	s.metadata.StructuralInspected = false
	s.metadata.MappingReachable = false
	loss := Loss{
		TopologyGenerationID: s.identity.TopologyGenerationID,
		Component:            role,
		Reason:               LossReasonProcessExited,
	}
	s.mu.Unlock()
	s.lossOnce.Do(func() {
		select {
		case s.losses <- loss:
		default:
		}
	})
}

func processDone(process ProcessHandle) bool {
	select {
	case <-process.Done():
		return true
	default:
		return false
	}
}

func processIdentityCurrent(process ProcessHandle) bool {
	if processDone(process) {
		return false
	}
	if owned, ok := process.(interface{ ownershipCurrent() bool }); ok {
		return owned.ownershipCurrent()
	}
	return true
}

func waitInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
