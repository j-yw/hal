package linuxtopology

import (
	"context"
	"errors"
	"reflect"
	"time"
)

func (l *Lifecycle) acquireSandboxOperationContext(ctx context.Context, sandboxID string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.Lock()
	operation := l.operations[sandboxID]
	if operation == nil {
		operation = &sandboxOperationLock{}
		l.operations[sandboxID] = operation
	}
	operation.references++
	l.mu.Unlock()

	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	for {
		if operation.mu.TryLock() {
			return func() {
				operation.mu.Unlock()
				l.mu.Lock()
				operation.references--
				if operation.references == 0 && l.operations[sandboxID] == operation {
					delete(l.operations, sandboxID)
				}
				l.mu.Unlock()
			}, nil
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(time.Millisecond)
		select {
		case <-ctx.Done():
			l.mu.Lock()
			operation.references--
			if operation.references == 0 && l.operations[sandboxID] == operation {
				delete(l.operations, sandboxID)
			}
			l.mu.Unlock()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Recover reopens exact durable topology authority for cleanup only. It never
// restores prepared, inspected, or reachable proof, never consumes the
// caller-owned namespace, and never presents unknown or interrupted state as
// running.
func (l *Lifecycle) Recover(ctx context.Context, request RecoveryRequest) (session *Session, err error) {
	var recovered RecoveredOwnership
	defer func() {
		if panicked := recover(); panicked != nil {
			abandonRecoveredOwnership(request, recovered)
			session = nil
			err = ErrStaleTopologyUnverified
		}
	}()
	if l == nil || !l.config.Enabled {
		return nil, ErrDisabled
	}
	if !l.supported {
		return nil, ErrUnsupported
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || !validIdentity(request.Identity) || request.Namespace == nil || request.Namespace.Closed() {
		return nil, ErrStaleTopologyUnverified
	}

	releaseOperation, err := l.acquireSandboxOperationContext(ctx, request.Identity.SandboxID)
	if err != nil {
		return nil, ErrStaleTopologyUnverified
	}
	defer releaseOperation()
	if ctx.Err() != nil {
		return nil, ErrStaleTopologyUnverified
	}

	l.mu.Lock()
	current := l.active[request.Identity.SandboxID]
	if current != nil {
		current.mu.Lock()
		same := current.identity == request.Identity && current.recoveryOnly &&
			current.metadata.Status == StatusRecoveryOnly && current.namespace != nil &&
			current.namespace.Correlates(request.Namespace)
		current.mu.Unlock()
		l.mu.Unlock()
		if same {
			return current, nil
		}
		return nil, ErrTopologyCollision
	}
	if stopped, ok := l.stopped[request.Identity.SandboxID]; ok && stopped.Identity == request.Identity {
		l.mu.Unlock()
		return nil, ErrStaleGeneration
	}
	l.mu.Unlock()

	if valueIsNil(l.ownership) {
		return nil, ErrStaleTopologyUnverified
	}
	store, ok := l.ownership.(RecoveryOwnershipStore)
	if !ok || valueIsNil(store) {
		return nil, ErrStaleTopologyUnverified
	}

	recovered, recoverErr := claimRecoveredOwnership(ctx, store, request)
	if recoverErr != nil {
		abandonRecoveredOwnership(request, recovered)
		recovered = RecoveredOwnership{}
		return nil, sanitizeRecoveryError(recoverErr)
	}
	owned, processes, valid := acceptRecoveredOwnership(request, recovered)
	if !valid {
		abandonRecoveredOwnership(request, recovered)
		if owned != nil {
			_ = owned.Close()
		}
		closeRecoveredProcesses(processes.keeper, processes.mapper)
		recovered = RecoveredOwnership{}
		return nil, ErrStaleTopologyUnverified
	}
	recovered.Namespace = nil

	session = &Session{
		identity:     request.Identity,
		metadata:     Metadata{Identity: request.Identity, Status: StatusRecoveryOnly},
		keeper:       processes.keeper,
		mapper:       processes.mapper,
		namespace:    owned,
		losses:       make(chan Loss, 1),
		ownership:    recovered.Lease,
		recoveryOnly: true,
	}
	l.mu.Lock()
	if existing := l.active[request.Identity.SandboxID]; existing != nil {
		l.mu.Unlock()
		abandonRecoveredOwnership(request, RecoveredOwnership{Lease: recovered.Lease, Namespace: owned, Keeper: processes.keeper, Mapper: processes.mapper})
		recovered = RecoveredOwnership{}
		return nil, ErrTopologyCollision
	}
	l.active[request.Identity.SandboxID] = session
	l.mu.Unlock()
	recovered = RecoveredOwnership{}
	return session, nil
}

type recoveredProcesses struct {
	keeper ProcessHandle
	mapper ProcessHandle
}

func claimRecoveredOwnership(ctx context.Context, store RecoveryOwnershipStore, request RecoveryRequest) (recovered RecoveredOwnership, err error) {
	defer func() {
		if panicked := recover(); panicked != nil {
			abandonRecoveredOwnership(request, recovered)
			recovered = RecoveredOwnership{}
			err = ErrStaleTopologyUnverified
		}
	}()
	recovered, err = store.AcquireRecovery(ctx, request)
	if err != nil {
		return recovered, err
	}
	return recovered, nil
}

func acceptRecoveredOwnership(request RecoveryRequest, recovered RecoveredOwnership) (*NamespaceHandle, recoveredProcesses, bool) {
	if recovered.Lease == nil || valueIsNil(recovered.Lease) {
		return nil, recoveredProcesses{}, false
	}
	if recovered.Namespace == nil || recovered.Namespace == request.Namespace || recovered.Namespace.Closed() ||
		!recovered.Namespace.Correlates(request.Namespace) {
		return nil, recoveredProcesses{}, false
	}
	keeper, keeperOK := acceptedRecoveryProcess(recovered.Keeper)
	mapper, mapperOK := acceptedRecoveryProcess(recovered.Mapper)
	if !keeperOK || !mapperOK {
		return nil, recoveredProcesses{}, false
	}
	if keeper != nil && mapper != nil && (keeper == mapper || sameProcessPID(keeper, mapper)) {
		return nil, recoveredProcesses{}, false
	}
	owned, err := recovered.Namespace.Duplicate()
	if err != nil || owned == nil || !owned.Correlates(request.Namespace) {
		return nil, recoveredProcesses{}, false
	}
	if closeErr := guardedCleanup(recovered.Namespace.Close); closeErr != nil {
		_ = owned.Close()
		return nil, recoveredProcesses{}, false
	}
	recovered.Namespace = nil
	return owned, recoveredProcesses{keeper: keeper, mapper: mapper}, true
}

func acceptedRecoveryProcess(handle ProcessHandle) (ProcessHandle, bool) {
	if handle == nil {
		return nil, true
	}
	if valueIsNil(handle) {
		return nil, false
	}
	return handle, true
}

func sameProcessPID(left, right ProcessHandle) bool {
	if left == nil || right == nil {
		return false
	}
	pid := left.PID()
	return pid > 0 && pid == right.PID()
}

func abandonRecoveredOwnership(request RecoveryRequest, recovered RecoveredOwnership) {
	if recovered.Namespace != nil && recovered.Namespace != request.Namespace {
		_ = guardedCleanup(recovered.Namespace.Close)
	}
	closeRecoveredProcesses(recovered.Keeper, recovered.Mapper)
	if recovered.Lease != nil && !valueIsNil(recovered.Lease) {
		_ = guardedCleanup(recovered.Lease.Release)
	}
}

func closeRecoveredProcesses(handles ...ProcessHandle) {
	for _, handle := range handles {
		if closer, ok := handle.(interface{ closePIDFD() }); ok {
			_ = guardedCleanup(func() error {
				closer.closePIDFD()
				return nil
			})
		}
	}
}

func valueIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func sanitizeRecoveryError(err error) error {
	switch {
	case err == nil:
		return ErrStaleTopologyUnverified
	case errors.Is(err, ErrTopologyCollision):
		return ErrTopologyCollision
	case errors.Is(err, ErrStaleGeneration):
		return ErrStaleGeneration
	case errors.Is(err, ErrIdentityMismatch):
		return ErrIdentityMismatch
	case errors.Is(err, ErrInvalidIdentity):
		return ErrInvalidIdentity
	case errors.Is(err, ErrStaleTopologyUnverified):
		return ErrStaleTopologyUnverified
	default:
		return ErrStaleTopologyUnverified
	}
}

func guardedCleanup(fn func() error) (err error) {
	defer func() {
		if panicked := recover(); panicked != nil {
			err = ErrCleanupIncomplete
		}
	}()
	return fn()
}
