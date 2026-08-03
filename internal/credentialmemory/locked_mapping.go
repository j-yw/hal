package credentialmemory

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const MaxLockedMappingBytes = 64 << 20

var (
	ErrCredentialMemoryCapacity      = errors.New("credential memory capacity is invalid")
	ErrCredentialMemoryLoad          = errors.New("credential memory load failed")
	ErrCredentialMemoryUnavailable   = errors.New("credential memory is unavailable")
	ErrCredentialMemoryAlreadyLoaded = errors.New("credential memory is already loaded")
	ErrCredentialMemoryBusy          = errors.New("credential memory is busy")
	ErrCredentialMemoryDestroyed     = errors.New("credential memory is destroyed")
	ErrCredentialMemoryUnlocked      = errors.New("credential memory could not be locked")
	ErrCredentialSinkLimitExceeded   = errors.New("credential sink limit exceeded")
	ErrBorrowedViewExpired           = errors.New("credential memory borrowed view expired")
	ErrCredentialMemorySerialization = errors.New("credential memory serialization is denied")
	ErrCredentialMemoryCleanup       = errors.New("credential memory cleanup failed")
	ErrCredentialProcessHardening    = errors.New("credential process hardening failed")
	ErrCredentialMemoryUnsupported   = errors.New("credential memory is unsupported")
	ErrCredentialMemoryBorrow        = errors.New("credential memory borrow failed")
	ErrCredentialSinkWrite           = errors.New("credential sink write failed")
)

type LockedMappingState string

const (
	LockedMappingStateUnavailable LockedMappingState = "unavailable"
	LockedMappingStateLoading     LockedMappingState = "loading"
	LockedMappingStateLoaded      LockedMappingState = "loaded"
	LockedMappingStateBorrowing   LockedMappingState = "borrowing"
	LockedMappingStateDestroying  LockedMappingState = "destroying"
	LockedMappingStateDestroyed   LockedMappingState = "destroyed"
)

type CredentialSink interface {
	MaxCredentialBytes() int
	WriteCredential([]byte) error
}

type BorrowedView interface {
	Len() int
	CopyTo(context.Context, *LockedMapping) error
	WriteTo(context.Context, CredentialSink) error
}

type LockedMapping struct {
	identity lockedMappingIdentity
	state    *lockedMappingState
}

type lockedMappingState struct {
	mu            sync.Mutex
	cond          *sync.Cond
	owner         *lockedMappingIdentity
	ops           memoryOps
	region        []byte
	length        int
	phase         LockedMappingState
	active        bool
	cleanupFailed bool
}

type borrowedView struct {
	identity borrowedViewIdentity
	lease    *borrowedViewLease
}

type borrowedViewLease struct {
	mu        sync.Mutex
	canonical *borrowedViewIdentity
	owner     *lockedMappingState
	length    int
	active    bool
}

type lockedMappingIdentity struct{ marker byte }

type borrowedViewIdentity struct{ marker byte }

type memoryOps interface {
	MapAnonymous(int) ([]byte, error)
	Lock([]byte) error
	Unlock([]byte) error
	Unmap([]byte) error
}

type processSecurityOps interface {
	SetCoreLimitZero() error
	SetDumpableFalse() error
	IsDumpable() (bool, error)
}

func newLockedMapping(capacity int, ops memoryOps) (*LockedMapping, error) {
	if capacity <= 0 || capacity > MaxLockedMappingBytes {
		return nil, ErrCredentialMemoryCapacity
	}
	if ops == nil {
		return nil, ErrCredentialMemoryUnavailable
	}
	region, err := ops.MapAnonymous(capacity)
	if err != nil || len(region) != capacity {
		if region != nil {
			wipeCredentialRegion(region)
			_ = ops.Unmap(region)
		}
		return nil, ErrCredentialMemoryUnavailable
	}
	if err := ops.Lock(region); err != nil {
		wipeCredentialRegion(region)
		_ = ops.Unmap(region)
		return nil, ErrCredentialMemoryUnlocked
	}
	state := &lockedMappingState{
		ops:    ops,
		region: region,
		phase:  LockedMappingStateUnavailable,
	}
	state.cond = sync.NewCond(&state.mu)
	mapping := &LockedMapping{state: state}
	state.owner = &mapping.identity
	return mapping, nil
}

func (mapping *LockedMapping) State() LockedMappingState {
	state := mapping.mappingState()
	if state == nil {
		return LockedMappingStateDestroyed
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.phase
}

func (mapping *LockedMapping) Load(ctx context.Context, reader func([]byte) (int, error)) error {
	if ctx == nil || reader == nil {
		return ErrCredentialMemoryLoad
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	state := mapping.mappingState()
	if state == nil {
		return ErrCredentialMemoryDestroyed
	}

	state.mu.Lock()
	switch state.phase {
	case LockedMappingStateDestroying, LockedMappingStateDestroyed:
		state.mu.Unlock()
		return ErrCredentialMemoryDestroyed
	case LockedMappingStateLoading, LockedMappingStateBorrowing:
		state.mu.Unlock()
		return ErrCredentialMemoryBusy
	case LockedMappingStateLoaded:
		state.mu.Unlock()
		return ErrCredentialMemoryAlreadyLoaded
	}
	if err := ctx.Err(); err != nil {
		state.mu.Unlock()
		return classifyContextError(err)
	}
	state.phase = LockedMappingStateLoading
	state.active = true
	region := state.region
	state.mu.Unlock()

	loaded := false
	length := 0
	defer func() {
		state.mu.Lock()
		if !loaded {
			wipeCredentialRegion(region)
			state.length = 0
		} else {
			wipeCredentialRegion(region[length:])
			state.length = length
		}
		state.active = false
		if state.phase != LockedMappingStateDestroying {
			if loaded {
				state.phase = LockedMappingStateLoaded
			} else {
				state.phase = LockedMappingStateUnavailable
			}
		}
		state.cond.Broadcast()
		state.mu.Unlock()
	}()

	n, err := reader(region)
	if err != nil {
		return classifyLoadError(err)
	}
	if n < 0 || n > len(region) {
		return ErrCredentialMemoryLoad
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	length = n
	loaded = true
	return nil
}

func (mapping *LockedMapping) Borrow(ctx context.Context, callback func(BorrowedView) error) error {
	if ctx == nil || callback == nil {
		return ErrCredentialMemoryBorrow
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	state := mapping.mappingState()
	if state == nil {
		return ErrCredentialMemoryDestroyed
	}

	state.mu.Lock()
	switch state.phase {
	case LockedMappingStateDestroying, LockedMappingStateDestroyed:
		state.mu.Unlock()
		return ErrCredentialMemoryDestroyed
	case LockedMappingStateLoading, LockedMappingStateBorrowing:
		state.mu.Unlock()
		return ErrCredentialMemoryBusy
	case LockedMappingStateUnavailable:
		state.mu.Unlock()
		return ErrCredentialMemoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		state.mu.Unlock()
		return classifyContextError(err)
	}
	state.phase = LockedMappingStateBorrowing
	state.active = true
	view := &borrowedView{}
	view.lease = &borrowedViewLease{
		canonical: &view.identity,
		owner:     state,
		length:    state.length,
		active:    true,
	}
	state.mu.Unlock()

	defer func() {
		view.expire()
		state.mu.Lock()
		state.active = false
		if state.phase != LockedMappingStateDestroying {
			state.phase = LockedMappingStateLoaded
		}
		state.cond.Broadcast()
		state.mu.Unlock()
	}()

	if err := callback(view); err != nil {
		return classifyBorrowError(err)
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	return nil
}

func (mapping *LockedMapping) Destroy() error {
	if mapping == nil || mapping.state == nil {
		return nil
	}
	state := mapping.mappingState()
	if state == nil {
		return ErrCredentialMemoryDestroyed
	}
	state.mu.Lock()
	for state.phase == LockedMappingStateDestroying {
		state.cond.Wait()
	}
	if state.phase == LockedMappingStateDestroyed {
		failed := state.cleanupFailed
		state.mu.Unlock()
		if failed {
			return ErrCredentialMemoryCleanup
		}
		return nil
	}
	state.phase = LockedMappingStateDestroying
	for state.active {
		state.cond.Wait()
	}
	region := state.region
	ops := state.ops
	wipeCredentialRegion(region)
	state.mu.Unlock()

	unlockErr := ops.Unlock(region)
	unmapErr := ops.Unmap(region)
	failed := unlockErr != nil || unmapErr != nil

	state.mu.Lock()
	state.region = nil
	state.length = 0
	state.cleanupFailed = failed
	state.phase = LockedMappingStateDestroyed
	state.cond.Broadcast()
	state.mu.Unlock()
	if failed {
		return ErrCredentialMemoryCleanup
	}
	return nil
}

func (view *borrowedView) Len() int {
	lease := view.borrowedLease()
	if lease == nil {
		return 0
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.active {
		return 0
	}
	return lease.length
}

func (view *borrowedView) CopyTo(ctx context.Context, target *LockedMapping) error {
	lease := view.borrowedLease()
	if lease == nil {
		return ErrBorrowedViewExpired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.active || lease.owner == nil {
		return ErrBorrowedViewExpired
	}
	if ctx == nil {
		return ErrCredentialMemoryLoad
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	if target == nil {
		return ErrCredentialMemoryUnavailable
	}
	owner := lease.owner
	length := lease.length
	return target.Load(ctx, func(dst []byte) (int, error) {
		copy(dst, owner.region[:length])
		return length, nil
	})
}

func (view *borrowedView) WriteTo(ctx context.Context, sink CredentialSink) error {
	lease := view.borrowedLease()
	if lease == nil {
		return ErrBorrowedViewExpired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.active || lease.owner == nil {
		return ErrBorrowedViewExpired
	}
	if ctx == nil {
		return ErrCredentialSinkWrite
	}
	if err := ctx.Err(); err != nil {
		return classifyContextError(err)
	}
	if sink == nil {
		return ErrCredentialSinkWrite
	}
	if sink.MaxCredentialBytes() < lease.length {
		return ErrCredentialSinkLimitExceeded
	}
	if err := sink.WriteCredential(lease.owner.region[:lease.length]); err != nil {
		return classifySinkError(err)
	}
	return nil
}

func (view *borrowedView) expire() {
	lease := view.borrowedLease()
	if lease == nil {
		return
	}
	lease.mu.Lock()
	lease.active = false
	lease.owner = nil
	lease.length = 0
	lease.mu.Unlock()
}

func (mapping *LockedMapping) mappingState() *lockedMappingState {
	if mapping == nil || mapping.state == nil || mapping.state.owner != &mapping.identity {
		return nil
	}
	return mapping.state
}

func (view *borrowedView) borrowedLease() *borrowedViewLease {
	if view == nil || view.lease == nil || view.lease.canonical != &view.identity {
		return nil
	}
	return view.lease
}

func wipeCredentialRegion(region []byte) {
	clear(region)
}

func classifyContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrCredentialMemoryUnavailable
}

func classifyLoadError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return classifyContextError(err)
	}
	return ErrCredentialMemoryLoad
}

func classifyBorrowError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return classifyContextError(err)
	}
	return ErrCredentialMemoryBorrow
}

func classifySinkError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return classifyContextError(err)
	}
	return ErrCredentialSinkWrite
}

func hardenCredentialProcess(ops processSecurityOps) error {
	if ops == nil {
		return ErrCredentialProcessHardening
	}
	if err := ops.SetCoreLimitZero(); err != nil {
		return ErrCredentialProcessHardening
	}
	if err := ops.SetDumpableFalse(); err != nil {
		return ErrCredentialProcessHardening
	}
	dumpable, err := ops.IsDumpable()
	if err != nil || dumpable {
		return ErrCredentialProcessHardening
	}
	return nil
}

func (LockedMapping) String() string {
	return "<credentialmemory.LockedMapping>"
}

func (LockedMapping) GoString() string {
	return "<credentialmemory.LockedMapping>"
}

func (LockedMapping) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialMemorySerialization
}

func (LockedMapping) MarshalText() ([]byte, error) {
	return nil, ErrCredentialMemorySerialization
}

func (LockedMapping) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialmemory.LockedMapping>")
}

func (borrowedView) String() string {
	return "<credentialmemory.borrowedView>"
}

func (borrowedView) GoString() string {
	return "<credentialmemory.borrowedView>"
}

func (borrowedView) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialMemorySerialization
}

func (borrowedView) MarshalText() ([]byte, error) {
	return nil, ErrCredentialMemorySerialization
}

func (borrowedView) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialmemory.borrowedView>")
}
