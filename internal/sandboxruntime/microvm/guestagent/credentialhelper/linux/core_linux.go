//go:build linux

package linux

import (
	"context"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

type core struct {
	mu     sync.RWMutex
	kernel CoreKernel
	closed bool
}

var _ credentialhelper.Core = (*core)(nil)

// NewCore constructs the explicit Linux credential-helper core foundation.
// It never selects a live kernel implementation or policy implicitly.
func NewCore(options CoreOptions) (credentialhelper.Core, error) {
	if err := coreKernelDependencyError(options.Kernel); err != nil {
		return nil, err
	}
	return &core{kernel: options.Kernel}, nil
}

func (core *core) BeginPrepare(ctx context.Context, request credentialhelper.CorePrepareRequest) (credentialhelper.CorePreparation, error) {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.closed {
		return nil, credentialhelper.ErrContractDestroyed
	}
	return core.kernel.BeginPrepare(ctx, request)
}

func (core *core) BeginExec(ctx context.Context, request credentialhelper.CoreExecRequest, body credentialmemory.BorrowedView) (credentialhelper.CoreExecution, error) {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.closed {
		return nil, credentialhelper.ErrContractDestroyed
	}
	return core.kernel.BeginExec(ctx, request, body)
}

func (core *core) Renew(ctx context.Context, request credentialhelper.CoreRenewRequest) error {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.closed {
		return credentialhelper.ErrContractDestroyed
	}
	return core.kernel.Renew(ctx, request)
}

func (core *core) Revoke(ctx context.Context, request credentialhelper.CoreRevokeRequest) (credentialhelper.CoreCleanupResult, error) {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.closed {
		return credentialhelper.CoreCleanupResult{}, credentialhelper.ErrContractDestroyed
	}
	return core.kernel.Revoke(ctx, request)
}

func (core *core) Inspect(ctx context.Context, request credentialhelper.CoreInspectRequest) (credentialhelper.CoreInspection, error) {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.closed {
		return credentialhelper.CoreInspection{}, credentialhelper.ErrContractDestroyed
	}
	return core.kernel.Inspect(ctx, request)
}

func (core *core) Close(ctx context.Context) error {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.closed {
		return nil
	}
	core.closed = true
	return core.kernel.Close(ctx)
}
