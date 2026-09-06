//go:build linux

package linux

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

func TestNewCoreRequiresKernel(t *testing.T) {
	if core, err := NewCore(CoreOptions{}); core != nil || !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("NewCore() = %#v, %v, want dependency failure", core, err)
	}

	var typedNil *recordingCoreKernel
	if core, err := NewCore(CoreOptions{Kernel: typedNil}); core != nil || !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("NewCore(typed nil) = %#v, %v, want typed-nil failure", core, err)
	}
}

func TestCoreDelegatesOnlyThroughInjectedKernel(t *testing.T) {
	kernel := &recordingCoreKernel{}
	core, err := NewCore(CoreOptions{Kernel: kernel})
	if err != nil {
		t.Fatalf("NewCore() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), coreTestContextKey{}, "exact")
	request := credentialhelper.CorePrepareRequest{}
	preparation, err := core.BeginPrepare(ctx, request)
	if err != nil {
		t.Fatalf("BeginPrepare() error = %v", err)
	}
	if preparation != kernel.preparation || kernel.beginPrepareCalls != 1 || kernel.prepareContext != ctx || kernel.prepareRequest != request {
		t.Fatalf("BeginPrepare() did not preserve the exact injected call")
	}
	if err := core.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := core.Close(ctx); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if kernel.closeCalls != 1 || kernel.closeContext != ctx {
		t.Fatalf("kernel Close calls/context = %d/%v, want 1/exact", kernel.closeCalls, kernel.closeContext == ctx)
	}
}

func TestCoreRejectsUseAfterClose(t *testing.T) {
	kernel := &recordingCoreKernel{}
	core, err := NewCore(CoreOptions{Kernel: kernel})
	if err != nil {
		t.Fatalf("NewCore() error = %v", err)
	}
	if err := core.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := core.BeginPrepare(context.Background(), credentialhelper.CorePrepareRequest{}); !errors.Is(err, credentialhelper.ErrContractDestroyed) {
		t.Fatalf("BeginPrepare() error = %v, want destroyed", err)
	}
	if kernel.beginPrepareCalls != 0 {
		t.Fatalf("kernel BeginPrepare calls = %d, want 0", kernel.beginPrepareCalls)
	}
}

func TestCoreDelegatesRemainingOperationsThroughKernel(t *testing.T) {
	kernel := &recordingCoreKernel{}
	core, err := NewCore(CoreOptions{Kernel: kernel})
	if err != nil {
		t.Fatalf("NewCore() error = %v", err)
	}
	ctx := context.WithValue(context.Background(), coreTestContextKey{}, "remaining")
	if _, err := core.BeginExec(ctx, credentialhelper.CoreExecRequest{}, nil); err != nil {
		t.Fatalf("BeginExec() error = %v", err)
	}
	if err := core.Renew(ctx, credentialhelper.CoreRenewRequest{}); err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if _, err := core.Revoke(ctx, credentialhelper.CoreRevokeRequest{}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := core.Inspect(ctx, credentialhelper.CoreInspectRequest{}); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if kernel.beginExecCalls != 1 || kernel.renewCalls != 1 || kernel.revokeCalls != 1 || kernel.inspectCalls != 1 {
		t.Fatalf("kernel operation calls = %d/%d/%d/%d, want 1/1/1/1", kernel.beginExecCalls, kernel.renewCalls, kernel.revokeCalls, kernel.inspectCalls)
	}
	if kernel.remainingContext != ctx {
		t.Fatalf("kernel did not receive the exact context")
	}
}

type coreTestContextKey struct{}

type recordingCoreKernel struct {
	beginPrepareCalls int
	prepareContext    context.Context
	prepareRequest    credentialhelper.CorePrepareRequest
	preparation       credentialhelper.CorePreparation
	beginExecCalls    int
	renewCalls        int
	revokeCalls       int
	inspectCalls      int
	remainingContext  context.Context
	closeCalls        int
	closeContext      context.Context
}

func (kernel *recordingCoreKernel) BeginPrepare(ctx context.Context, request credentialhelper.CorePrepareRequest) (credentialhelper.CorePreparation, error) {
	kernel.beginPrepareCalls++
	kernel.prepareContext = ctx
	kernel.prepareRequest = request
	return kernel.preparation, nil
}

func (kernel *recordingCoreKernel) BeginExec(ctx context.Context, _ credentialhelper.CoreExecRequest, _ credentialmemory.BorrowedView) (credentialhelper.CoreExecution, error) {
	kernel.beginExecCalls++
	kernel.remainingContext = ctx
	return nil, nil
}

func (kernel *recordingCoreKernel) Renew(ctx context.Context, _ credentialhelper.CoreRenewRequest) error {
	kernel.renewCalls++
	kernel.remainingContext = ctx
	return nil
}

func (kernel *recordingCoreKernel) Revoke(ctx context.Context, _ credentialhelper.CoreRevokeRequest) (credentialhelper.CoreCleanupResult, error) {
	kernel.revokeCalls++
	kernel.remainingContext = ctx
	return credentialhelper.CoreCleanupResult{}, nil
}

func (kernel *recordingCoreKernel) Inspect(ctx context.Context, _ credentialhelper.CoreInspectRequest) (credentialhelper.CoreInspection, error) {
	kernel.inspectCalls++
	kernel.remainingContext = ctx
	return credentialhelper.CoreInspection{}, nil
}

func (kernel *recordingCoreKernel) Close(ctx context.Context) error {
	kernel.closeCalls++
	kernel.closeContext = ctx
	return nil
}
