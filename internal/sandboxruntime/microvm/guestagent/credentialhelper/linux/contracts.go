package linux

import (
	"context"
	"reflect"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
)

// CoreKernel is the injected D4 boundary for Linux credential-helper resource
// operations. This foundation intentionally has no default implementation:
// the D2 FilterProfile and D7-issued generated policy remain prerequisites for
// the live kernel adapter.
type CoreKernel interface {
	BeginPrepare(context.Context, credentialhelper.CorePrepareRequest) (credentialhelper.CorePreparation, error)
	BeginExec(context.Context, credentialhelper.CoreExecRequest, credentialmemory.BorrowedView) (credentialhelper.CoreExecution, error)
	Renew(context.Context, credentialhelper.CoreRenewRequest) error
	Revoke(context.Context, credentialhelper.CoreRevokeRequest) (credentialhelper.CoreCleanupResult, error)
	Inspect(context.Context, credentialhelper.CoreInspectRequest) (credentialhelper.CoreInspection, error)
	Close(context.Context) error
}

// CoreOptions contains the complete explicit dependency set for NewCore.
type CoreOptions struct {
	Kernel CoreKernel
}

// SyscallPolicyCoreKernelOptions binds the injected kernel to the exact D7
// native agent install plan. The constructor loads guest policy authority
// internally; callers cannot pass or mint a policy artifact or profile.
type SyscallPolicyCoreKernelOptions struct {
	Kernel      CoreKernel
	InstallPlan rolebootstrap.InstallPlan
}

func coreKernelDependencyError(kernel CoreKernel) error {
	if kernel == nil {
		return credentialhelper.ErrContractDependency
	}
	reflected := reflect.ValueOf(kernel)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if reflected.IsNil() {
			return credentialhelper.ErrContractTypedNil
		}
	}
	return nil
}
