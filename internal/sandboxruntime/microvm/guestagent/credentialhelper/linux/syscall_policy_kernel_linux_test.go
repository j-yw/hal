//go:build linux

package linux

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

func TestL8D4SyscallPolicyKernelFailsClosedWithoutCompleteD7Authority(t *testing.T) {
	if kernel, err := NewSyscallPolicyCoreKernel(SyscallPolicyCoreKernelOptions{}); kernel != nil || !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("NewSyscallPolicyCoreKernel(zero) = %#v, %v", kernel, err)
	}

	var typedNil *recordingCoreKernel
	if kernel, err := NewSyscallPolicyCoreKernel(SyscallPolicyCoreKernelOptions{Kernel: typedNil}); kernel != nil || !errors.Is(err, credentialhelper.ErrContractTypedNil) {
		t.Fatalf("NewSyscallPolicyCoreKernel(typed nil) = %#v, %v", kernel, err)
	}

	injected := &recordingCoreKernel{}
	kernel, err := NewSyscallPolicyCoreKernel(SyscallPolicyCoreKernelOptions{Kernel: injected})
	if kernel != nil || !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("NewSyscallPolicyCoreKernel(incomplete D7) = %#v, %v", kernel, err)
	}
	if injected.beginPrepareCalls != 0 || injected.beginExecCalls != 0 || injected.renewCalls != 0 || injected.revokeCalls != 0 || injected.inspectCalls != 0 || injected.closeCalls != 0 {
		t.Fatal("unavailable constructor invoked or cleaned caller-owned kernel")
	}
}
