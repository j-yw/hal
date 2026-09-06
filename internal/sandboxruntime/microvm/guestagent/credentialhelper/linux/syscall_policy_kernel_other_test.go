//go:build !linux

package linux

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

func TestSyscallPolicyCoreKernelIsUnavailableAwayFromLinux(t *testing.T) {
	kernel, err := NewSyscallPolicyCoreKernel(SyscallPolicyCoreKernelOptions{Kernel: panicCoreKernel{}})
	if kernel != nil || !errors.Is(err, credentialhelper.ErrContractDependency) {
		t.Fatalf("NewSyscallPolicyCoreKernel() = %#v, %v", kernel, err)
	}
}

type panicCoreKernel struct{ CoreKernel }
