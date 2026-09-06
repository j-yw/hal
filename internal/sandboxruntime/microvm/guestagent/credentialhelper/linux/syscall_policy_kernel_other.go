//go:build !linux

package linux

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"

// NewSyscallPolicyCoreKernel fails closed away from Linux without inspecting
// or retaining the injected kernel or install plan.
func NewSyscallPolicyCoreKernel(SyscallPolicyCoreKernelOptions) (CoreKernel, error) {
	return nil, credentialhelper.ErrContractDependency
}
