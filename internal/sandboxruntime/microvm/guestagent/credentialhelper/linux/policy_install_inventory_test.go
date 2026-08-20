package linux

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

func TestL8D4GeneratedInstallInventoryMatchesExactD2RolesAndKinds(t *testing.T) {
	want := [...]policyInstallBinding{
		{installRole: rolebootstrap.RolePID1, policyRole: syscallpolicy.RoleLaunchBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleController, policyRole: syscallpolicy.RoleControllerBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleAgent, policyRole: syscallpolicy.RoleAgentBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleMonitor, policyRole: syscallpolicy.RoleMonitorBootstrap, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
		{installRole: rolebootstrap.RoleWorkloadShim, policyRole: syscallpolicy.RoleWorkloadTransition, binaryKind: syscallpolicy.BinaryBindingKindNativeBootstrap},
	}
	generated, generatedSHA256 := generatedPolicyInstallInventory()
	if generated != want {
		t.Fatalf("generated install inventory = %#v, want exact D2 role/kind map", generated)
	}
	digest, err := policyInstallInventorySHA256()
	if err != nil || digest == ([32]byte{}) || digest != generatedSHA256 {
		t.Fatalf("install inventory digest = %x, %v", digest, err)
	}
	callsites := generatedPolicyAdapterCallsiteInventory()
	if len(callsites) != 0 {
		t.Fatalf("current incomplete D7 artifact generated %d adapter callsites, want zero", len(callsites))
	}
	if policyAdapterCallsiteInventoryReady(nil) {
		t.Fatal("empty D7 adapter inventory reported ready")
	}
}

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
