//go:build linux

package linux

import (
	"crypto/subtle"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

// NewSyscallPolicyCoreKernel is the fail-closed D4 junction for the later live
// wrapper. This slice validates only D2/D7-issued immutable authority. It does
// not retain the injected kernel and cannot return a live CoreKernel until D7
// emits complete adapter callsites, expected final-binary evidence, and the
// native role-bootstrap artifact.
func NewSyscallPolicyCoreKernel(options SyscallPolicyCoreKernelOptions) (CoreKernel, error) {
	if err := coreKernelDependencyError(options.Kernel); err != nil {
		return nil, err
	}
	installInventorySHA256, err := policyInstallInventorySHA256()
	if err != nil {
		return nil, credentialhelper.ErrContractDependency
	}
	artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()
	if err != nil || artifact.SHA256() == ([32]byte{}) {
		return nil, credentialhelper.ErrContractDependency
	}
	policy, err := syscallpolicy.NewPolicy(artifact)
	if err != nil || !policyAdapterCallsiteInventoryReady(policy) {
		return nil, credentialhelper.ErrContractDependency
	}
	expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()
	if err != nil || expectedEvidence.SHA256() == ([32]byte{}) {
		return nil, credentialhelper.ErrContractDependency
	}
	generatedArtifact, err := rolebootstrap.EmbeddedGeneratedArtifact()
	if err != nil {
		return nil, credentialhelper.ErrContractDependency
	}
	generatedPolicySHA256 := generatedArtifact.PolicySHA256()
	artifactSHA256 := artifact.SHA256()
	generatedInstallSHA256 := generatedArtifact.NativeInstallTableSHA256()
	if subtle.ConstantTimeCompare(generatedPolicySHA256[:], artifactSHA256[:]) != 1 ||
		subtle.ConstantTimeCompare(generatedInstallSHA256[:], installInventorySHA256[:]) != 1 {
		return nil, credentialhelper.ErrContractCorrelation
	}
	planArtifact := options.InstallPlan.Artifact()
	if options.InstallPlan.Role() != rolebootstrap.RoleAgent ||
		options.InstallPlan.BinarySHA256() == ([32]byte{}) ||
		planArtifact != generatedArtifact {
		return nil, credentialhelper.ErrContractCorrelation
	}

	// The concrete one-use syscall wrapper intentionally remains unavailable in
	// this truthful half. The tagged red gate owns its later lifecycle closure.
	return nil, credentialhelper.ErrContractDependency
}
