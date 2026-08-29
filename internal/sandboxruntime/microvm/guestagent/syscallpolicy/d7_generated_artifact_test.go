//go:build l8_verified_policy_artifact

package syscallpolicy

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestL8D7GeneratedArtifactImportsCanonicalNonzeroAuthority(t *testing.T) {
	artifact, err := EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		t.Fatalf("EmbeddedVerifiedPolicyArtifact() error code = %v", d7ContractErrorCode(err))
	}
	if artifact.SHA256() == ([sha256.Size]byte{}) || artifact.SourceLockSHA256() == ([sha256.Size]byte{}) {
		t.Fatal("generated D7 artifact returned zero authority")
	}
	if artifact.SHA256() != embeddedVerifiedPolicyArtifactSHA256 || artifact.SourceLockSHA256() != embeddedVerifiedPolicySourceLockSHA256 {
		t.Fatal("generated D7 artifact does not match its independently embedded expectations")
	}
	if len(embeddedVerifiedPolicyArtifactBytes) == 0 || len(embeddedVerifiedPolicyArtifactBytes) > MaxVerifiedPolicyArtifactBytes {
		t.Fatalf("generated D7 artifact byte length = %d", len(embeddedVerifiedPolicyArtifactBytes))
	}
	if len(artifact.Catalog()) < 300 || len(artifact.Rules()) != 47 || len(artifact.Transitions()) != 9 {
		t.Fatalf("generated D7 topology = catalog:%d rules:%d transitions:%d", len(artifact.Catalog()), len(artifact.Rules()), len(artifact.Transitions()))
	}
	if len(artifact.Workload().Rules()) != 1 || len(artifact.Runtime().Rules()) != 19 || artifact.Runtime().GoVersion() != "go1.25.7" {
		t.Fatal("generated D7 workload/runtime projections are incomplete")
	}
	for _, rule := range artifact.Runtime().Rules() {
		if rule.SyscallNumber() == 435 || rule.SyscallNumber() == 56 {
			t.Fatal("Go runtime envelope projection includes clone or clone3")
		}
	}
	legacyFound := false
	for _, entry := range artifact.Catalog() {
		if entry.Number() == 156 {
			legacyFound = entry.Name() == "_sysctl"
		}
	}
	if !legacyFound {
		t.Fatal("generated D7 catalog does not preserve exact legacy row 156,_sysctl")
	}
}

func TestL8D7GeneratedLaunchBaseClone3ExecveTemplates(t *testing.T) {
	artifact, err := EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		t.Fatalf("EmbeddedVerifiedPolicyArtifact() error code = %v", d7ContractErrorCode(err))
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	profile, err := policy.FilterProfile(RoleLaunchBase)
	if err != nil {
		t.Fatalf("FilterProfile(RoleLaunchBase) error = %v", err)
	}
	compiled, err := CompileFilterProfile(profile)
	if err != nil {
		t.Fatalf("CompileFilterProfile() error = %v", err)
	}
	exact := [6]uint64{1, 88}
	decision := profile.Decide(0xc000003e, 435, exact)
	if !decision.Allowed() {
		t.Fatalf("generated launch-base clone3 template Decide() = %v/%v, want allow", decision.Action(), decision.Reason())
	}
	if got := compiled.Action(0xc000003e, 435, exact); got != decision.Action() {
		t.Fatalf("generated compiled clone3 Action() = %v, want Decide %v", got, decision.Action())
	}
	if got := profile.Decide(0xc000003e, 322, [6]uint64{5, 1, 0, 0, 0x1000}); !got.Allowed() {
		t.Fatalf("generated launch-base execveat FD 5 Decide() = %v/%v, want allow", got.Action(), got.Reason())
	}
	if got := profile.Decide(0xc000003e, 322, [6]uint64{6, 1, 0, 0, 0x1000}); !got.Allowed() {
		t.Fatalf("generated launch-base execveat FD 6 Decide() = %v/%v, want allow", got.Action(), got.Reason())
	}
	if got := compiled.Action(0xc000003e, 322, [6]uint64{5, 1, 0, 0, 0x1000}); got != ActionAllow {
		t.Fatalf("generated compiled execveat FD 5 Action() = %v, want allow", got)
	}
	if got := profile.Decide(0xc000003e, 322, [6]uint64{}); got.Action() != ActionErrnoEPERM {
		t.Fatalf("generated launch-base empty execveat Decide() = %v, want eperm", got.Action())
	}
	if got := profile.Decide(0xc000003e, 59, [6]uint64{1, 1, 0}); got.Action() != ActionKillProcess {
		t.Fatalf("generated launch-base execve Decide() = %v, want kill", got.Action())
	}
	if got := profile.Decide(0xc000003e, 47, [6]uint64{16, 1, 0x40000040}); got.Action() != ActionErrnoEPERM {
		t.Fatalf("generated launch-base recvmsg Decide() = %v, want eperm", got.Action())
	}
	if got := compiled.Action(0xc000003e, 47, [6]uint64{16, 1, 0x40000040}); got != ActionErrnoEPERM {
		t.Fatalf("generated compiled recvmsg Action() = %v, want eperm", got)
	}
}

func TestL8D7GeneratedArtifactInputMutationFailsClosed(t *testing.T) {
	mutated := append([]byte(nil), embeddedVerifiedPolicyArtifactBytes...)
	mutated[len(mutated)-1] ^= 0x01
	artifact, err := ImportVerifiedPolicyArtifact(mutated, ExpectedPolicyArtifact{
		sha256: embeddedVerifiedPolicyArtifactSHA256,
		issuer: expectedIssuer{issued: true},
	})
	if artifact.artifact != nil || artifact.SHA256() != ([sha256.Size]byte{}) {
		t.Fatal("mutated generated artifact returned authority")
	}
	if got := d7ContractErrorCode(err); got != ErrorCodeDigestMismatch {
		t.Fatalf("mutated generated artifact error = %v, want digest-mismatch", got)
	}
}

func d7ContractErrorCode(err error) ErrorCode {
	var contractError *ContractError
	if !errors.As(err, &contractError) {
		return 0
	}
	return contractError.Code()
}
