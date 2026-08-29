package syscallpolicy

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D7LaunchBaseClone3ExecveTemplatesMatchDecideAndCompiledBPF(t *testing.T) {
	t.Parallel()
	profile := issuedLaunchBaseFilterProfile(t)
	compiled, err := CompileFilterProfile(profile)
	if err != nil {
		t.Fatalf("CompileFilterProfile(launch-base) error = %v", err)
	}
	auditArch := uint32(0xc000003e)
	exactClone3 := [6]uint64{1, 88}
	flagSets := []struct {
		name   string
		flags  uint64
		cgroup uint64
	}{
		{name: "controller", flags: 0x5100, cgroup: 0},
		{name: "agent", flags: 0x5100, cgroup: 0},
		{name: "monitor", flags: 0x25100, cgroup: 0},
		{name: "shim", flags: 0x200005100, cgroup: 9},
	}
	for _, op := range flagSets {
		decision := profile.Decide(auditArch, 435, exactClone3)
		if !decision.Allowed() || decision.Reason() != ReasonExactRule {
			t.Fatalf("Decide clone3 %s flags=%#x cgroup=%d = %v/%v, want allow/exact-rule for pointer/size template", op.name, op.flags, op.cgroup, decision.Action(), decision.Reason())
		}
		if got := compiled.Action(auditArch, 435, exactClone3); got != decision.Action() {
			t.Fatalf("compiled clone3 %s Action() = %v, want Decide %v", op.name, got, decision.Action())
		}
	}

	clone3HasTemplate := false
	execveatHasTemplate := false
	execveRuleCount := 0
	sendmsgRuleCount := 0
	recvmsgRuleCount := 0
	for _, rule := range profile.Rules() {
		switch rule.SyscallNumber() {
		case 435:
			clone3HasTemplate = true
			if len(rule.ScalarClauses()) == 0 {
				t.Fatal("launch-base clone3 is catalog-name-only with no argument template")
			}
		case 322:
			execveatHasTemplate = true
			if len(rule.ScalarClauses()) == 0 {
				t.Fatal("launch-base execveat is catalog-name-only with no argument template")
			}
		case 59:
			execveRuleCount++
		case 46:
			sendmsgRuleCount++
		case 47:
			recvmsgRuleCount++
		}
	}
	if !clone3HasTemplate {
		t.Fatal("launch-base filter is missing the clone3 argument template")
	}
	if !execveatHasTemplate {
		t.Fatal("launch-base filter is missing the execveat FD+AT_EMPTY_PATH template")
	}
	if execveRuleCount != 0 {
		t.Fatal("launch-base filter encoded an execve row; pathname templates are not HL8Q-scalar-encodable so execve must stay unlisted")
	}
	if sendmsgRuleCount != 0 || recvmsgRuleCount != 0 {
		t.Fatal("launch-base filter encoded a sendmsg/recvmsg row; SCM_RIGHTS cmsg contents are not HL8Q-scalar-encodable")
	}

	for _, fd := range []uint64{5, 6} {
		args := [6]uint64{fd, 1, 0, 0, 0x1000}
		decision := profile.Decide(auditArch, 322, args)
		if !decision.Allowed() || decision.Reason() != ReasonExactRule {
			t.Fatalf("Decide execveat fd %d AT_EMPTY_PATH = %v/%v, want allow/exact-rule", fd, decision.Action(), decision.Reason())
		}
		if got := compiled.Action(auditArch, 322, args); got != decision.Action() {
			t.Fatalf("compiled execveat fd %d Action() = %v, want Decide %v", fd, got, decision.Action())
		}
	}

	pathnames := []string{
		"/usr/bin/hal-guest-credential-helper",
		"/usr/bin/hal-guest-agent",
		"/usr/bin/hal-guest-mount-monitor",
		"/usr/bin/hal-guest-workload-shim",
	}
	for index, pathname := range pathnames {
		args := [6]uint64{uint64(index + 1), 1, 0}
		decision := profile.Decide(auditArch, 59, args)
		if decision.Action() != ActionKillProcess {
			t.Fatalf("Decide execve pathname %s = %v, want kill (pathname execve is no longer a native _start site)", pathname, decision.Action())
		}
		if got := compiled.Action(auditArch, 59, args); got != decision.Action() {
			t.Fatalf("compiled execve pathname %s Action() = %v, want Decide %v", pathname, got, decision.Action())
		}
	}

	mismatches := []struct {
		name string
		nr   uint32
		args [6]uint64
	}{
		{name: "clone3 empty", nr: 435},
		{name: "clone3 missing pidfd/clone_args pointer", nr: 435, args: [6]uint64{0, 88}},
		{name: "clone3 wrong size 64", nr: 435, args: [6]uint64{1, 64}},
		{name: "clone3 wrong size 0", nr: 435, args: [6]uint64{1, 0}},
		{name: "clone3 catalog name only", nr: 435},
		{name: "execve empty", nr: 59},
		{name: "execve nonempty envp", nr: 59, args: [6]uint64{1, 1, 1}},
		{name: "execveat empty", nr: 322},
		{name: "execveat catalog name only", nr: 322},
		{name: "execveat wrong fd 16", nr: 322, args: [6]uint64{16, 1, 0, 0, 0x1000}},
		{name: "execveat missing AT_EMPTY_PATH", nr: 322, args: [6]uint64{5, 1, 0, 0, 0}},
		{name: "execveat nonempty envp", nr: 322, args: [6]uint64{5, 1, 0, 1, 0x1000}},
		{name: "recvmsg empty", nr: 47},
		{name: "recvmsg fd 16 MSG_CMSG_CLOEXEC|MSG_DONTWAIT", nr: 47, args: [6]uint64{16, 1, 0x40000040}},
		{name: "sendmsg empty", nr: 46},
		{name: "sendmsg catalog name only", nr: 46, args: [6]uint64{16, 1, 0}},
	}
	for _, test := range mismatches {
		decision := profile.Decide(auditArch, test.nr, test.args)
		if decision.Allowed() || (decision.Action() != ActionErrnoEPERM && decision.Action() != ActionKillProcess) {
			t.Fatalf("Decide %s = %v/%v, want eperm or kill", test.name, decision.Action(), decision.Reason())
		}
		if got := compiled.Action(auditArch, test.nr, test.args); got != decision.Action() {
			t.Fatalf("compiled %s Action() = %v, want Decide %v", test.name, got, decision.Action())
		}
	}
}

func issuedLaunchBaseFilterProfile(t *testing.T) FilterProfile {
	t.Helper()
	root := syscallpolicyRepositoryRoot(t)
	encoded, err := os.ReadFile(filepath.Join(root, "tools/microvm/l8/policy/verified-syscall-policy.hl8q"))
	if err != nil {
		t.Fatalf("read issued HL8Q: %v", err)
	}
	digestLine, err := os.ReadFile(filepath.Join(root, "tools/microvm/l8/policy/verified-syscall-policy.hl8q.sha256"))
	if err != nil {
		t.Fatalf("read issued HL8Q digest: %v", err)
	}
	digestHex := strings.TrimSpace(string(digestLine))
	decoded, err := hex.DecodeString(digestHex)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("issued HL8Q digest %q is invalid: %v", digestHex, err)
	}
	var digest [32]byte
	copy(digest[:], decoded)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{sha256: digest, issuer: expectedIssuer{issued: true}})
	if err != nil {
		t.Fatalf("ImportVerifiedPolicyArtifact(): %v", err)
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	profile, err := policy.FilterProfile(RoleLaunchBase)
	if err != nil {
		t.Fatalf("FilterProfile(RoleLaunchBase): %v", err)
	}
	return profile
}

func syscallpolicyRepositoryRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(current, "go.mod")); statErr == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root not found")
		}
		current = parent
	}
}
