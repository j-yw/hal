package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestL8D7ArtifactGenerationIsDeterministicAndMatchesCheckedInOutputs(t *testing.T) {
	root := repositoryRoot(t)
	first, err := generate(root)
	if err != nil {
		t.Fatalf("generate first copy: %v", err)
	}
	second, err := generate(root)
	if err != nil {
		t.Fatalf("generate second copy: %v", err)
	}
	if !bytes.Equal(first.artifact, second.artifact) || !bytes.Equal(first.guestSource, second.guestSource) || !bytes.Equal(first.d4InstallSource, second.d4InstallSource) {
		t.Fatal("identical locked inputs produced different D7 outputs")
	}
	for path, want := range first.files() {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read checked-in D7 output %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("checked-in D7 output %s is stale", path)
		}
	}
}

func TestL8D7CatalogDerivationPreservesTheFrozenLegacySysctlException(t *testing.T) {
	entries, err := parseCatalog([]byte("const (\n SYS_READ = 0\n SYS__SYSCTL = 156\n)\n"), 450)
	if err != nil {
		t.Fatalf("parseCatalog() error = %v", err)
	}
	if len(entries) != 2 || entries[0] != (catalogEntry{number: 0, name: "read"}) || entries[1] != (catalogEntry{number: 156, name: "_sysctl"}) {
		t.Fatalf("catalog entries = %#v", entries)
	}
	if _, err := parseCatalog([]byte("const (\n SYS__OTHER = 155\n)\n"), 450); err == nil {
		t.Fatal("noncanonical leading-underscore syscall was accepted")
	}
}

func TestL8D7EvidenceIssuanceRejectsBinaryWithoutFinalIdentityAndGraph(t *testing.T) {
	root := repositoryRoot(t)
	outputs, err := generate(root)
	if err != nil {
		t.Fatalf("generate artifact: %v", err)
	}
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	if _, err := generateEvidence(root, binaryPath, outputs); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence() error = %v", err)
	}
}

func TestL8D7EvidenceIssuanceRejectsUnrelatedBinaryWithEmbeddedArtifactAndGenericSyscall(t *testing.T) {
	root := repositoryRoot(t)
	outputs, err := generate(root)
	if err != nil {
		t.Fatalf("generate artifact: %v", err)
	}
	temporary := t.TempDir()
	sourcePath := filepath.Join(temporary, "main.go")
	binaryPath := filepath.Join(temporary, "unrelated")
	source := fmt.Sprintf(`package main

import (
	"os"
	"syscall"
)

var unrelatedEmbeddedArtifact = %#v

func main() {
	_, _ = os.Stdout.Write(unrelatedEmbeddedArtifact[:1])
	_, _, _ = syscall.Syscall6(syscall.SYS_READ, ^uintptr(0), 0, 0, 0, 0, 0)
}
`, outputs.artifact)
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatalf("write unrelated source: %v", err)
	}
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binaryPath, sourcePath)
	command.Dir = root
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=go1.25.7", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build unrelated binary: %v\n%s", err, output)
	}
	if _, err := generateEvidence(root, binaryPath, outputs); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence(unrelated) error = %v", err)
	}
}

func TestL8D7BoundedReadRejectsSymlinkAndIdentityReplacement(t *testing.T) {
	temporary := t.TempDir()
	target := filepath.Join(temporary, "target")
	link := filepath.Join(temporary, "locked-input")
	if err := os.WriteFile(target, []byte("exact locked bytes"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := readBounded(link, 1024); err == nil {
		t.Fatal("bounded read accepted a symlinked locked input")
	}

	path := filepath.Join(temporary, "replaceable")
	replacement := filepath.Join(temporary, "replacement")
	if err := os.WriteFile(path, []byte("same-size-content"), 0o600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}
	if err := os.WriteFile(replacement, []byte("same-size-content"), 0o600); err != nil {
		t.Fatalf("write replacement file: %v", err)
	}
	_, err := readBoundedWithIdentityHook(path, 1024, func() {
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			t.Fatalf("replace file between identity check and read: %v", renameErr)
		}
	})
	if err == nil {
		t.Fatal("bounded read accepted an identity replacement with exact bytes and size")
	}
}

func TestL8D7CheckedOutputRejectsSymlink(t *testing.T) {
	temporary := t.TempDir()
	want := []byte("canonical generated output")
	target := filepath.Join(temporary, "outside-output")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("write output target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(temporary, "checked-output")); err != nil {
		t.Fatalf("create output symlink: %v", err)
	}
	if err := checkFileMap(temporary, map[string][]byte{"checked-output": want}); err == nil {
		t.Fatal("output check accepted a symlink to exact generated bytes")
	}
}

func TestL8D7LockDecoderRejectsAnythingExceptExactClosedInputs(t *testing.T) {
	expected := map[string]string{
		"format":           "hal-l8-runtime-lock-v1",
		"go_version":       "go1.25.7",
		"toolchain_module": "golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64",
	}
	valid := []byte("format=hal-l8-runtime-lock-v1\ngo_version=go1.25.7\ntoolchain_module=golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64\n")
	if _, err := decodeExactLock(valid, expected, "runtime test lock"); err != nil {
		t.Fatalf("decodeExactLock(valid) error = %v", err)
	}
	for _, test := range []struct {
		name    string
		encoded []byte
	}{
		{name: "unknown key", encoded: append(append([]byte(nil), valid...), []byte("extra=value\n")...)},
		{name: "missing key", encoded: []byte("format=hal-l8-runtime-lock-v1\ngo_version=go1.25.7\n")},
		{name: "duplicate key", encoded: append(append([]byte(nil), valid...), []byte("go_version=go1.25.7\n")...)},
		{name: "wrong format", encoded: bytes.Replace(valid, []byte("hal-l8-runtime-lock-v1"), []byte("other"), 1)},
		{name: "wrong toolchain module", encoded: bytes.Replace(valid, []byte("go1.25.7.linux-amd64"), []byte("go1.25.8.linux-amd64"), 1)},
		{name: "garbage", encoded: []byte("not-a-lock\n")},
		{name: "missing final LF", encoded: bytes.TrimSuffix(valid, []byte("\n"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeExactLock(test.encoded, expected, "runtime test lock"); err == nil {
				t.Fatal("noncanonical lock was accepted")
			}
		})
	}
}

func TestL8D7RuntimeEnvelopeLockIsExactNamedGoPID1Catalog(t *testing.T) {
	root := repositoryRoot(t)
	encoded, err := os.ReadFile(filepath.Join(root, policyDir, "roles-v1.yaml"))
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	document, err := decodeRoles(encoded)
	if err != nil {
		t.Fatalf("decodeRoles() error = %v", err)
	}
	want := exactRuntimeEnvelope()
	if !equalStringSlices(document.RuntimeEnvelope, want) {
		t.Fatalf("runtimeEnvelope = %v, want %v", document.RuntimeEnvelope, want)
	}
	if len(want) != 19 || want[0] != "clock_gettime" || want[4] != "getppid" || want[len(want)-1] != "write" {
		t.Fatalf("exactRuntimeEnvelope() = %v", want)
	}
	for _, name := range []string{"clone", "clone3"} {
		for _, got := range want {
			if got == name {
				t.Fatalf("exactRuntimeEnvelope() includes process-creation syscall %s: %v", name, want)
			}
		}
	}
}

func TestL8D7NativeEnvelopeLockIsExactNamedNativeStartCatalog(t *testing.T) {
	root := repositoryRoot(t)
	encoded, err := os.ReadFile(filepath.Join(root, policyDir, "roles-v1.yaml"))
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	document, err := decodeRoles(encoded)
	if err != nil {
		t.Fatalf("decodeRoles() error = %v", err)
	}
	want := exactNativeEnvelope()
	if !equalStringSlices(document.NativeEnvelope, want) {
		t.Fatalf("nativeEnvelope = %v, want %v", document.NativeEnvelope, want)
	}
	if len(want) != 12 || want[0] != "getuid" || want[6] != "socket" || want[len(want)-1] != "exit_group" {
		t.Fatalf("exactNativeEnvelope() = %v", want)
	}
	for _, name := range []string{"clone", "clone3", "execve", "seccomp"} {
		for _, got := range want {
			if got == name {
				t.Fatalf("exactNativeEnvelope() includes forbidden syscall %s: %v", name, want)
			}
		}
	}
}

func TestL8D7RolesDecoderRequiresExactOrderedRoleAndRuleSet(t *testing.T) {
	root := repositoryRoot(t)
	valid, err := os.ReadFile(filepath.Join(root, policyDir, "roles-v1.yaml"))
	if err != nil {
		t.Fatalf("read roles: %v", err)
	}
	document, err := decodeRoles(valid)
	if err != nil {
		t.Fatalf("decodeRoles(valid) error = %v", err)
	}
	mutations := map[string]func(*rolesDocument){
		"changed schema":      func(input *rolesDocument) { input.Schema = "hal-l8-policy-roles-v2" },
		"misnamed role":       func(input *rolesDocument) { input.Roles[0].Name = "renamed" },
		"duplicate role name": func(input *rolesDocument) { input.Roles[1].Name = input.Roles[0].Name },
		"duplicate role ID":   func(input *rolesDocument) { input.Roles[1].ID = input.Roles[0].ID },
		"reordered roles":     func(input *rolesDocument) { input.Roles[0], input.Roles[1] = input.Roles[1], input.Roles[0] },
		"extra role":          func(input *rolesDocument) { input.Roles = append(input.Roles, input.Roles[len(input.Roles)-1]) },
		"missing role":        func(input *rolesDocument) { input.Roles = input.Roles[:len(input.Roles)-1] },
		"changed rule":        func(input *rolesDocument) { input.Roles[3].Syscall = "write" },
		"changed path":        func(input *rolesDocument) { input.Roles[3].Path = 2 },
		"changed envelope":    func(input *rolesDocument) { input.RuntimeEnvelope[2] = "clone" },
		"missing envelope": func(input *rolesDocument) {
			input.RuntimeEnvelope = input.RuntimeEnvelope[:len(input.RuntimeEnvelope)-1]
		},
		"changed native envelope": func(input *rolesDocument) { input.NativeEnvelope[0] = "clone3" },
		"missing native envelope": func(input *rolesDocument) {
			input.NativeEnvelope = input.NativeEnvelope[:len(input.NativeEnvelope)-1]
		},
		"changed callsite": func(input *rolesDocument) { input.PinnedCallsite.Symbol = "internal/runtime/syscall.Other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := document
			candidate.Roles = append([]roleInput(nil), document.Roles...)
			candidate.RuntimeEnvelope = append([]string(nil), document.RuntimeEnvelope...)
			candidate.NativeEnvelope = append([]string(nil), document.NativeEnvelope...)
			mutate(&candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatalf("marshal mutation: %v", err)
			}
			if _, err := decodeRoles(encoded); err == nil {
				t.Fatal("noncanonical roles document was accepted")
			}
		})
	}
}

func TestL8D7CheckGenerationRejectsMutatedRepositoryLocks(t *testing.T) {
	root := repositoryRoot(t)
	for _, test := range []struct {
		name     string
		lockName string
		oldValue string
		newValue string
	}{
		{name: "workload unknown key", lockName: "workload-v1.lock", oldValue: "format=hal-l8-workload-lock-v1", newValue: "unknown=value"},
		{name: "runtime format", lockName: "runtime-go1.25.7.lock", oldValue: "hal-l8-runtime-lock-v1", newValue: "hal-l8-runtime-lock-v2"},
		{name: "runtime toolchain module", lockName: "runtime-go1.25.7.lock", oldValue: "go1.25.7.linux-amd64", newValue: "go1.25.8.linux-amd64"},
		{name: "catalog missing key", lockName: "catalog-xsys-v0.41.0.lock", oldValue: "kernel_ceiling=450\n", newValue: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporaryRoot := t.TempDir()
			temporaryPolicyDir := filepath.Join(temporaryRoot, policyDir)
			if err := os.MkdirAll(temporaryPolicyDir, 0o755); err != nil {
				t.Fatalf("create temporary policy directory: %v", err)
			}
			for _, name := range []string{"roles-v1.yaml", "workload-v1.lock", "runtime-go1.25.7.lock", "catalog-xsys-v0.41.0.lock"} {
				encoded, err := os.ReadFile(filepath.Join(root, policyDir, name))
				if err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				if name == test.lockName {
					encoded = bytes.Replace(encoded, []byte(test.oldValue), []byte(test.newValue), 1)
				}
				if err := os.WriteFile(filepath.Join(temporaryPolicyDir, name), encoded, 0o600); err != nil {
					t.Fatalf("write temporary %s: %v", name, err)
				}
			}
			if _, err := generate(temporaryRoot); err == nil {
				t.Fatal("check generation accepted a mutated repository lock")
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
