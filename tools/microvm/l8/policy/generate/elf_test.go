package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL8D7FinalBinaryInspectorLocatesPinnedSyscall6(t *testing.T) {
	root := repositoryRoot(t)
	binaryPath := buildLinuxAMD64GoBinary(t, t.TempDir(), "inspect-syscall6", linuxAMD64Syscall6Source())
	inspected, err := inspectLinuxAMD64ELF(filepath.Base(binaryPath), binaryPath)
	if err != nil {
		t.Fatalf("inspectLinuxAMD64ELF() error = %v", err)
	}
	if inspected.native || !inspected.hasGoRuntime || inspected.goPath != "command-line-arguments" || inspected.goVersion != requiredGoToolchainVersion {
		t.Fatalf("generic Go binary identity = native:%v runtime:%v path:%q version:%q", inspected.native, inspected.hasGoRuntime, inspected.goPath, inspected.goVersion)
	}
	if inspected.binarySHA256 == ([32]byte{}) || inspected.executableTextSHA256 == ([32]byte{}) || inspected.textLength == 0 {
		t.Fatal("inspector returned zero binary or executable-text identity")
	}
	if !inspected.syscall6Found || !bytes.Equal(inspected.instruction, pinnedSyscallInstruction) {
		t.Fatalf("pinned callsite = found:%v insn:%s", inspected.syscall6Found, hex.EncodeToString(inspected.instruction))
	}
	end := inspected.syscall6TextOffset + uint64(len(pinnedSyscallInstruction))
	if end > inspected.textLength || !bytes.Equal(inspected.executableText[inspected.syscall6TextOffset:end], pinnedSyscallInstruction) {
		t.Fatal("executable text does not contain source-derived 0f05 at the pinned Syscall6 offset")
	}
	if countInstruction(inspected.executableText, pinnedSyscallInstruction) < 2 {
		t.Fatal("generic Go runtime unexpectedly has a unique syscall instruction")
	}
	if _, err := generateEvidence(root, binaryPath, mustGenerate(t, root)); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence(generic Go binary) error = %v", err)
	}
}

func TestL8D7EvidenceIssuanceRejectsMissingRoleBinariesDir(t *testing.T) {
	root := repositoryRoot(t)
	outputs := mustGenerate(t, root)
	_, err := generateEvidenceFromInputs(root, evidenceInputs{binariesDir: t.TempDir()}, outputs)
	if !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidenceFromInputs(empty dir) error = %v", err)
	}
	if !strings.Contains(err.Error(), "missing role binary "+guestInitBinaryName) {
		t.Fatalf("missing-role error = %v, want missing %s", err, guestInitBinaryName)
	}
}

func TestL8D7EvidenceIssuanceRejectsIncompleteBinariesDirMissingHelper(t *testing.T) {
	root := repositoryRoot(t)
	outputs := mustGenerate(t, root)
	dir := t.TempDir()
	binaryPath := buildLinuxAMD64GoBinary(t, dir, "partial-src", linuxAMD64Syscall6Source())
	for _, name := range []string{guestInitBinaryName, guestAgentBinaryName} {
		if err := copyFileOverwrite(t, binaryPath, filepath.Join(dir, name)); err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
	}
	_, err := generateEvidenceFromInputs(root, evidenceInputs{binariesDir: dir}, outputs)
	if !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidenceFromInputs(missing helper) error = %v", err)
	}
	if !strings.Contains(err.Error(), "missing role binary") && !strings.Contains(err.Error(), "is not "+guestInitPackagePath) {
		t.Fatalf("incomplete helper error = %v, want missing-role or identity fail-closed", err)
	}
}

func TestL8D7EvidenceIssuanceRejectsUnrelatedBinariesDirWithRoleFilenames(t *testing.T) {
	root := repositoryRoot(t)
	outputs := mustGenerate(t, root)
	dir := t.TempDir()
	binaryPath := buildLinuxAMD64GoBinary(t, dir, "unrelated-role-names", linuxAMD64Syscall6Source())
	for _, role := range requiredGuestRoleBinaries() {
		if err := copyFileOverwrite(t, binaryPath, filepath.Join(dir, role.name)); err != nil {
			t.Fatalf("stage %s: %v", role.name, err)
		}
	}
	_, err := generateEvidenceFromInputs(root, evidenceInputs{binariesDir: dir}, outputs)
	if !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidenceFromInputs(unrelated complete names) error = %v", err)
	}
	if !strings.Contains(err.Error(), "is not "+guestInitPackagePath) && !strings.Contains(err.Error(), "native bootstrap identity") {
		t.Fatalf("unrelated binaries-dir error = %v, want role identity fail-closed", err)
	}
}

func TestL8D7FinalBinaryInspectorRejectsNativeGoConfusion(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native ELF assemble/link requires linux/amd64 as/ld")
	}
	if _, err := exec.LookPath("as"); err != nil {
		t.Fatalf("as is required to prove native identity: %v", err)
	}
	if _, err := exec.LookPath("ld"); err != nil {
		t.Fatalf("ld is required to prove native identity: %v", err)
	}
	root := repositoryRoot(t)
	out := t.TempDir()
	build := exec.Command("bash", filepath.Join(root, "tools/microvm/l8/role-bootstrap/build.sh"), out)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native bootstrap: %v\n%s", err, output)
	}
	nativePath := filepath.Join(out, guestBootstrapBinaryName)
	inspected, err := inspectLinuxAMD64ELF(guestBootstrapBinaryName, nativePath)
	if err != nil {
		t.Fatalf("inspect native bootstrap: %v", err)
	}
	if !inspected.native || inspected.hasGoRuntime || inspected.syscall6Found || inspected.goPath != "" {
		t.Fatalf("native identity = %#v", inspected)
	}
	goBinary := buildLinuxAMD64GoBinary(t, t.TempDir(), "not-native", linuxAMD64Syscall6Source())
	goInspected, err := inspectLinuxAMD64ELF(guestBootstrapBinaryName, goBinary)
	if err != nil {
		t.Fatalf("inspect Go binary as bootstrap name: %v", err)
	}
	if err := matchRequiredGuestRoleIdentity(requiredGuestRoleBinary{name: guestBootstrapBinaryName, native: true}, goInspected); err == nil {
		t.Fatal("Go runtime binary was accepted as native bootstrap identity")
	}
}

func TestL8D7EvidenceIssuanceRejectsMutuallyExclusiveBinaryInputs(t *testing.T) {
	root := repositoryRoot(t)
	outputs := mustGenerate(t, root)
	_, err := generateEvidenceFromInputs(root, evidenceInputs{binaryPath: "one", binariesDir: "two"}, outputs)
	if !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("mutually exclusive inputs error = %v", err)
	}
}

func mustGenerate(t *testing.T, root string) generatedOutputs {
	t.Helper()
	outputs, err := generate(root)
	if err != nil {
		t.Fatalf("generate artifact: %v", err)
	}
	return outputs
}

func linuxAMD64Syscall6Source() string {
	return `package main

import (
	"os"
	"syscall"
)

func main() {
	_, _, _ = syscall.Syscall6(syscall.SYS_READ, ^uintptr(0), 0, 0, 0, 0, 0)
	os.Exit(0)
}
`
}

func buildLinuxAMD64GoBinary(t *testing.T, dir, name, source string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, name+".go")
	binaryPath := filepath.Join(dir, name)
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatalf("write %s source: %v", name, err)
	}
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", binaryPath, sourcePath)
	command.Dir = repositoryRoot(t)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=go1.25.7", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return binaryPath
}

func copyFileOverwrite(t *testing.T, source, destination string) error {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, encoded, 0o755)
}
