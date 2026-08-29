package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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

func TestL8D7FinalBinaryInspectorRejectsPinnedInstructionOutsideSymbol(t *testing.T) {
	binaryPath := buildLinuxAMD64GoBinary(t, t.TempDir(), "short-syscall6", linuxAMD64Syscall6Source())
	encoded, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read test ELF: %v", err)
	}
	for _, symbolSize := range []uint64{0, pinnedInstructionOffset + uint64(len(pinnedSyscallInstruction)) - 1} {
		t.Run(fmt.Sprintf("size_%d", symbolSize), func(t *testing.T) {
			mutated := append([]byte(nil), encoded...)
			if err := setELFSymbolSize(mutated, pinnedGoRuntimeSymbol, symbolSize); err != nil {
				t.Fatalf("set symbol size: %v", err)
			}
			mutatedPath := filepath.Join(t.TempDir(), "short-syscall6")
			if err := os.WriteFile(mutatedPath, mutated, 0o755); err != nil {
				t.Fatalf("write mutated ELF: %v", err)
			}
			if _, err := inspectLinuxAMD64ELF(filepath.Base(mutatedPath), mutatedPath); err == nil {
				t.Fatal("inspector accepted an instruction extending beyond the declared Syscall6 symbol")
			}
		})
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

func TestL8D7EvidenceIssuanceRejectsCompleteRolesWithoutBoundedCallGraph(t *testing.T) {
	root := repositoryRoot(t)
	outputs := mustGenerate(t, root)
	dir := buildCompleteGuestRoleBinariesDir(t, root)
	evidence, err := generateEvidenceFromInputs(root, evidenceInputs{binariesDir: dir}, outputs)
	if !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidenceFromInputs(complete guest roles) = (%d bytes, %v), want no evidence/dependency unaccepted", len(evidence.encoded), err)
	}
	if len(evidence.encoded) != 0 || len(evidence.source) != 0 || evidence.sha256 != ([32]byte{}) {
		t.Fatal("complete role filenames and identities issued evidence without a bounded reachable call graph")
	}
	message := err.Error()
	if !strings.Contains(message, "unique/reachable D4/D6 call graph is unavailable") {
		t.Fatalf("complete-role error = %v, want unavailable bounded-call-graph reason", err)
	}
	if !strings.Contains(message, "role binary "+guestInitBinaryName+" has reachable extra syscalls from "+goRoleEntrySymbol+":") {
		t.Fatalf("complete-role error = %v, want launch-base extras from %s", err, goRoleEntrySymbol)
	}
	for _, name := range []string{"unknown:syscall.rawSyscallNoError.abi0", "unknown:syscall.rawVforkSyscall.abi0"} {
		if !strings.Contains(message, name) {
			t.Fatalf("complete-role error = %v, want unknown trampoline %s", err, name)
		}
	}
	for _, name := range []string{"futex", "mmap", "clock_gettime"} {
		if strings.Contains(message, name+",") || strings.Contains(message, name+" ") || strings.HasSuffix(message, name) {
			t.Fatalf("complete-role error = %v leaked catalog-listed runtime envelope syscall %s", err, name)
		}
	}
	if !strings.Contains(message, "role binary "+guestBootstrapBinaryName+" has reachable extra syscalls from "+nativeBootstrapSymbol+":") {
		t.Fatalf("complete-role error = %v, want named native extras from %s", err, nativeBootstrapSymbol)
	}
	for _, name := range []string{"getuid", "exit_group"} {
		if !strings.Contains(message, name) {
			t.Fatalf("complete-role error = %v, want named native extra syscall %s", err, name)
		}
	}
	if strings.Contains(message, "runtime.reviewerAuthority") || strings.Contains(message, "classifiedNonAuthority") {
		t.Fatalf("complete-role error used namespace classification: %v", err)
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

func buildCompleteGuestRoleBinariesDir(t *testing.T, root string) string {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("complete guest role inspection requires linux/amd64 as/ld and Go 1.25.7")
	}
	if _, err := exec.LookPath("as"); err != nil {
		t.Fatalf("as is required to inspect the native bootstrap: %v", err)
	}
	if _, err := exec.LookPath("ld"); err != nil {
		t.Fatalf("ld is required to inspect the native bootstrap: %v", err)
	}
	dir := t.TempDir()
	packages := []struct {
		name string
		pkg  string
	}{
		{guestInitBinaryName, "./cmd/hal-guest-init"},
		{guestAgentBinaryName, "./cmd/hal-guest-agent"},
		{guestHelperBinaryName, "./cmd/hal-guest-credential-helper"},
		{guestMonitorBinaryName, "./cmd/hal-guest-mount-monitor"},
		{guestShimBinaryName, "./cmd/hal-guest-workload-shim"},
	}
	for _, role := range packages {
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", filepath.Join(dir, role.name), role.pkg)
		command.Dir = root
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=go1.25.7", "GOPROXY=off")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", role.name, err, output)
		}
	}
	build := exec.Command("bash", filepath.Join(root, "tools/microvm/l8/role-bootstrap/build.sh"), dir)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native bootstrap: %v\n%s", err, output)
	}
	return dir
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

func setELFSymbolSize(encoded []byte, name string, size uint64) error {
	file, err := elf.NewFile(bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	defer file.Close()
	symbols := file.Section(".symtab")
	if symbols == nil || int(symbols.Link) >= len(file.Sections) || symbols.Entsize != 24 {
		return errors.New("ELF symbol table is unavailable")
	}
	names, err := file.Sections[symbols.Link].Data()
	if err != nil {
		return err
	}
	start := symbols.Offset
	end := start + symbols.Size
	if end < start || end > uint64(len(encoded)) {
		return errors.New("ELF symbol table is outside the file")
	}
	for offset := start + symbols.Entsize; offset+symbols.Entsize <= end; offset += symbols.Entsize {
		nameOffset := uint64(binary.LittleEndian.Uint32(encoded[offset : offset+4]))
		if nameOffset >= uint64(len(names)) {
			continue
		}
		nameEnd := bytes.IndexByte(names[nameOffset:], 0)
		if nameEnd < 0 || string(names[nameOffset:nameOffset+uint64(nameEnd)]) != name {
			continue
		}
		binary.LittleEndian.PutUint64(encoded[offset+16:offset+24], size)
		return nil
	}
	return fmt.Errorf("ELF symbol %s is missing", name)
}
