package main

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL8D7NativeIdentityGenerationIsDeterministicAndMatchesCheckedInOutput(t *testing.T) {
	root := repositoryRoot(t)
	first, err := generate(root)
	if err != nil {
		t.Fatalf("generate first copy: %v", err)
	}
	second, err := generate(root)
	if err != nil {
		t.Fatalf("generate second copy: %v", err)
	}
	if !bytes.Equal(first.source, second.source) {
		t.Fatal("identical native inputs produced different generated identities")
	}
	if first.policySHA256 == ([32]byte{}) || first.sourceSHA256 == ([32]byte{}) || first.callsiteSHA256 == ([32]byte{}) || first.installTableSHA256 == ([32]byte{}) {
		t.Fatal("generated native identities include a zero digest")
	}
	if first.policySHA256 != second.policySHA256 || first.sourceSHA256 != second.sourceSHA256 || first.callsiteSHA256 != second.callsiteSHA256 || first.installTableSHA256 != second.installTableSHA256 {
		t.Fatal("identical native inputs produced different digest fields")
	}
	got, err := os.ReadFile(filepath.Join(root, generatedArtifactRel))
	if err != nil {
		t.Fatalf("read checked-in generated artifact: %v", err)
	}
	if !bytes.Equal(got, first.source) {
		t.Fatal("checked-in generated native artifact is stale")
	}
}

func TestL8D7NativeIdentitiesHashIssuedPolicySourceCallsiteAndInstallTable(t *testing.T) {
	root := repositoryRoot(t)
	identities, err := generate(root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	policy, err := readDigestFile(filepath.Join(root, policyDigestRel))
	if err != nil {
		t.Fatalf("issued policy digest: %v", err)
	}
	if identities.policySHA256 != policy {
		t.Fatal("native policy digest is not the already-issued HL8Q identity")
	}
	sourceBytes, err := os.ReadFile(filepath.Join(root, nativeSourceRel))
	if err != nil {
		t.Fatalf("read native source: %v", err)
	}
	if identities.sourceSHA256 != framedSHA256(sourceDomain, encodeNativeSourcePreimage(nativeSourceRel, sourceBytes)) {
		t.Fatal("native source digest does not match hashed source bytes")
	}
	callsiteBytes, err := os.ReadFile(filepath.Join(root, nativeCallsitesRel))
	if err != nil {
		t.Fatalf("read callsite inventory: %v", err)
	}
	if identities.callsiteSHA256 != framedSHA256(callsiteDomain, callsiteBytes) {
		t.Fatal("native callsite digest does not match hashed inventory bytes")
	}
	if identities.installTableSHA256 != nativeInstallTableSHA256() {
		t.Fatal("native install-table digest does not match the D4 binding table")
	}
	if hex.EncodeToString(identities.installTableSHA256[:]) != "3e70095d1e38da90824f30464c20aaff01e199ce2d3808ac50096fd131286a74" {
		t.Fatalf("install-table digest = %x, want the issued D4 native install table", identities.installTableSHA256)
	}
}

func TestL8D7NativeRoleBootstrapELFIsFreestandingStaticExec(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native ELF assemble/link requires linux/amd64 as/ld")
	}
	if _, err := exec.LookPath("as"); err != nil {
		t.Fatalf("as is required to prove the native ELF: %v", err)
	}
	if _, err := exec.LookPath("ld"); err != nil {
		t.Fatalf("ld is required to prove the native ELF: %v", err)
	}
	root := repositoryRoot(t)
	out := t.TempDir()
	build := exec.Command("bash", filepath.Join(root, "tools/microvm/l8/role-bootstrap/build.sh"), out)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build.sh: %v\n%s", err, output)
	}
	binary := filepath.Join(out, "hal-guest-role-bootstrap")
	file, err := elf.Open(binary)
	if err != nil {
		t.Fatalf("open ELF: %v", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC {
		t.Fatalf("ELF class/machine/type = %v/%v/%v, want ELF64/x86-64/ET_EXEC", file.Class, file.Machine, file.Type)
	}
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_INTERP {
			t.Fatal("native ELF contains PT_INTERP")
		}
	}
	if sec := file.Section(".interp"); sec != nil && sec.Size > 0 {
		t.Fatal("native ELF contains .interp")
	}
	if needed, err := file.DynString(elf.DT_NEEDED); err == nil {
		for _, name := range needed {
			if name != "" {
				t.Fatalf("native ELF NEEDED %q", name)
			}
		}
	}
	for _, section := range []string{".gopclntab", ".go.buildinfo"} {
		if file.Section(section) != nil {
			t.Fatalf("native ELF contains Go runtime section %s", section)
		}
	}
	symbols, err := file.Symbols()
	if err != nil && !strings.Contains(err.Error(), "no symbol section") {
		t.Fatalf("ELF symbols: %v", err)
	}
	hasStart := false
	for _, symbol := range symbols {
		if symbol.Name == "_start" {
			hasStart = true
		}
		if strings.Contains(symbol.Name, "runtime.") || symbol.Name == "main.main" || strings.Contains(symbol.Name, "libc") {
			t.Fatalf("native ELF contains forbidden symbol %q", symbol.Name)
		}
	}
	if !hasStart {
		t.Fatal("native ELF is missing _start")
	}
	payload, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("read ELF: %v", err)
	}
	for _, marker := range []string{"runtime.main", "Go build ID", "/lib64/ld-linux"} {
		if bytes.Contains(payload, []byte(marker)) {
			t.Fatalf("native ELF contains forbidden marker %q", marker)
		}
	}

	for _, args := range [][]string{nil, {"agent"}, {"not-a-role"}} {
		command := exec.Command(binary, args...)
		err := command.Run()
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 127 {
			t.Fatalf("native ELF args %v exit = %v, want 127", args, err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %s is missing go.mod: %v", root, err)
	}
	return root
}
