package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestL8D7PointerTakenPID1Report(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64")
	}
	root := repositoryRoot(t)
	dir := t.TempDir()
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-tags="+l8ProductionPID1Tag, "-o", filepath.Join(dir, guestInitBinaryName), "./cmd/hal-guest-init")
	command.Dir = root
	command.Env = linuxAMD64GoBuildEnv(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	path := filepath.Join(dir, guestInitBinaryName)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.NewFile(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	inspected, err := inspectLinuxAMD64ELF(guestInitBinaryName, path)
	if err != nil {
		t.Fatal(err)
	}
	functions, err := listExecutableFunctions(file, inspected.hasGoRuntime)
	if err != nil {
		t.Fatal(err)
	}
	taken := collectPointerTakenFunctionTargets(file, encoded, functions)
	t.Logf("functions=%d pointerTaken=%d reachable=%d unbounded=%v extras=%v graphErr=%v", len(functions), len(taken), len(inspected.reachableFunctions), inspected.unboundedIndirect, extraReachableSyscallNames(inspected), inspected.graphErr)
	if inspected.graphErr != nil {
		t.Fatalf("PID1 graph: %v", inspected.graphErr)
	}
	if len(taken) == 0 {
		t.Fatal("PID1 pointer-taken start set was empty")
	}
	if !inspected.unboundedIndirect {
		t.Fatal("PID1 static pointer inventory was treated as a complete register-indirect target proof")
	}
	if extras := extraReachableSyscallNames(inspected); len(extras) != 0 {
		t.Fatalf("PID1 extras = %v, want empty", extras)
	}
	if _, err := generateEvidence(root, path, mustGenerate(t, root)); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence(PID1) error = %v, want fail-closed HL8E", err)
	}
}

func TestL8D7CompleteGuestRoleGraphsRemainUnboundedWithoutPointsToProof(t *testing.T) {
	root := repositoryRoot(t)
	dir := buildCompleteGuestRoleBinariesDir(t, root)
	binaries, err := inspectGuestRoleBinariesDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unbounded := 0
	for _, binary := range binaries {
		extras := extraReachableSyscallNames(binary)
		t.Logf("%s native=%v unbounded=%v extras=%v graphErr=%v", binary.name, binary.native, binary.unboundedIndirect, extras, binary.graphErr)
		if binary.graphErr != nil {
			t.Errorf("%s graph: %v", binary.name, binary.graphErr)
		}
		if binary.unboundedIndirect {
			unbounded++
		}
		if len(extras) != 0 {
			t.Errorf("%s extras = %v, want empty", binary.name, extras)
		}
	}
	if unbounded == 0 {
		t.Fatal("complete guest role set claimed no reachable unbounded indirect")
	}
	if err := proveBoundedReachableSyscallGraph(binaries); err == nil {
		t.Fatal("proveBounded accepted an incomplete register-indirect target proof")
	}
	if err := requireCompleteHonestIssuanceInputs(binaries); err == nil {
		t.Fatal("requireCompleteHonestIssuanceInputs accepted an incomplete register-indirect target proof")
	}
}

func TestL8D7PointerTakenScanSkipsExecutableAndPclntab(t *testing.T) {
	hasher := executableFunction{name: "runtime.aeshashbody", start: 0x401000, end: 0x401100}
	vfork := executableFunction{name: syscallRawVforkSyscallABI0, start: 0x402000, end: 0x402100}
	interior := executableFunction{name: "runtime.duffcopy", start: 0x403000, end: 0x403100}
	encoded := make([]byte, 64)
	binary.LittleEndian.PutUint64(encoded[0:8], hasher.start)
	binary.LittleEndian.PutUint64(encoded[8:16], vfork.start)
	binary.LittleEndian.PutUint64(encoded[16:24], interior.start+0x10)
	binary.LittleEndian.PutUint64(encoded[32:40], hasher.start)
	noptr := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:     ".noptrdata",
		Offset:   0,
		FileSize: 8,
	}}
	pclntab := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:     ".gopclntab",
		Offset:   8,
		FileSize: 16,
	}}
	rodata := &elf.Section{SectionHeader: elf.SectionHeader{
		Name:     ".rodata",
		Offset:   32,
		FileSize: 8,
	}}
	file := &elf.File{Sections: []*elf.Section{noptr, pclntab, rodata}}
	got := collectPointerTakenFunctionTargets(file, encoded, []executableFunction{hasher, vfork, interior})
	if len(got) != 1 || got[0] != hasher.start {
		t.Fatalf("pointer-taken starts = %v, want only hasher start from .noptrdata", got)
	}
}
