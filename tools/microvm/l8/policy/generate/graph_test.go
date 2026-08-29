package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL8D7PinnedDirectAllowIsExactSyscall6Callsite(t *testing.T) {
	binary := inspectedGuestBinary{
		syscall6Found:      true,
		syscall6TextOffset: 12,
		textLength:         16,
		executableText:     append(make([]byte, 12), pinnedSyscallInstruction...),
	}
	pinned := decodedSyscallSite{
		symbol:       pinnedGoRuntimeSymbol,
		symbolOffset: pinnedInstructionOffset,
		textOffset:   12,
		kind:         syscallKindSyscall,
	}
	if !isPinnedDirectSyscall(binary, pinned) {
		t.Fatal("exact Syscall6 0f05 at offset 12 was not pinned-direct")
	}
	for _, site := range []decodedSyscallSite{
		{symbol: "runtime.reviewerAuthority", symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSyscall},
		{symbol: "syscall.reviewerAuthority", symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSyscall},
		{symbol: "golang.org/x/sys/unix.reviewerAuthority", symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSyscall},
		{symbol: "internal/runtime/syscall.reviewerAuthority", symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSyscall},
		{symbol: pinnedGoRuntimeSymbol, symbolOffset: 0, textOffset: 12, kind: syscallKindSyscall},
		{symbol: pinnedGoRuntimeSymbol, symbolOffset: pinnedInstructionOffset, textOffset: 64, kind: syscallKindSyscall},
		{symbol: pinnedGoRuntimeSymbol, symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSysenter},
	} {
		if isPinnedDirectSyscall(binary, site) {
			t.Fatalf("isPinnedDirectSyscall(%+v) = true; namespace or offset membership is not pinned-direct", site)
		}
		if extra := extraReachableSyscallName(binary, site); extra == "" {
			t.Fatalf("extraReachableSyscallName(%+v) treated a non-pinned site as allowed", site)
		}
	}
}

func TestL8D7ReachableGraphDoesNotClassifyByNamespacePrefix(t *testing.T) {
	sources := []string{"elf.go", "evidence.go", "graph.go", "main.go"}
	for _, name := range sources {
		encoded, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(encoded)
		for _, forbidden := range []string{
			"classifiedNonAuthoritySyscallSymbol",
			`strings.HasPrefix(symbol, "runtime.")`,
			`strings.HasPrefix(site.symbol, "runtime.")`,
			`strings.HasPrefix(symbol, "syscall.")`,
			`strings.HasPrefix(symbol, "golang.org/x/sys/unix.")`,
			`strings.HasPrefix(symbol, "internal/runtime/syscall.")`,
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s reintroduced unbounded namespace classification %q", name, forbidden)
			}
		}
	}
}

func TestL8D7ReachableGraphIncludesEveryRelativeBranchTarget(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		want uint64
	}{
		{name: "near conditional", code: []byte{0x0f, 0x85, 0x04, 0, 0, 0}, want: 0x100a},
		{name: "short conditional", code: []byte{0x75, 0x04}, want: 0x1006},
		{name: "loop", code: []byte{0xe2, 0x04}, want: 0x1006},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := executableFunction{name: goRoleEntrySymbol, start: 0x1000, end: 0x1000 + uint64(len(test.code))}
			_, targets, _, err := decodeFunctionSyscallGraph(fn, test.code, 0)
			if err != nil {
				t.Fatalf("decode relative branch: %v", err)
			}
			if len(targets) != 1 || targets[0] != test.want {
				t.Fatalf("relative branch targets = %#x, want [%#x]", targets, test.want)
			}
		})
	}
}

func TestL8D7ReachableGraphRejectsTruncatedControlTransfers(t *testing.T) {
	for _, code := range [][]byte{{0xe8}, {0xe9}, {0xeb}, {0x75}} {
		fn := executableFunction{name: goRoleEntrySymbol, start: 0x1000, end: 0x1000 + uint64(len(code))}
		if _, _, _, err := decodeFunctionSyscallGraph(fn, code, 0); err == nil {
			t.Fatalf("truncated control transfer %x was accepted as harmless padding", code)
		}
	}
}

func TestL8D7ReachableGraphRejectsAmbiguousEntrySymbols(t *testing.T) {
	functions := []executableFunction{
		{name: goRoleEntrySymbol, start: 0x1000, end: 0x1100},
		{name: goRoleEntrySymbol, start: 0x2000, end: 0x2010},
	}
	if _, err := lookupExecutableFunction(functions, goRoleEntrySymbol); err == nil {
		t.Fatal("duplicate entry symbol was accepted by size preference")
	}
}

func TestL8D7ReachableGraphKeepsPclntabSpansAuthoritative(t *testing.T) {
	primary := executableFunction{name: goRoleEntrySymbol, start: 0x1000, end: 0x1100}
	merged, err := mergeExecutableFunctions([]executableFunction{primary}, []executableFunction{
		{name: "reviewer.alias", start: 0x1000, end: 0x1010},
	})
	if err != nil {
		t.Fatalf("merge executable functions: %v", err)
	}
	got, err := lookupExecutableFunction(merged, goRoleEntrySymbol)
	if err != nil || got != primary {
		t.Fatalf("authoritative pclntab entry was shadowed: got %+v, err %v", got, err)
	}
}

func TestL8D7ReachableGraphNamesNativeStartSyscalls(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native ELF assemble/link requires linux/amd64 as/ld")
	}
	root := repositoryRoot(t)
	out := t.TempDir()
	build := exec.Command("bash", filepath.Join(root, "tools/microvm/l8/role-bootstrap/build.sh"), out)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native bootstrap: %v\n%s", err, output)
	}
	inspected, err := inspectLinuxAMD64ELF(guestBootstrapBinaryName, filepath.Join(out, guestBootstrapBinaryName))
	if err != nil {
		t.Fatalf("inspect native bootstrap: %v", err)
	}
	if inspected.graphErr != nil {
		t.Fatalf("native reachable graph error = %v", inspected.graphErr)
	}
	if inspected.entry != nativeBootstrapSymbol {
		t.Fatalf("native entry = %q, want %s", inspected.entry, nativeBootstrapSymbol)
	}
	if len(inspected.reachableFunctions) != 1 || inspected.reachableFunctions[0] != nativeBootstrapSymbol {
		if !containsString(inspected.reachableFunctions, nativeBootstrapSymbol) {
			t.Fatalf("native reachable functions = %v, want %s", inspected.reachableFunctions, nativeBootstrapSymbol)
		}
	}
	got := extraReachableSyscallNames(inspected)
	want := []string{"bind", "capget", "close", "dup3", "exit_group", "getegid", "geteuid", "getgid", "getuid", "listen", "prlimit64", "socket"}
	if len(inspected.reachableSyscalls) < nativeBootstrapSyscallCount {
		t.Fatalf("native reachable syscalls = %d (%v), lost shared identity preflight sites", len(inspected.reachableSyscalls), got)
	}
	if len(inspected.reachableSyscalls) != len(want) {
		t.Fatalf("native reachable syscalls = %d (%v), want %d %v", len(inspected.reachableSyscalls), got, len(want), want)
	}
	for _, site := range inspected.reachableSyscalls {
		if site.symbol != nativeBootstrapSymbol || !site.numberKnown {
			t.Fatalf("native reachable syscall %+v is not a named _start site", site)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("native extra syscalls = %v, want %v", got, want)
	}
	for _, live := range []string{"clone3", "execve", "seccomp", "sendmsg", "recvmsg"} {
		if strings.Contains(strings.Join(got, ","), live) {
			t.Fatalf("native extra syscalls = %v claimed unimplemented live syscall %s", got, live)
		}
	}
	if err := proveBoundedReachableSyscallGraph([]inspectedGuestBinary{inspected}); err == nil {
		t.Fatal("native bootstrap graph issued pinned-direct authority")
	} else if !strings.Contains(err.Error(), "reachable extra syscalls from "+nativeBootstrapSymbol+":") || !strings.Contains(err.Error(), "exit_group") {
		t.Fatalf("native graph error = %v, want named extras from _start", err)
	}
}

func TestL8D7ReachableGraphNamesGoLaunchBaseExtraSyscalls(t *testing.T) {
	root := repositoryRoot(t)
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("launch-base graph requires linux/amd64 Go 1.25.7")
	}
	dir := t.TempDir()
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", filepath.Join(dir, guestInitBinaryName), "./cmd/hal-guest-init")
	command.Dir = root
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=go1.25.7", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", guestInitBinaryName, err, output)
	}
	inspected, err := inspectLinuxAMD64ELF(guestInitBinaryName, filepath.Join(dir, guestInitBinaryName))
	if err != nil {
		t.Fatalf("inspect launch-base: %v", err)
	}
	if inspected.graphErr != nil {
		t.Fatalf("launch-base reachable graph error = %v", inspected.graphErr)
	}
	if inspected.entry != goRoleEntrySymbol {
		t.Fatalf("launch-base entry = %q, want %s", inspected.entry, goRoleEntrySymbol)
	}
	if !inspected.syscall6Found {
		t.Fatal("launch-base is missing pinned Syscall6")
	}
	pinned := 0
	for _, site := range inspected.reachableSyscalls {
		if isPinnedDirectSyscall(inspected, site) {
			pinned++
		}
	}
	if pinned != 1 {
		t.Fatalf("launch-base reachable pinned-direct sites = %d, want 1", pinned)
	}
	extras := extraReachableSyscallNames(inspected)
	if len(extras) == 0 {
		t.Fatal("launch-base reachable extra syscalls were empty; HL8E must not be issued without a named fail-closed reason")
	}
	for _, name := range exactRuntimeEnvelope() {
		if containsString(extras, name) {
			t.Fatalf("launch-base extras = %v include catalog-listed runtime envelope syscall %s", extras, name)
		}
	}
	for _, name := range []string{"unknown:syscall.rawSyscallNoError.abi0", "unknown:syscall.rawVforkSyscall.abi0"} {
		if !containsString(extras, name) {
			t.Fatalf("launch-base extras = %v, want unknown trampoline %s", extras, name)
		}
	}
	if err := proveBoundedReachableSyscallGraph([]inspectedGuestBinary{inspected}); err == nil {
		t.Fatal("launch-base graph with extra reachable syscalls was accepted")
	} else if !strings.Contains(err.Error(), "reachable extra syscalls from "+goRoleEntrySymbol+":") || !strings.Contains(err.Error(), "unknown:syscall.rawVforkSyscall.abi0") {
		t.Fatalf("launch-base graph error = %v, want unknown trampoline extras from %s", err, goRoleEntrySymbol)
	}
}

func TestL8D7RuntimeEnvelopeCatalogClassifiesNamedSyscallsWithoutPrefixAuthority(t *testing.T) {
	binary := inspectedGuestBinary{
		name:               guestInitBinaryName,
		entry:              goRoleEntrySymbol,
		syscall6Found:      true,
		syscall6TextOffset: 12,
		textLength:         80,
		executableText:     append(append(make([]byte, 12), pinnedSyscallInstruction...), make([]byte, 66)...),
	}
	pinned := decodedSyscallSite{
		symbol:       pinnedGoRuntimeSymbol,
		symbolOffset: pinnedInstructionOffset,
		textOffset:   12,
		kind:         syscallKindSyscall,
	}
	listed := decodedSyscallSite{symbol: "runtime.futex", textOffset: 32, kind: syscallKindSyscall, numberKnown: true, number: 202}
	unlisted := decodedSyscallSite{symbol: "runtime.reviewerAuthority", textOffset: 48, kind: syscallKindSyscall, numberKnown: true, number: 56}
	trampoline := decodedSyscallSite{symbol: "syscall.rawSyscallNoError.abi0", textOffset: 64, kind: syscallKindSyscall}
	if extra := extraReachableSyscallName(binary, pinned); extra != "" {
		t.Fatalf("pinned-direct extra = %q", extra)
	}
	if extra := extraReachableSyscallName(binary, listed); extra != "" {
		t.Fatalf("catalog-listed named syscall treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, unlisted); extra != "clone" {
		t.Fatalf("unlisted named syscall extra = %q, want clone", extra)
	}
	if extra := extraReachableSyscallName(binary, trampoline); extra != "unknown:syscall.rawSyscallNoError.abi0" {
		t.Fatalf("unknown trampoline extra = %q", extra)
	}
	generic := binary
	generic.name = "inspect-graph"
	if extra := extraReachableSyscallName(generic, listed); extra != "futex" {
		t.Fatalf("generic binary catalog-listed extra = %q, want futex because prefix/role union is empty", extra)
	}
	binary.reachableSyscalls = []decodedSyscallSite{pinned, listed, unlisted, trampoline}
	binary.extraSyscalls = []decodedSyscallSite{listed, unlisted, trampoline}
	got := extraReachableSyscallNames(binary)
	want := []string{"clone", "unknown:syscall.rawSyscallNoError.abi0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("launch-base extras = %v, want %v", got, want)
	}
}

func TestL8D7ReachableGraphRejectsPrefixOnlyNonAuthority(t *testing.T) {
	binary := inspectedGuestBinary{
		name:               guestInitBinaryName,
		entry:              goRoleEntrySymbol,
		syscall6Found:      true,
		syscall6TextOffset: 12,
		textLength:         80,
		executableText:     append(append(make([]byte, 12), pinnedSyscallInstruction...), make([]byte, 66)...),
		reachableSyscalls: []decodedSyscallSite{
			{symbol: pinnedGoRuntimeSymbol, symbolOffset: pinnedInstructionOffset, textOffset: 12, kind: syscallKindSyscall},
			{symbol: "runtime.reviewerAuthority", symbolOffset: 0, textOffset: 64, kind: syscallKindSyscall, numberKnown: true, number: 56},
		},
	}
	binary.extraSyscalls = binary.reachableSyscalls[1:]
	err := proveBoundedReachableSyscallGraph([]inspectedGuestBinary{binary})
	if err == nil {
		t.Fatal("reachable extra runtime.reviewerAuthority clone was accepted because of its namespace")
	}
	if !strings.Contains(err.Error(), "clone") {
		t.Fatalf("prefix-rejection error = %v, want named extra syscall clone", err)
	}
}

func TestL8D7GenericGoBinaryKeepsSingularEvidenceRejection(t *testing.T) {
	root := repositoryRoot(t)
	binaryPath := buildLinuxAMD64GoBinary(t, t.TempDir(), "inspect-graph", linuxAMD64Syscall6Source())
	inspected, err := inspectLinuxAMD64ELF(filepath.Base(binaryPath), binaryPath)
	if err != nil {
		t.Fatalf("inspectLinuxAMD64ELF() error = %v", err)
	}
	if inspected.graphErr != nil {
		t.Fatalf("generic Go reachable graph error = %v", inspected.graphErr)
	}
	if inspected.entry != goRoleEntrySymbol {
		t.Fatalf("generic Go entry = %q, want %s", inspected.entry, goRoleEntrySymbol)
	}
	if len(extraReachableSyscallNames(inspected)) == 0 {
		t.Fatal("generic Go runtime unexpectedly had no extra reachable syscalls from main.main")
	}
	if _, err := generateEvidence(root, binaryPath, mustGenerate(t, root)); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence(generic Go binary) error = %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
