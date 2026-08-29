package main

import (
	"debug/elf"
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
	sources := []string{"elf.go", "evidence.go", "graph.go", "indirect.go", "main.go"}
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
			_, targets, _, _, err := decodeFunctionSyscallGraph(fn, test.code, 0)
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
		if _, _, _, _, err := decodeFunctionSyscallGraph(fn, code, 0); err == nil {
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
	want := exactNativeEnvelope()
	if len(inspected.reachableSyscalls) < nativeBootstrapSyscallCount {
		t.Fatalf("native reachable syscalls = %d (%v), lost shared identity preflight sites", len(inspected.reachableSyscalls), got)
	}
	if len(inspected.reachableSyscalls) != len(want) {
		t.Fatalf("native reachable syscalls = %d extras=%v, want %d catalog names %v", len(inspected.reachableSyscalls), got, len(want), want)
	}
	seen := make(map[string]struct{}, len(inspected.reachableSyscalls))
	for _, site := range inspected.reachableSyscalls {
		if site.symbol != nativeBootstrapSymbol || !site.numberKnown {
			t.Fatalf("native reachable syscall %+v is not a named _start site", site)
		}
		name := linuxAMD64SyscallName(site.number)
		seen[name] = struct{}{}
		if extraReachableSyscallName(inspected, site) != "" {
			t.Fatalf("catalog-listed native _start syscall %s treated as extra", name)
		}
	}
	for _, name := range want {
		if _, ok := seen[name]; !ok {
			t.Fatalf("native reachable syscalls missing catalog name %s", name)
		}
	}
	if len(got) != 0 {
		t.Fatalf("native extra syscalls = %v, want none after nativeEnvelope catalog bind", got)
	}
	for _, live := range []string{"sendmsg", "recvmsg", "execveat"} {
		if _, ok := seen[live]; ok {
			t.Fatalf("native reachable syscalls claimed unimplemented live syscall %s", live)
		}
		if containsString(got, live) {
			t.Fatalf("native extra syscalls = %v claimed unimplemented live syscall %s", got, live)
		}
	}
	if _, ok := seen["prctl"]; !ok {
		t.Fatal("native reachable syscalls missing prctl")
	}
	if _, ok := seen["seccomp"]; !ok {
		t.Fatal("native reachable syscalls missing seccomp")
	}
	if _, ok := seen["clone3"]; !ok {
		t.Fatal("native reachable syscalls missing clone3")
	}
	if _, ok := seen["execve"]; !ok {
		t.Fatal("native reachable syscalls missing execve")
	}
	if err := proveBoundedReachableSyscallGraph([]inspectedGuestBinary{inspected}); err != nil {
		t.Fatalf("native bootstrap graph after nativeEnvelope bind error = %v", err)
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
	command.Env = linuxAMD64GoBuildEnv(t)
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
		if containsString(extras, name) {
			t.Fatalf("launch-base extras = %v still include unnumbered trampoline %s", extras, name)
		}
	}
	wantExtras := []string{"clone", "clone3"}
	if strings.Join(extras, ",") != strings.Join(wantExtras, ",") {
		t.Fatalf("launch-base extras = %v, want process-creation extras %v", extras, wantExtras)
	}
	if containsString(extras, "getppid") {
		t.Fatalf("launch-base extras = %v still include catalog-listed getppid", extras)
	}
	if err := proveBoundedReachableSyscallGraph([]inspectedGuestBinary{inspected}); err == nil {
		t.Fatal("launch-base graph with extra reachable syscalls was accepted")
	} else if !strings.Contains(err.Error(), "reachable extra syscalls from "+goRoleEntrySymbol+":") || !strings.Contains(err.Error(), "clone") {
		t.Fatalf("launch-base graph error = %v, want named trampoline extras from %s", err, goRoleEntrySymbol)
	}
}

func TestL8D7ProductionPID1OmitsCloneClone3ForkExecExtras(t *testing.T) {
	root := repositoryRoot(t)
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("launch-base graph requires linux/amd64 Go 1.25.7")
	}
	dir := t.TempDir()
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-tags="+l8ProductionPID1Tag, "-o", filepath.Join(dir, guestInitBinaryName), "./cmd/hal-guest-init")
	command.Dir = root
	command.Env = linuxAMD64GoBuildEnv(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build tagged %s: %v\n%s", guestInitBinaryName, err, output)
	}
	inspected, err := inspectLinuxAMD64ELF(guestInitBinaryName, filepath.Join(dir, guestInitBinaryName))
	if err != nil {
		t.Fatalf("inspect L8-tagged PID1: %v", err)
	}
	if inspected.graphErr != nil {
		t.Fatalf("L8-tagged PID1 reachable graph error = %v", inspected.graphErr)
	}
	if inspected.entry != goRoleEntrySymbol {
		t.Fatalf("L8-tagged PID1 entry = %q, want %s", inspected.entry, goRoleEntrySymbol)
	}
	extras := extraReachableSyscallNames(inspected)
	for _, name := range []string{"clone", "clone3"} {
		if containsString(extras, name) {
			t.Fatalf("L8-tagged PID1 extras = %v still include ForkExec syscall %s", extras, name)
		}
	}
	for _, name := range []string{"unknown:syscall.rawSyscallNoError.abi0", "unknown:syscall.rawVforkSyscall.abi0"} {
		if containsString(extras, name) {
			t.Fatalf("L8-tagged PID1 extras = %v still include unnumbered trampoline %s", extras, name)
		}
	}
	if _, err := generateEvidence(root, filepath.Join(dir, guestInitBinaryName), mustGenerate(t, root)); !errors.Is(err, errEvidenceInputsUnavailable) {
		t.Fatalf("generateEvidence(L8-tagged PID1) error = %v, want fail-closed HL8E", err)
	}
	if !containsString(inspected.reachableFunctions, "runtime.duffcopy") || !containsString(inspected.reachableFunctions, "runtime.duffzero") {
		t.Fatalf("L8-tagged PID1 reachable functions = %v, want listed-span interiors duffcopy/duffzero", inspected.reachableFunctions)
	}
	if !inspected.unboundedIndirect {
		t.Fatal("L8-tagged PID1 register-indirect CALL was treated as bounded")
	}
	if extras := extraReachableSyscallNames(inspected); len(extras) != 0 {
		t.Fatalf("L8-tagged PID1 extras = %v, want empty after interior bind", extras)
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
	listedPPID := decodedSyscallSite{symbol: "runtime.getppid", textOffset: 40, kind: syscallKindSyscall, numberKnown: true, number: 110}
	unlisted := decodedSyscallSite{symbol: "runtime.reviewerAuthority", textOffset: 48, kind: syscallKindSyscall, numberKnown: true, number: 56}
	trampoline := decodedSyscallSite{symbol: "syscall.rawSyscallNoError.abi0", textOffset: 64, kind: syscallKindSyscall}
	namedTrampoline := decodedSyscallSite{symbol: "syscall.rawSyscallNoError.abi0", textOffset: 72, kind: syscallKindSyscall, numberKnown: true, number: 39}
	if extra := extraReachableSyscallName(binary, pinned); extra != "" {
		t.Fatalf("pinned-direct extra = %q", extra)
	}
	if extra := extraReachableSyscallName(binary, listed); extra != "" {
		t.Fatalf("catalog-listed named syscall treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, listedPPID); extra != "" {
		t.Fatalf("catalog-listed getppid treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, unlisted); extra != "clone" {
		t.Fatalf("unlisted named syscall extra = %q, want clone", extra)
	}
	if extra := extraReachableSyscallName(binary, trampoline); extra != "unknown:syscall.rawSyscallNoError.abi0" {
		t.Fatalf("unknown trampoline extra = %q", extra)
	}
	if extra := extraReachableSyscallName(binary, namedTrampoline); extra != "" {
		t.Fatalf("catalog-listed trampoline getpid treated as extra: %q", extra)
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

func TestL8D7NativeEnvelopeCatalogClassifiesNamedSyscallsWithoutPrefixAuthority(t *testing.T) {
	binary := inspectedGuestBinary{
		name:   guestBootstrapBinaryName,
		native: true,
		entry:  nativeBootstrapSymbol,
	}
	listed := decodedSyscallSite{symbol: nativeBootstrapSymbol, textOffset: 16, kind: syscallKindSyscall, numberKnown: true, number: 102}
	listen := decodedSyscallSite{symbol: nativeBootstrapSymbol, textOffset: 32, kind: syscallKindSyscall, numberKnown: true, number: 50}
	unlisted := decodedSyscallSite{symbol: "unix.reviewerAuthority", textOffset: 48, kind: syscallKindSyscall, numberKnown: true, number: 56}
	clone3 := decodedSyscallSite{symbol: nativeBootstrapSymbol, textOffset: 64, kind: syscallKindSyscall, numberKnown: true, number: 435}
	execve := decodedSyscallSite{symbol: nativeBootstrapSymbol, textOffset: 72, kind: syscallKindSyscall, numberKnown: true, number: 59}
	unimplemented := decodedSyscallSite{symbol: nativeBootstrapSymbol, textOffset: 80, kind: syscallKindSyscall, numberKnown: true, number: 46}
	if extra := extraReachableSyscallName(binary, listed); extra != "" {
		t.Fatalf("catalog-listed native getuid treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, listen); extra != "" {
		t.Fatalf("catalog-listed native listen treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, unlisted); extra != "clone" {
		t.Fatalf("unlisted named syscall extra = %q, want clone", extra)
	}
	if extra := extraReachableSyscallName(binary, clone3); extra != "" {
		t.Fatalf("catalog-listed native clone3 treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, execve); extra != "" {
		t.Fatalf("catalog-listed native execve treated as extra: %q", extra)
	}
	if extra := extraReachableSyscallName(binary, unimplemented); extra != "sendmsg" {
		t.Fatalf("unimplemented sendmsg extra = %q, want sendmsg", extra)
	}
	goPID1 := inspectedGuestBinary{name: guestInitBinaryName}
	if extra := extraReachableSyscallName(goPID1, listed); extra != "getuid" {
		t.Fatalf("Go PID1 native-envelope getuid extra = %q, want getuid because nativeEnvelope is bootstrap-only", extra)
	}
	generic := inspectedGuestBinary{name: "inspect-graph"}
	if extra := extraReachableSyscallName(generic, listen); extra != "listen" {
		t.Fatalf("generic binary native-envelope extra = %q, want listen because prefix/role union is empty", extra)
	}
	misnamed := inspectedGuestBinary{name: guestBootstrapBinaryName}
	if extra := extraReachableSyscallName(misnamed, listed); extra != "getuid" {
		t.Fatalf("non-native bootstrap filename extra = %q, want getuid because nativeEnvelope requires the native identity", extra)
	}
}

func TestL8D7EnvelopesOmitProcessCreationAndUnimplementedLiveSyscalls(t *testing.T) {
	for _, name := range []string{"clone", "clone3"} {
		if containsString(exactRuntimeEnvelope(), name) {
			t.Fatalf("runtimeEnvelope includes process-creation syscall %s", name)
		}
	}
	if containsString(exactNativeEnvelope(), "clone") {
		t.Fatal("nativeEnvelope includes clone; native PID1 catalogs clone3 only")
	}
	for _, name := range []string{"sendmsg", "recvmsg", "execveat"} {
		if containsString(exactNativeEnvelope(), name) {
			t.Fatalf("nativeEnvelope includes unimplemented live syscall %s", name)
		}
	}
	if !containsString(exactNativeEnvelope(), "prctl") || !containsString(exactNativeEnvelope(), "seccomp") {
		t.Fatal("nativeEnvelope omitted launch-base seccomp install syscalls")
	}
	if !containsString(exactNativeEnvelope(), "clone3") || !containsString(exactNativeEnvelope(), "execve") {
		t.Fatal("nativeEnvelope omitted PID1 clone3 and execve")
	}
	if !containsString(exactRuntimeEnvelope(), "getppid") {
		t.Fatal("runtimeEnvelope omitted ordinary main.main extra getppid")
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

func TestL8D7SyscallTrampolineRecoversTrapSlotImmediateFromDirectCall(t *testing.T) {
	code := []byte{
		0x48, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
		0x44, 0x0f, 0x11, 0x7c, 0x24, 0x08,
		0x48, 0xc7, 0x44, 0x24, 0x18, 0x00, 0x00, 0x00, 0x00,
		0xe8, 0x03, 0x00, 0x00, 0x00,
	}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	_, targets, transfers, _, err := decodeFunctionSyscallGraph(fn, code, 32)
	if err != nil {
		t.Fatalf("decode trampoline caller: %v", err)
	}
	if len(targets) != 1 || len(transfers) != 1 {
		t.Fatalf("trampoline caller transfers = %d targets = %#x", len(transfers), targets)
	}
	if !transfers[0].trapSlotKnown || transfers[0].trapSlot != 39 {
		t.Fatalf("trap-slot immediate = known:%v nr:%d, want 39", transfers[0].trapSlotKnown, transfers[0].trapSlot)
	}
	functions := []executableFunction{
		fn,
		{name: syscallRawSyscallNoErrorABI0, start: transfers[0].target, end: transfers[0].target + 16},
	}
	sites := trampolineSyscallSites(transfers, functions)
	if len(sites) != 1 || sites[0].symbol != syscallRawSyscallNoErrorABI0 || !sites[0].numberKnown || sites[0].number != 39 {
		t.Fatalf("classified trampoline site = %+v", sites)
	}
	launchBase := inspectedGuestBinary{name: guestInitBinaryName}
	if extra := extraReachableSyscallName(launchBase, sites[0]); extra != "" {
		t.Fatalf("catalog-listed trampoline getpid extra = %q", extra)
	}
}

func TestL8D7SyscallTrampolineKeepsUnknownWhenTrapNumberIsUnproven(t *testing.T) {
	code := []byte{0xe8, 0x04, 0x00, 0x00, 0x00}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	_, _, transfers, _, err := decodeFunctionSyscallGraph(fn, code, 0)
	if err != nil {
		t.Fatalf("decode unproven trampoline caller: %v", err)
	}
	functions := []executableFunction{
		fn,
		{name: syscallRawVforkSyscallABI0, start: transfers[0].target, end: transfers[0].target + 16},
	}
	sites := trampolineSyscallSites(transfers, functions)
	if len(sites) != 1 || sites[0].numberKnown {
		t.Fatalf("unproven trampoline site = %+v", sites)
	}
	if extra := extraReachableSyscallName(inspectedGuestBinary{name: guestInitBinaryName}, sites[0]); extra != "unknown:syscall.rawVforkSyscall.abi0" {
		t.Fatalf("unproven trampoline extra = %q", extra)
	}
}

func TestL8D7SyscallTrampolinePrefersTrapSlotOverLeftoverAX(t *testing.T) {
	code := []byte{
		0x48, 0xc7, 0xc0, 0x38, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0x04, 0x24, 0xb3, 0x01, 0x00, 0x00,
		0xe8, 0x04, 0x00, 0x00, 0x00,
	}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	_, _, transfers, _, err := decodeFunctionSyscallGraph(fn, code, 0)
	if err != nil {
		t.Fatalf("decode mixed trap/AX caller: %v", err)
	}
	if len(transfers) != 1 || !transfers[0].trapSlotKnown || transfers[0].trapSlot != 435 {
		t.Fatalf("trap-slot/AX transfer = %+v, want clone3 435", transfers)
	}
	number, ok := provenTrampolineNumber(transfers[0])
	if !ok || number != 435 {
		t.Fatalf("proven trampoline number = (%d, %v), want clone3", number, ok)
	}
}

func TestL8D7SyscallTrampolineUsesAXWhenTrapSlotIsAbsent(t *testing.T) {
	code := []byte{
		0xb8, 0x38, 0x00, 0x00, 0x00,
		0xe8, 0x04, 0x00, 0x00, 0x00,
	}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	_, _, transfers, _, err := decodeFunctionSyscallGraph(fn, code, 0)
	if err != nil {
		t.Fatalf("decode AX trampoline caller: %v", err)
	}
	if len(transfers) != 1 || !transfers[0].raxKnown || transfers[0].rax != 56 || transfers[0].trapSlotKnown {
		t.Fatalf("AX-only transfer = %+v, want clone 56", transfers)
	}
	functions := []executableFunction{
		fn,
		{name: syscallRawVforkSyscallABI0, start: transfers[0].target, end: transfers[0].target + 8},
	}
	sites := trampolineSyscallSites(transfers, functions)
	if len(sites) != 1 || !sites[0].numberKnown || sites[0].number != 56 {
		t.Fatalf("AX trampoline site = %+v", sites)
	}
	if extra := extraReachableSyscallName(inspectedGuestBinary{name: guestInitBinaryName}, sites[0]); extra != "clone" {
		t.Fatalf("unlisted trampoline clone extra = %q", extra)
	}
}

func TestL8D7SyscallTrampolineDoesNotClassifyByPrefix(t *testing.T) {
	if isSyscallNumberTrampoline("syscall.reviewerAuthority") || isSyscallNumberTrampoline("syscall.RawSyscall.abi0") || isSyscallNumberTrampoline("runtime.rawSyscallNoError.abi0") {
		t.Fatal("prefix or similarly named symbol was treated as a number trampoline")
	}
	if !isSyscallNumberTrampoline(syscallRawSyscallNoErrorABI0) || !isSyscallNumberTrampoline(syscallRawVforkSyscallABI0) {
		t.Fatal("exact ABI0 trampoline names were not recognized")
	}
}

func TestL8D7SyscallTrampolineRejectsUnprovenInstructionFlows(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{
			name: "jump skips trap-slot immediate",
			code: []byte{
				0xeb, 0x08,
				0x48, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "conditional path skips trap-slot immediate",
			code: []byte{
				0x75, 0x08,
				0x48, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "branch into trap-slot instruction",
			code: []byte{
				0xeb, 0x03,
				0x48, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "movl is not the required movq",
			code: []byte{
				0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "indexed stack address is not zero sp",
			code: []byte{
				0x4a, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "segment-relative stack address is not zero sp",
			code: []byte{
				0x64, 0x48, 0xc7, 0x04, 0x24, 0x27, 0x00, 0x00, 0x00,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "ax overwrite kills immediate",
			code: []byte{
				0xb8, 0x27, 0x00, 0x00, 0x00,
				0x31, 0xc0,
				0xe8, 0x04, 0x00, 0x00, 0x00,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(test.code))}
			_, _, transfers, _, err := decodeFunctionSyscallGraph(fn, test.code, 0)
			if err != nil {
				t.Fatalf("decode unproven trampoline caller: %v", err)
			}
			if len(transfers) == 0 {
				t.Fatal("decoder omitted trampoline transfer")
			}
			transfer := transfers[len(transfers)-1]
			if transfer.trapSlotKnown || transfer.raxKnown {
				t.Fatalf("unproven transfer = %+v, want no recovered number", transfer)
			}
		})
	}
}

func TestL8D7SyscallTrampolineRejectsCallIntoSymbolInterior(t *testing.T) {
	transfer := decodedControlTransfer{
		target:        0x2001,
		trapSlotKnown: true,
		trapSlot:      39,
	}
	functions := []executableFunction{{name: syscallRawSyscallNoErrorABI0, start: 0x2000, end: 0x2010}}
	sites := trampolineSyscallSites([]decodedControlTransfer{transfer}, functions)
	if len(sites) != 1 || sites[0].numberKnown {
		t.Fatalf("interior trampoline target = %+v, want one unknown fail-closed site", sites)
	}
}

func TestL8D7ListedSpanInteriorIsAKnownFunction(t *testing.T) {
	functions := []executableFunction{
		{name: "runtime.duffcopy", start: 0x2000, end: 0x2400},
		{name: "indexbytebody", start: 0x3000, end: 0x3100},
	}
	callee, unbounded := followListedSpanTarget(functions, 0x232c)
	if unbounded || callee == nil || callee.name != "runtime.duffcopy" || callee.start != 0x2000 {
		t.Fatalf("duffcopy interior = %+v unbounded:%v", callee, unbounded)
	}
	callee, unbounded = followListedSpanTarget(functions, 0x3000)
	if unbounded || callee == nil || callee.name != "indexbytebody" {
		t.Fatalf("ABI0 stub start = %+v unbounded:%v", callee, unbounded)
	}
	if _, unbounded = followListedSpanTarget(functions, 0x9999); !unbounded {
		t.Fatal("unlisted destination was treated as a known function")
	}
}

func TestL8D7RIPRelativeJumpTableIsAKnownTargetSet(t *testing.T) {
	code := []byte{
		0x83, 0xe1, 0x01,
		0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
		0x90, 0x90,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	resolver := &goTextResolver{
		functions: []executableFunction{fn},
		loadU64: func(va uint64) (uint64, bool) {
			switch va {
			case 0x2000:
				return 0x100d, true
			case 0x2008:
				return 0x100e, true
			default:
				return 0, false
			}
		},
	}
	_, extra, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode jump table: %v", err)
	}
	if unbounded {
		t.Fatal("in-function RIP-relative jump table remained unbounded")
	}
	if len(extra) != 0 {
		t.Fatalf("in-function jump table extra targets = %#x, want none", extra)
	}
}

func TestL8D7RIPRelativeCMPJumpTableIsAKnownTargetSet(t *testing.T) {
	code := []byte{
		0x48, 0x83, 0xf9, 0x01,
		0x77, 0x0a,
		0x48, 0x8d, 0x15, 0xf3, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
		0x90,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	resolver := &goTextResolver{
		functions: []executableFunction{fn},
		loadU64: func(va uint64) (uint64, bool) {
			if va == 0x2000 || va == 0x2008 {
				return fn.start, true
			}
			return 0, false
		},
	}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode CMP/JA jump table: %v", err)
	}
	if unbounded {
		t.Fatal("64-bit CMP/forward-JA guarded jump table remained unbounded")
	}
}

func TestL8D7RegisterIndirectCallRemainsUnboundedWithoutProvenTarget(t *testing.T) {
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1002}
	_, _, _, unbounded, err := decodeFunctionSyscallGraph(fn, []byte{0xff, 0xd0}, 0)
	if err != nil {
		t.Fatalf("decode CALL RAX: %v", err)
	}
	if !unbounded {
		t.Fatal("unproven CALL RAX was treated as a known target set")
	}
	_, _, _, unbounded, err = decodeFunctionSyscallGraph(fn, []byte{0xff, 0xd1}, 0)
	if err != nil || !unbounded {
		t.Fatalf("unproven CALL RCX unbounded=%v err=%v", unbounded, err)
	}
	_, _, _, unbounded, err = decodeFunctionSyscallGraph(fn, []byte{0xff, 0xd6}, 0)
	if err != nil || !unbounded {
		t.Fatalf("unproven CALL RSI unbounded=%v err=%v", unbounded, err)
	}
}

func TestL8D7RIPRelativeLEARegisterCallRemainsUnbounded(t *testing.T) {
	code := []byte{0x48, 0x8d, 0x05, 0xf9, 0x1f, 0x00, 0x00, 0xff, 0xd0}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	callee := executableFunction{name: "callee", start: 0x3000, end: 0x3010}
	resolver := &goTextResolver{functions: []executableFunction{fn, callee}}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode LEA/CALL: %v", err)
	}
	if !unbounded {
		t.Fatal("RIP-relative LEA followed by CALL RAX was treated as an allowed relative transfer")
	}
}

func TestL8D7MethodTableEncodingWithoutProvenBaseStaysUnbounded(t *testing.T) {
	fn := executableFunction{name: "iface", start: 0x1000, end: 0x1003}
	_, _, _, unbounded, err := decodeFunctionSyscallGraph(fn, []byte{0xff, 0x24, 0xd1}, 0)
	if err != nil {
		t.Fatalf("decode JMP [RCX+RDX*8]: %v", err)
	}
	if !unbounded {
		t.Fatal("FF 24 D1 without a proven table base was treated as bounded")
	}
}

func TestL8D7JumpTableWithoutProvenLengthStaysUnbounded(t *testing.T) {
	code := []byte{
		0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	_, _, _, unbounded, err := decodeFunctionSyscallGraph(fn, code, 0)
	if err != nil {
		t.Fatalf("decode unproven jump table: %v", err)
	}
	if !unbounded {
		t.Fatal("jump table without AND/CMP length was treated as bounded")
	}
}

func TestL8D7JumpTableRejectsBranchSkippedFacts(t *testing.T) {
	code := []byte{
		0xeb, 0x0a,
		0x83, 0xe1, 0x01,
		0x48, 0x8d, 0x15, 0xf4, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	resolver := &goTextResolver{
		functions: []executableFunction{fn},
		loadU64: func(va uint64) (uint64, bool) {
			if va == 0x2000 || va == 0x2008 {
				return 0x100c, true
			}
			return 0, false
		},
	}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode branch-skipped jump table facts: %v", err)
	}
	if !unbounded {
		t.Fatal("branch-skipped AND/LEA facts bounded an indirect jump")
	}
}

func TestL8D7JumpTableRejectsExternalInteriorEntryThatSkipsFacts(t *testing.T) {
	code := []byte{
		0x83, 0xe1, 0x01,
		0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	resolver := &goTextResolver{
		functions:       []executableFunction{fn},
		interiorEntries: map[uint64][]uint64{fn.start: {fn.start + 10}},
		loadU64: func(va uint64) (uint64, bool) {
			if va == 0x2000 || va == 0x2008 {
				return fn.start, true
			}
			return 0, false
		},
	}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode externally entered jump table: %v", err)
	}
	if !unbounded {
		t.Fatal("external listed-span interior entry skipped the AND/LEA proof")
	}
}

func TestL8D7JumpTableRejectsJAGuardIntoDispatch(t *testing.T) {
	code := []byte{
		0x48, 0x83, 0xf9, 0x01,
		0x77, 0x07,
		0x48, 0x8d, 0x15, 0xf3, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	resolver := &goTextResolver{
		functions: []executableFunction{fn},
		loadU64: func(va uint64) (uint64, bool) {
			if va == 0x2000 || va == 0x2008 {
				return 0x100d, true
			}
			return 0, false
		},
	}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode invalid JA guard: %v", err)
	}
	if !unbounded {
		t.Fatal("JA into the indirect jump was treated as an upper-bound guard")
	}
}

func TestL8D7JumpTableRejectsIndexedIndirectCall(t *testing.T) {
	code := []byte{
		0x83, 0xe1, 0x01,
		0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00,
		0xff, 0x14, 0xca,
	}
	fn := executableFunction{name: "caller", start: 0x1000, end: 0x1000 + uint64(len(code))}
	callee := executableFunction{name: "callee", start: 0x3000, end: 0x3010}
	resolver := &goTextResolver{
		functions: []executableFunction{fn, callee},
		loadU64: func(va uint64) (uint64, bool) {
			if va == 0x2000 || va == 0x2008 {
				return callee.start, true
			}
			return 0, false
		},
	}
	_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
	if err != nil {
		t.Fatalf("decode indexed indirect CALL: %v", err)
	}
	if !unbounded {
		t.Fatal("indexed indirect CALL was accepted as a proven JMP table")
	}
}

func TestL8D7JumpTableRejectsZeroAndUnlistedEntries(t *testing.T) {
	code := []byte{
		0x83, 0xe1, 0x01,
		0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00,
		0xff, 0x24, 0xca,
	}
	fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(code))}
	for _, invalid := range []uint64{0, 0x9999} {
		resolver := &goTextResolver{
			functions: []executableFunction{fn},
			loadU64: func(va uint64) (uint64, bool) {
				if va == 0x2000 {
					return fn.start, true
				}
				if va == 0x2008 {
					return invalid, true
				}
				return 0, false
			},
		}
		_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, code, 0, resolver)
		if err != nil {
			t.Fatalf("decode table with entry %#x: %v", invalid, err)
		}
		if !unbounded {
			t.Fatalf("table entry %#x outside every listed span was accepted", invalid)
		}
	}
}

func TestL8D7JumpTableRequiresCanonicalRegisterBaseAnd64BitCMP(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{
			name: "segment override",
			code: []byte{0x83, 0xe1, 0x01, 0x48, 0x8d, 0x15, 0xf6, 0x0f, 0x00, 0x00, 0x64, 0xff, 0x24, 0xca},
		},
		{
			name: "SIB without base",
			code: []byte{0x83, 0xe1, 0x01, 0x48, 0x8d, 0x2d, 0xf6, 0x0f, 0x00, 0x00, 0xff, 0x24, 0xcd, 0x00, 0x20, 0x00, 0x00},
		},
		{
			name: "32-bit CMP for 64-bit index",
			code: []byte{0x83, 0xf9, 0x01, 0x77, 0x0a, 0x48, 0x8d, 0x15, 0xf4, 0x0f, 0x00, 0x00, 0xff, 0x24, 0xca, 0x90, 0x90},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := executableFunction{name: "kindSwitch", start: 0x1000, end: 0x1000 + uint64(len(test.code))}
			resolver := &goTextResolver{functions: []executableFunction{fn}, loadU64: func(va uint64) (uint64, bool) {
				return fn.start, true
			}}
			_, _, _, unbounded, err := decodeFunctionSyscallGraphWithResolver(fn, test.code, 0, resolver)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !unbounded {
				t.Fatal("noncanonical table proof was accepted")
			}
		})
	}
}

func TestL8D7JumpTableReadsOnlyOneCompleteReadOnlyMapping(t *testing.T) {
	encoded := make([]byte, 32)
	readOnly := &elf.Prog{ProgHeader: elf.ProgHeader{
		Type:   elf.PT_LOAD,
		Flags:  elf.PF_R,
		Off:    0,
		Vaddr:  0x2000,
		Filesz: 16,
	}}
	file := &elf.File{Progs: []*elf.Prog{readOnly}}
	if off, err := mapReadOnlyLoadAddress(file, encoded, 0x2000, 8); err != nil || off != 0 {
		t.Fatalf("read-only mapping offset=%d err=%v", off, err)
	}
	if _, err := mapReadOnlyLoadAddress(file, encoded, 0x200c, 8); err == nil {
		t.Fatal("entry crossing the mapped segment was accepted")
	}
	writable := &elf.Prog{ProgHeader: readOnly.ProgHeader}
	writable.Flags |= elf.PF_W
	if _, err := mapReadOnlyLoadAddress(&elf.File{Progs: []*elf.Prog{writable}}, encoded, 0x2000, 8); err == nil {
		t.Fatal("writable jump-table mapping was accepted")
	}
	duplicate := &elf.Prog{ProgHeader: readOnly.ProgHeader}
	if _, err := mapReadOnlyLoadAddress(&elf.File{Progs: []*elf.Prog{readOnly, duplicate}}, encoded, 0x2000, 8); err == nil {
		t.Fatal("ambiguous jump-table mapping was accepted")
	}
}

func TestL8D7HonestIssuanceFailsClosedEvenIfExtrasAreEmpty(t *testing.T) {
	for _, name := range []string{"elf.go", "evidence.go"} {
		encoded, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(encoded)
		if name == "elf.go" && !strings.Contains(text, `return errors.New("unique/reachable D4/D6 call graph is unavailable")`) {
			t.Fatal("requireCompleteHonestIssuanceInputs lost the fail-closed last return")
		}
		if name == "evidence.go" && !strings.Contains(text, "errEvidenceInputsUnavailable") {
			t.Fatal("generateEvidence lost errEvidenceInputsUnavailable")
		}
	}
	encoded, err := os.ReadFile("elf.go")
	if err != nil {
		t.Fatalf("read elf.go: %v", err)
	}
	if !strings.Contains(string(encoded), `return generatedEvidence{}, fmt.Errorf("%w: unique/reachable D4/D6 call graph is unavailable", errEvidenceInputsUnavailable)`) {
		t.Fatal("generateEvidenceFromInputs lost the fail-closed empty-extra return")
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
