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

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
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
	for path, want := range first.files() {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read checked-in generated output %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("checked-in generated native output %s is stale", path)
		}
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
	policySHA256, err := readDigestFile(filepath.Join(root, policyDigestRel))
	if err != nil {
		t.Fatalf("issued policy digest: %v", err)
	}
	policyBytes, err := os.ReadFile(filepath.Join(root, policyArtifactRel))
	if err != nil {
		t.Fatalf("issued policy artifact: %v", err)
	}
	compiled, err := syscallpolicy.CompileIssuedRoleFilter(policyBytes, policySHA256, syscallpolicy.RoleLaunchBase)
	if err != nil {
		t.Fatalf("compile launch-base filter: %v", err)
	}
	if compiled.Len() == 0 || !bytes.Contains(payload, compiled.CanonicalBytes()) {
		t.Fatal("native ELF is missing the compiled launch-base seccomp program")
	}
	if compiled.Action(0xc000003e, 231, [6]uint64{}) != syscallpolicy.ActionAllow {
		t.Fatal("compiled launch-base filter does not allow exit_group")
	}
	if compiled.Action(0xc000003e, 435, [6]uint64{1, 88}) != syscallpolicy.ActionAllow {
		t.Fatal("compiled launch-base filter does not allow the exact clone3 pointer/size template")
	}
	if compiled.Action(0xc000003e, 435, [6]uint64{}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter does not fail-closed EPERM clone3 without matching the exact template")
	}
	if compiled.Action(0xc000003e, 435, [6]uint64{0, 88}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter does not fail-closed EPERM clone3 with a missing clone_args pointer")
	}
	if compiled.Action(0xc000003e, 435, [6]uint64{1, 64}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter does not fail-closed EPERM clone3 with the wrong clone_args size")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{5, 1, 0, 0, 0x1000}) != syscallpolicy.ActionAllow {
		t.Fatal("compiled launch-base filter does not allow the exact monitor execveat FD 5 AT_EMPTY_PATH template")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{6, 1, 0, 0, 0x1000}) != syscallpolicy.ActionAllow {
		t.Fatal("compiled launch-base filter does not allow the exact shim execveat FD 6 AT_EMPTY_PATH template")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{3, 1, 0, 0, 0x1000}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter allowed invented controller execveat FD 3")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{4, 1, 0, 0, 0x1000}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter allowed invented agent execveat FD 4")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter does not fail-closed EPERM execveat without the exact FD+AT_EMPTY_PATH template")
	}
	if compiled.Action(0xc000003e, 322, [6]uint64{5, 1, 0, 0, 0}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter allowed execveat without AT_EMPTY_PATH")
	}
	if compiled.Action(0xc000003e, 59, [6]uint64{}) != syscallpolicy.ActionKillProcess {
		t.Fatal("compiled launch-base filter does not fail-closed kill pathname execve after nativeEnvelope dropped it")
	}
	if compiled.Action(0xc000003e, 59, [6]uint64{1, 1, 0}) != syscallpolicy.ActionKillProcess {
		t.Fatal("compiled launch-base filter allowed pathname execve; it is no longer a native _start site")
	}
	if compiled.Action(0xc000003e, 47, [6]uint64{}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter does not fail-closed EPERM recvmsg without an exact SCM_RIGHTS template")
	}
	if compiled.Action(0xc000003e, 47, [6]uint64{16, 1, 0x40000040}) != syscallpolicy.ActionErrnoEPERM {
		t.Fatal("compiled launch-base filter allowed recvmsg; SCM_RIGHTS cmsg contents are not HL8Q-scalar-encodable")
	}
	if compiled.Action(0xc000003e, 46, [6]uint64{}) == syscallpolicy.ActionAllow || compiled.Action(0xc000003e, 46, [6]uint64{16, 1, 0}) == syscallpolicy.ActionAllow {
		t.Fatal("compiled launch-base filter allowed sendmsg by catalog name")
	}

	for _, args := range [][]string{
		nil,
		{"controller"},
		{"agent"},
		{"monitor"},
		{"workload-shim"},
		{"not-a-role"},
		{"controller", "extra"},
	} {
		command := exec.Command(binary, args...)
		err := command.Run()
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 127 {
			t.Fatalf("native ELF args %v exit = %v, want 127", args, err)
		}
	}
}

func TestL8D7NativeRoleBootstrapBuildIgnoresCallerFilterShadow(t *testing.T) {
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
	caller := t.TempDir()
	shadow := []byte("\t.section .rodata, \"a\", @progbits\n\t.align 8\n\t.type\tlaunch_base_filter, @object\nlaunch_base_filter:\n\t.short\t0x0006\n\t.byte\t0\n\t.byte\t0\n\t.long\t0x7fff0000\n\t.size\tlaunch_base_filter, .-launch_base_filter\n\t.type\tlaunch_base_filter_len, @object\nlaunch_base_filter_len:\n\t.short\t1\n")
	if err := os.WriteFile(filepath.Join(caller, "launch_base_filter.inc"), shadow, 0o600); err != nil {
		t.Fatalf("write caller filter shadow: %v", err)
	}
	out := filepath.Join(caller, "out")
	build := exec.Command("bash", filepath.Join(root, "tools/microvm/l8/role-bootstrap/build.sh"), out)
	build.Dir = caller
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build.sh from caller directory: %v\n%s", err, output)
	}
	file, err := elf.Open(filepath.Join(out, "hal-guest-role-bootstrap"))
	if err != nil {
		t.Fatalf("open ELF: %v", err)
	}
	defer file.Close()
	policySHA256, err := readDigestFile(filepath.Join(root, policyDigestRel))
	if err != nil {
		t.Fatalf("issued policy digest: %v", err)
	}
	policyBytes, err := os.ReadFile(filepath.Join(root, policyArtifactRel))
	if err != nil {
		t.Fatalf("issued policy artifact: %v", err)
	}
	compiled, err := syscallpolicy.CompileIssuedRoleFilter(policyBytes, policySHA256, syscallpolicy.RoleLaunchBase)
	if err != nil {
		t.Fatalf("compile launch-base filter: %v", err)
	}
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatalf("ELF symbols: %v", err)
	}
	for _, symbol := range symbols {
		if symbol.Name != "launch_base_filter" {
			continue
		}
		section := file.Sections[symbol.Section]
		sectionBytes, readErr := section.Data()
		if readErr != nil {
			t.Fatalf("read launch-base filter section: %v", readErr)
		}
		offset := symbol.Value - section.Addr
		if symbol.Size != uint64(len(compiled.CanonicalBytes())) || offset+symbol.Size > uint64(len(sectionBytes)) {
			t.Fatalf("launch-base filter symbol size/range = %d/%d", symbol.Size, len(sectionBytes))
		}
		if got := sectionBytes[offset : offset+symbol.Size]; !bytes.Equal(got, compiled.CanonicalBytes()) {
			t.Fatal("caller working directory shadowed the issued launch-base filter")
		}
		return
	}
	t.Fatal("native ELF is missing launch_base_filter")
}

func TestL8D7NativeSupervisorStagesRemainFailClosed(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, nativeSourceRel))
	if err != nil {
		t.Fatalf("read native source: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		".Lpid1_vsock:",
		".Lpid1_seccomp:",
		".Lpid1_clone3:",
		".Lpid1_execveat:",
		".Lpid1_scm_rights:",
		".Lcontroller_unimpl:",
		".Lagent_unimpl:",
		".Lmonitor_unimpl:",
		".Lshim_unimpl:",
		"movq\t$41, %rax",
		"movq\t$49, %rax",
		"movq\t$50, %rax",
		"movq\t$292, %rax",
		"movq\t$3, %rax",
		"movq\t$157, %rax",
		"movq\t$317, %rax",
		"movq\t$435, %rax",
		"movq\t$322, %rax",
		"movq\t$47, %rax",
		"movq\t$16, %rdi",
		"movq\t$0x40000040, %rdx",
		"movq\t$231, %rax",
		"$0x80801",
		"$0xffffffff",
		"$1024",
		"$1025",
		"$1026",
		"$0x5100",
		"$0x25100",
		"$0x200005100",
		"movq\t$9, 80(%rsp)",
		"movq\t$17, 32(%rsp)",
		"movq\t$5, %rdi",
		"movq\t$6, %rdi",
		"leaq\ttoken_monitor(%rip), %r9",
		"leaq\ttoken_workload_shim(%rip), %r9",
		"movq\t%r9, 96(%rsp)",
		"movq\t$0, 104(%rsp)",
		"movq\t$0x1000, %r8",
		"empty_path",
		"launch_base_filter",
		"A successful bind is not live vsock proof",
		"Native PID1 is the image-init supervisor",
		"Go PID1 remains ForkExec-free",
		"Unimplemented: pivot_root",
		"Unimplemented: setresuid/setresgid",
		"Unimplemented: SCM_RIGHTS monitor-ready, execve",
		"Unimplemented: setns/ioctl",
		"reinspection and HL8L job_created relay stay unimplemented",
		"Controller/agent have no admitted sealed executable FD",
		"remaining admission gap",
		"do not allow-all execveat",
		"controller supervisor endpoint",
		"delegated cgroup-v2 root",
		"cmpq\t$2, %rbx",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("native supervisor source omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"movq\t$59, %rax",
		"movq\t$46, %rax",
		"movq\t$0, 96(%rsp)",
		"movl\t$0, %edi",
		"/usr/bin/hal-guest-credential-helper",
		"/usr/bin/hal-guest-agent",
		"/usr/bin/hal-guest-mount-monitor",
		"/usr/bin/hal-guest-workload-shim",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("native supervisor source contains forbidden live marker %q", forbidden)
		}
	}
	if err := validateNativeSource(source); err != nil {
		t.Fatalf("validateNativeSource(): %v", err)
	}
	callsite, err := os.ReadFile(filepath.Join(root, nativeCallsitesRel))
	if err != nil {
		t.Fatalf("read callsite inventory: %v", err)
	}
	if err := validateCallsiteInventory(callsite); err != nil {
		t.Fatalf("validateCallsiteInventory(): %v", err)
	}
	if !strings.Contains(string(callsite), "6=socket:41:pid1:0f05") {
		t.Fatal("callsite inventory is missing the PID1-only socket site")
	}
	if !strings.Contains(string(callsite), "11=prctl:157:pid1:0f05") || !strings.Contains(string(callsite), "12=seccomp:317:pid1:0f05") {
		t.Fatal("callsite inventory is missing the PID1 launch-base seccomp sites")
	}
	if !strings.Contains(string(callsite), "13=clone3:435:pid1:0f05") || !strings.Contains(string(callsite), "14=execveat:322:pid1:0f05") {
		t.Fatal("callsite inventory is missing the PID1 clone3 and execveat sites")
	}
	if !strings.Contains(string(callsite), "15=recvmsg:47:pid1:0f05") {
		t.Fatal("callsite inventory is missing the PID1 recvmsg SCM_RIGHTS site")
	}
	if strings.Contains(string(callsite), "sendmsg") || strings.Contains(string(callsite), "14=execve:59") {
		t.Fatal("callsite inventory claimed an unimplemented live supervisor syscall")
	}
}

func TestL8D7NativeExecveatRetainsOneImageOwnedArgv0(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, nativeSourceRel))
	if err != nil {
		t.Fatalf("read native source: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"leaq\ttoken_monitor(%rip), %r9",
		"leaq\ttoken_workload_shim(%rip), %r9",
		"movq\t%r9, 96(%rsp)",
		"movq\t$0, 104(%rsp)",
		"leaq\t96(%rsp), %rdx",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("native execveat argv omits %q", required)
		}
	}
	if strings.Contains(text, "movq\t$0, 96(%rsp)") {
		t.Fatal("native execveat passes argc zero to admitted Go role children")
	}
}

func TestL8D7NativeControllerAgentExecFDsRemainFailClosed(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, nativeSourceRel))
	if err != nil {
		t.Fatalf("read native source: %v", err)
	}
	text := string(source)
	start := strings.Index(text, ".Lpid1_execveat:")
	end := strings.Index(text, ".Lpid1_scm_rights:")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("native source is missing the PID1 execveat/scm-rights stage labels")
	}
	block := text[start:end]
	for _, required := range []string{
		"cmpq\t$2, %rbx",
		"jb\t.Lfail_closed",
		"movq\t$5, %rdi",
		"movq\t$6, %rdi",
		"leaq\ttoken_monitor(%rip), %r9",
		"leaq\ttoken_workload_shim(%rip), %r9",
		"remaining admission gap",
		"Controller/agent have no admitted sealed executable FD",
	} {
		if !strings.Contains(block, required) {
			t.Fatalf("native execveat stage omits fail-closed controller/agent marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"token_controller",
		"token_agent",
		"movq\t$3, %rdi",
		"movq\t$4, %rdi",
		"/usr/bin/hal-guest-credential-helper",
		"/usr/bin/hal-guest-agent",
		"movq\t$59, %rax",
	} {
		if strings.Contains(block, forbidden) {
			t.Fatalf("native execveat admitted controller/agent without a named sealed FD via %q", forbidden)
		}
	}

	policySHA256, err := readDigestFile(filepath.Join(root, policyDigestRel))
	if err != nil {
		t.Fatalf("issued policy digest: %v", err)
	}
	policyBytes, err := os.ReadFile(filepath.Join(root, policyArtifactRel))
	if err != nil {
		t.Fatalf("issued policy artifact: %v", err)
	}
	compiled, err := syscallpolicy.CompileIssuedRoleFilter(policyBytes, policySHA256, syscallpolicy.RoleLaunchBase)
	if err != nil {
		t.Fatalf("compile launch-base filter: %v", err)
	}
	auditArch := uint32(0xc000003e)
	if compiled.Action(auditArch, 322, [6]uint64{5, 1, 0, 0, 0x1000}) != syscallpolicy.ActionAllow {
		t.Fatal("launch-base execveat no longer Allows the named monitor FD 5")
	}
	if compiled.Action(auditArch, 322, [6]uint64{6, 1, 0, 0, 0x1000}) != syscallpolicy.ActionAllow {
		t.Fatal("launch-base execveat no longer Allows the named shim FD 6")
	}
	for _, fd := range []uint64{3, 4, 7, 8, 16} {
		if compiled.Action(auditArch, 322, [6]uint64{fd, 1, 0, 0, 0x1000}) != syscallpolicy.ActionErrnoEPERM {
			t.Fatalf("launch-base execveat Allowed unnamed controller/agent candidate FD %d", fd)
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
