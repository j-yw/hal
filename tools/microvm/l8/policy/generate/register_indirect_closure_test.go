package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestL8D7FuncvalTrampolineReachesRuntimeCreatedClosure(t *testing.T) {
	source := `package main

import "syscall"

//go:noinline
func invoke(fn func()) { fn() }

func main() {
	value := uintptr(7)
	invoke(func() {
		_, _, _ = syscall.RawSyscall(syscall.SYS_GETUID, value, 0, 0)
	})
}
`
	path := buildLinuxAMD64GoBinary(t, t.TempDir(), "register-indirect-closure", source)
	inspected, err := inspectLinuxAMD64ELF("register-indirect-closure", path)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.graphErr != nil {
		t.Fatal(inspected.graphErr)
	}
	if !containsString(inspected.reachableFunctions, "main.main.func1") {
		t.Fatalf("funcval trampoline did not reach the closure; reachable=%v unbounded=%v extras=%v", inspected.reachableFunctions, inspected.unboundedIndirect, extraReachableSyscallNames(inspected))
	}
}

func TestL8D7ReachableVEXBodyFollowsRelativeCall(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.invalid/l8-vex-review\n\ngo 1.25.7\n",
		"main.go": `package main

import "syscall"

func vexCaller()

//go:noinline
func syscallCallee() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_GETUID, 0, 0, 0)
}

func main() { vexCaller() }
`,
		"vex_amd64.s": `#include "textflag.h"

TEXT ·vexCaller(SB), NOSPLIT, $0-0
	BYTE $0xc5
	BYTE $0xf8
	BYTE $0x77
	CALL ·syscallCallee(SB)
	RET
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "l8-vex-review")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", path, ".")
	command.Dir = dir
	command.Env = linuxAMD64GoBuildEnv(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build VEX review binary: %v\n%s", err, output)
	}
	inspected, err := inspectLinuxAMD64ELF("l8-vex-review", path)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.graphErr != nil {
		t.Fatal(inspected.graphErr)
	}
	if !containsString(inspected.reachableFunctions, "main.syscallCallee") {
		t.Fatalf("VEX body hid the relative CALL; reachable=%v extras=%v", inspected.reachableFunctions, extraReachableSyscallNames(inspected))
	}
}
