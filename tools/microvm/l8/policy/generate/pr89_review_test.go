package main

import "testing"

func TestL8D7RegisterIndirectCallRejectsRuntimeCreatedClosureOutsideStaticSections(t *testing.T) {
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
	path := buildLinuxAMD64GoBinary(t, t.TempDir(), "pr89-review-closure", source)
	inspected, err := inspectLinuxAMD64ELF("pr89-review-closure", path)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.graphErr != nil {
		t.Fatal(inspected.graphErr)
	}
	if !inspected.unboundedIndirect {
		t.Fatal("runtime-created closure outside the static section inventory was treated as a complete register-indirect target set")
	}
}
