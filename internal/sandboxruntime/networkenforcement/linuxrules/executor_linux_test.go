//go:build linux

package linuxrules

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxRulesProductionExecutorRequiresAbsoluteToolPaths(t *testing.T) {
	for _, options := range []ProductionExecutorOptions{
		{NSenterPath: "nsenter", NFTPath: "/usr/bin/nft"},
		{NSenterPath: "/usr/bin/nsenter", NFTPath: "nft"},
	} {
		if executor, err := NewProductionExecutor(options); !errors.Is(err, ErrInvalidConfiguration) || executor != nil {
			t.Fatalf("NewProductionExecutor(%#v) = (%#v, %v), want nil ErrInvalidConfiguration", options, executor, err)
		}
	}
}

func TestLinuxRulesNamespaceCommandRetainsOwningNamespaceCapabilities(t *testing.T) {
	userNamespace, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatalf("open user namespace: %v", err)
	}
	defer userNamespace.Close()
	networkNamespace, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("open network namespace: %v", err)
	}
	defer networkNamespace.Close()

	executor, err := newProductionExecutor(ProductionExecutorOptions{
		NSenterPath: "/usr/bin/nsenter",
		NFTPath:     "/usr/bin/nft",
	})
	if err != nil {
		t.Fatalf("newProductionExecutor: %v", err)
	}
	command, namespaceFiles, err := executor.namespaceCommand(context.Background(), NewNamespaceHandle(int(userNamespace.Fd()), int(networkNamespace.Fd())), "--json")
	if err != nil {
		t.Fatalf("namespaceCommand: %v", err)
	}
	for _, file := range namespaceFiles {
		defer file.Close()
	}
	if command.Path != "/usr/bin/nsenter" {
		t.Fatalf("command path = %q, want absolute nsenter path", command.Path)
	}
	want := []string{"/usr/bin/nsenter", "--preserve-credentials", "--keep-caps", "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--", "/usr/bin/nft", "--json"}
	if len(command.Args) != len(want) {
		t.Fatalf("command args = %#v, want %#v", command.Args, want)
	}
	for index := range want {
		if command.Args[index] != want[index] {
			t.Fatalf("command args = %#v, want %#v", command.Args, want)
		}
	}
	if len(command.ExtraFiles) != 2 {
		t.Fatalf("extra files = %d, want user and network namespace descriptors", len(command.ExtraFiles))
	}
	for _, file := range command.ExtraFiles {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("read duplicate descriptor flags: %v", err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("duplicate namespace descriptor lacks atomic close-on-exec protection")
		}
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("command environment = %#v, want explicit empty environment", command.Env)
	}
}
