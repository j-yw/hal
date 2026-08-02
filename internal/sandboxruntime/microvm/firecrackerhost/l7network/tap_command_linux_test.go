//go:build linux

package l7network

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

func TestOSNamespaceCommandPreservesMappedUserCredentials(t *testing.T) {
	root := t.TempDir()
	user, err := os.OpenFile(filepath.Join(root, "user"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	network, err := os.OpenFile(filepath.Join(root, "network"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = user.Close()
		t.Fatal(err)
	}
	handle, err := linuxtopology.NewNamespaceHandle(user, network)
	if err != nil {
		_ = user.Close()
		_ = network.Close()
		t.Fatal(err)
	}
	files, err := handle.BorrowFiles()
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	lease := &linuxNamespaceLease{handle: handle, files: files}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Errorf("close namespace lease: %v", err)
		}
	}()

	launcher := filepath.Join(root, "capture-args")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := &osNamespaceCommand{nsenterPath: launcher}
	output, err := command.Run(context.Background(), lease, NamespaceCommandRequest{
		Path: "/usr/sbin/ip",
		Args: []string{"link", "show"},
	}, defaultTAPOutputLimit)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(output))
	want := []string{
		"--preserve-credentials",
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--",
		"/usr/sbin/ip",
		"link",
		"show",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("namespace command arguments = %#v, want %#v", got, want)
	}
}
