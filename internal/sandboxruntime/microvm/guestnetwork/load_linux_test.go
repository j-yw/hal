//go:build linux

package guestnetwork

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLoadLinuxBootConfigPathRejectsSymlinkTypeOverflowAndCancellation(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "cmdline")
	if err := os.WriteFile(validPath, []byte(validBootCommandLine), 0600); err != nil {
		t.Fatal(err)
	}
	config, present, err := loadLinuxBootConfigPath(context.Background(), validPath)
	if err != nil || !present || !config.Valid() {
		t.Fatalf("valid load = %#v, %t, %v", config, present, err)
	}

	symlinkPath := filepath.Join(directory, "cmdline-link")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	overflowPath := filepath.Join(directory, "overflow")
	if err := os.WriteFile(overflowPath, []byte(strings.Repeat("x", int(MaximumBootCommandLineBytes+1))), 0600); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, test := range []struct {
		name string
		ctx  context.Context
		path string
	}{
		{name: "symlink", ctx: context.Background(), path: symlinkPath},
		{name: "directory", ctx: context.Background(), path: directory},
		{name: "fifo", ctx: context.Background(), path: fifoPath},
		{name: "overflow", ctx: context.Background(), path: overflowPath},
		{name: "canceled", ctx: canceled, path: validPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, present, err := loadLinuxBootConfigPath(test.ctx, test.path)
			if err == nil || present || config.Valid() {
				t.Fatalf("load = %#v, %t, %v, want fail closed", config, present, err)
			}
			if strings.Contains(err.Error(), directory) {
				t.Fatalf("error leaked path: %v", err)
			}
		})
	}
}
