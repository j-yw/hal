//go:build !linux

package l7network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
)

func TestFirecrackerHostTopologyProductionBoundariesFailClosedOffLinux(t *testing.T) {
	tap, err := NewLinuxTAP(TAPOptions{IPPath: "/usr/sbin/ip", SysctlPath: "/usr/sbin/sysctl", NsenterPath: "/usr/bin/nsenter",
		Command: panicNamespaceCommand{}})
	if err != nil {
		t.Fatal(err)
	}
	spec := staticTAPSpec(testIdentity(), netip.MustParseAddr("192.0.2.2"), 43123)
	if _, err := tap.CreateConfigure(context.Background(), &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, spec); !errors.Is(err, ErrTopologyPrepareFailed) {
		t.Fatalf("CreateConfigure() = %v", err)
	}
	root := filepath.Join(t.TempDir(), "topology")
	store, err := newFileJournalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), testIdentity()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("journal Acquire() = %v, want ErrUnsupported", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-Linux journal mutated state: %v", err)
	}
}

type panicNamespaceCommand struct{}

func (panicNamespaceCommand) Run(context.Context, NamespaceLease, NamespaceCommandRequest, int64) ([]byte, error) {
	panic("non-Linux command invoked")
}
