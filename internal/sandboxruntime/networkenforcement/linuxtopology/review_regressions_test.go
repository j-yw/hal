package linuxtopology

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxTopologyLossRevokesInspectionAndNamespaceTransfer(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-loss-revoke"))
	if err != nil {
		t.Fatal(err)
	}
	starter.latest(ProcessRoleMapping).exit()
	select {
	case <-session.Losses():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for loss")
	}
	if metadata := session.Metadata(); metadata.Status != StatusLost || metadata.Inspected {
		t.Fatalf("metadata after loss = %#v, want lost without inspection", metadata)
	}
	if handle, err := session.NamespaceHandle(); !errors.Is(err, ErrStopped) || handle != nil {
		t.Fatalf("NamespaceHandle after loss = %#v, %v", handle, err)
	}
	_, _ = lifecycle.Stop(context.Background(), testIdentity("topology-gen-loss-revoke"))
}

func TestLinuxTopologyStoppedGenerationCannotEverRestart(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: goodLinkJSON()}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)
	request := testRequest("topology-gen-retired")
	if _, err := lifecycle.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Stop(context.Background(), request.Identity); err != nil {
		t.Fatal(err)
	}
	before := starter.startCount()
	if _, err := lifecycle.Start(context.Background(), request); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("reused generation error = %v, want ErrStaleGeneration", err)
	}
	if got := starter.startCount(); got != before {
		t.Fatalf("reused generation started processes: before=%d after=%d", before, got)
	}
}

func TestLinuxTopologyIncompleteRollbackRetainsOwnershipAndBlocksReplacement(t *testing.T) {
	starter := newFakeStarter()
	runner := &fakeRunner{output: []byte(`[]`)}
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle := newTestLifecycle(t, starter, runner, namespaces)

	// Force reverse rollback to remain uncertain after structural inspection fails.
	go func() {
		for starter.latest(ProcessRoleMapping) == nil {
			time.Sleep(time.Millisecond)
		}
		starter.latest(ProcessRoleMapping).terminateErr = errors.New("uncertain termination")
	}()
	session, err := lifecycle.Start(context.Background(), testRequest("topology-gen-incomplete"))
	if !errors.Is(err, ErrCleanupIncomplete) || session == nil {
		t.Fatalf("Start = %#v, %v, want retained session and ErrCleanupIncomplete", session, err)
	}
	if metadata := session.Metadata(); metadata.Status != StatusCleanupIncomplete || metadata.Inspected {
		t.Fatalf("retained metadata = %#v", metadata)
	}
	if _, err := lifecycle.Start(context.Background(), testRequest("topology-gen-replacement")); !errors.Is(err, ErrTopologyCollision) {
		t.Fatalf("replacement error = %v, want ErrTopologyCollision", err)
	}
	starter.latest(ProcessRoleMapping).terminateErr = nil
	if _, err := lifecycle.Stop(context.Background(), testIdentity("topology-gen-incomplete")); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
}

func TestLinuxTopologyFileOwnershipLockAndRetirementAreDurable(t *testing.T) {
	root := t.TempDir()
	store, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-durable")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFileOwnershipStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquire(context.Background(), identity); !errors.Is(err, ErrTopologyCollision) {
		t.Fatalf("second acquire error = %v, want ErrTopologyCollision", err)
	}
	if err := lease.retire(identity); err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquire(context.Background(), identity); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("retired acquire error = %v, want ErrStaleGeneration", err)
	}

	sandboxDir := filepath.Join(root, identity.SandboxID)
	info, err := os.Stat(sandboxDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("sandbox state mode = %o, want 700", info.Mode().Perm())
	}
	entries, err := os.ReadDir(sandboxDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() && info.Mode().Perm() != 0o600 {
			t.Fatalf("private state %q mode = %o, want 600", entry.Name(), info.Mode().Perm())
		}
	}
}

func TestLinuxTopologyProductionSourceUsesAtomicCLOEXECAndParentDeath(t *testing.T) {
	duplication, err := os.ReadFile("namespace_dup_unix.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(duplication), "syscall.Dup(") || !strings.Contains(string(duplication), "F_DUPFD_CLOEXEC") {
		t.Fatal("namespace duplication must be atomic CLOEXEC")
	}
	process, err := os.ReadFile("process_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(process), "Pdeathsig") {
		t.Fatal("production helpers must have parent-death containment")
	}
}
