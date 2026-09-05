//go:build linux && l7_linux_network_integration

package linuxtopology

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestL7PreparedLinuxOwnedNamespacePastaTopology(t *testing.T) {
	tool := func(name string) string {
		t.Helper()
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("selected L7 Linux topology prerequisite %q unavailable: %v", name, err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatalf("resolve selected prerequisite %q: %v", name, err)
		}
		return path
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start selected loopback fixture: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()

	lifecycle, err := New(Config{
		Enabled: true,
		Tools: ToolPaths{
			Unshare: tool("unshare"),
			Pasta:   tool("pasta"),
			Nsenter: tool("nsenter"),
			IP:      tool("ip"),
			NC:      tool("nc"),
			Keeper:  tool("sleep"),
		},
		StateDir:          t.TempDir(),
		CleanupTimeout:    5 * time.Second,
		InspectionTimeout: 5 * time.Second,
		OutputLimit:       64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := StartRequest{
		Identity: testIdentity("topology-gen-live"),
		Mapping: Mapping{
			ProxyEndpoint:      listener.Addr().String(),
			GuestProxyAddress:  "192.0.2.2",
			NamespaceInterface: "halpasta0",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	beforeFDs := openFDCount(t)
	session, err := lifecycle.Start(ctx, req)
	if err != nil {
		probeReached := false
		select {
		case <-accepted:
			probeReached = true
		default:
		}
		metadata := Metadata{}
		if session != nil {
			registerL7RetainedStartCleanup(t, session, req.Identity, l7RetainedStartCleanupDeps{
				Timeout: 6 * time.Second,
				Stop:    lifecycle.Stop,
			})
			metadata = session.Metadata()
		}
		t.Fatalf("selected L7 Linux topology start failed: %v (retained=%t status=%s probeReached=%t)", err, session != nil, metadata.Status, probeReached)
	}
	cleanupGuard, err := registerL7LiveCleanupGuard(t, session, req.Identity, l7LiveCleanupGuardDeps{
		Timeout:              6 * time.Second,
		Stop:                 lifecycle.Stop,
		ReadProcessStartTime: readProcessStartTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	trackedKeeper := cleanupGuard.keeper.handle
	trackedMapper := cleanupGuard.mapper.handle
	keeperPID := cleanupGuard.keeper.pid
	mapperPID := cleanupGuard.mapper.pid
	if got := session.Metadata(); got.Status != StatusPrepared || !got.StructuralInspected || !got.MappingReachable {
		t.Fatalf("selected topology metadata = %#v", got)
	}
	keeperNamespaces, err := openLinuxNamespaces(keeperPID)
	if err != nil {
		t.Fatal("tracked keeper does not own the selected namespaces")
	}
	if !keeperNamespaces.Correlates(session.namespace) {
		_ = keeperNamespaces.Close()
		t.Fatal("tracked keeper namespace identity does not match the retained topology")
	}
	if err := keeperNamespaces.Close(); err != nil {
		t.Fatal("close tracked keeper namespace probe")
	}
	childrenPath := filepath.Join("/proc", strconv.Itoa(keeperPID), "task", strconv.Itoa(keeperPID), "children")
	children, err := os.ReadFile(childrenPath)
	if err != nil {
		t.Fatal("inspect tracked keeper children")
	}
	if strings.TrimSpace(string(children)) != "" {
		t.Fatal("tracked keeper unexpectedly delegates namespace ownership to a child")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("exact mapping did not reach the owned loopback fixture")
	}
	handle, err := session.NamespaceHandle()
	if err != nil {
		t.Fatal(err)
	}
	if handle.Closed() {
		t.Fatal("owned namespace handle unexpectedly closed while topology active")
	}
	_ = handle.Close()

	stopStarted := time.Now()
	metadata, err := cleanupGuard.Stop()
	if err != nil {
		t.Fatalf("selected L7 Linux topology cleanup failed: %v", err)
	}
	if elapsed := time.Since(stopStarted); elapsed >= 2*time.Second {
		t.Fatal("selected L7 Linux topology cleanup did not promptly reap the tracked keeper")
	}
	if metadata.Status != StatusStopped {
		t.Fatalf("cleanup status = %q, want stopped", metadata.Status)
	}
	if !processDone(trackedKeeper) {
		t.Fatal("tracked keeper remained live after cleanup")
	}
	if !processDone(trackedMapper) {
		t.Fatal("tracked mapper remained live after cleanup")
	}
	if _, err := readProcessStartTime(keeperPID); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tracked keeper process identity remained after cleanup")
	}
	if _, err := readProcessStartTime(mapperPID); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tracked mapper process identity remained after cleanup")
	}
	if _, err := openLinuxNamespaces(keeperPID); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tracked keeper namespaces remained after cleanup")
	}
	if _, err := os.ReadFile(childrenPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tracked keeper task remained after cleanup")
	}
	if _, err := session.NamespaceHandle(); !errors.Is(err, ErrStopped) {
		t.Fatalf("namespace handle after cleanup error = %v, want ErrStopped", err)
	}
	if err := cleanupGuard.VerifyAbsent(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for openFDCount(t) != beforeFDs && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := openFDCount(t); after != beforeFDs {
		t.Fatalf("owned descriptor count after cleanup = %d, want baseline %d", after, beforeFDs)
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
