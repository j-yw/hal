//go:build linux && l7_linux_network_integration

package linuxtopology

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

	lifecycle, err := New(Config{
		Enabled: true,
		Tools: ToolPaths{
			Unshare: tool("unshare"),
			Pasta:   tool("pasta"),
			Nsenter: tool("nsenter"),
			IP:      tool("ip"),
			Keeper:  tool("sleep"),
		},
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
			ProxyEndpoint:      "127.0.0.1:43123",
			GuestProxyAddress:  "192.0.2.2",
			NamespaceInterface: "halpasta0",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	beforeFDs := openFDCount(t)
	session, err := lifecycle.Start(ctx, req)
	if err != nil {
		t.Fatalf("selected L7 Linux topology start failed: %v", err)
	}
	if got := session.Metadata(); got.Status != StatusActive || !got.Inspected {
		t.Fatalf("selected topology metadata = %#v", got)
	}
	handle, err := session.NamespaceHandle()
	if err != nil {
		t.Fatal(err)
	}
	if handle.Closed() {
		t.Fatal("owned namespace handle unexpectedly closed while topology active")
	}
	_ = handle.Close()

	metadata, err := lifecycle.Stop(context.Background(), req.Identity)
	if err != nil {
		t.Fatalf("selected L7 Linux topology cleanup failed: %v", err)
	}
	if metadata.Status != StatusStopped {
		t.Fatalf("cleanup status = %q, want stopped", metadata.Status)
	}
	if _, err := session.NamespaceHandle(); !errors.Is(err, ErrStopped) {
		t.Fatalf("namespace handle after cleanup error = %v, want ErrStopped", err)
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
