//go:build linux

package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxTopologyOwnershipJournalIsBootBound(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	boundary := &execBoundary{}
	keeper, err := boundary.Start(context.Background(), ProcessSpec{Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = keeper.Terminate(ctx)
	}()
	store, err := newFileOwnershipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-boot-bound")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := lease.Record(context.Background(), keeper, nil, nil); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(lease.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	bootID, ok := raw["hostBootId"].(string)
	expectedBootIDBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	expectedBootID := strings.TrimSuffix(string(expectedBootIDBytes), "\n")
	if !ok || bootID != expectedBootID || string(expectedBootIDBytes) != bootID+"\n" {
		t.Fatalf("ownership journal = %s, want exact hostBootId", payload)
	}
}

func TestLinuxTopologyFileOwnershipRecoversExactSuppliedNamespace(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	boundary := &execBoundary{}
	keeper, err := boundary.Start(context.Background(), ProcessSpec{Role: ProcessRoleKeeper, Path: sleep, Args: []string{"30"}, OutputLimit: 1024})
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := boundary.Start(context.Background(), ProcessSpec{Role: ProcessRoleMapping, Path: sleep, Args: []string{"30"}, OutputLimit: 1024})
	if err != nil {
		terminateTestProcess(t, keeper)
		t.Fatal(err)
	}
	defer terminateTestProcess(t, keeper)
	defer terminateTestProcess(t, mapper)
	namespace, err := openRecordedTestNamespaces(keeper.PID())
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	store, err := newFileOwnershipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-file-recovery")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Record(context.Background(), keeper, mapper, namespace); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	recoveryStore, ok := any(store).(RecoveryOwnershipStore)
	if !ok {
		t.Fatal("file ownership store exposes no exact recovery claim")
	}
	recovered, err := recoveryStore.AcquireRecovery(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Lease.Release()
	defer recovered.Namespace.Close()
	if recovered.Keeper == nil || recovered.Mapper == nil || !recovered.Namespace.Correlates(namespace) {
		t.Fatalf("recovered authority = keeper %T mapper %T namespace %T", recovered.Keeper, recovered.Mapper, recovered.Namespace)
	}
	wrongUser, err := os.Open(filepath.Join("/proc", "self", "ns", "user"))
	if err != nil {
		t.Fatal(err)
	}
	wrongNet, err := os.Open(filepath.Join("/proc", "1", "ns", "net"))
	if err != nil {
		wrongUser.Close()
		t.Fatal(err)
	}
	wrong, err := NewNamespaceHandle(wrongUser, wrongNet)
	if err != nil {
		wrongUser.Close()
		wrongNet.Close()
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := recoveryStore.AcquireRecovery(context.Background(), RecoveryRequest{Identity: identity, Namespace: wrong}); !errors.Is(err, ErrTopologyCollision) {
		// The first exact claim intentionally retains the journal lock; a second
		// caller cannot inspect or mutate it, even with wrong namespace authority.
		t.Fatalf("concurrent wrong recovery = %v, want collision", err)
	}
}

func openRecordedTestNamespaces(pid int) (*NamespaceHandle, error) {
	user, err := os.Open(filepath.Join("/proc", fmtInt(pid), "ns", "user"))
	if err != nil {
		return nil, err
	}
	network, err := os.Open(filepath.Join("/proc", fmtInt(pid), "ns", "net"))
	if err != nil {
		user.Close()
		return nil, err
	}
	handle, err := NewNamespaceHandle(user, network)
	if err != nil {
		user.Close()
		network.Close()
	}
	return handle, err
}

func fmtInt(value int) string {
	return strconv.Itoa(value)
}

func terminateTestProcess(t *testing.T, process ProcessHandle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = process.Terminate(ctx)
}
