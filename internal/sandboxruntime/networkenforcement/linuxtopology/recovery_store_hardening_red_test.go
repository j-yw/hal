//go:build linux

package linuxtopology

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fileRecoveryFixture struct {
	store       *fileOwnershipStore
	identity    Identity
	namespace   *NamespaceHandle
	keeper      ProcessHandle
	mapper      ProcessHandle
	journalPath string
}

func newFileRecoveryFixture(t *testing.T) *fileRecoveryFixture {
	t.Helper()
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
	namespace, err := openRecordedTestNamespaces(keeper.PID())
	if err != nil {
		terminateTestProcess(t, mapper)
		terminateTestProcess(t, keeper)
		t.Fatal(err)
	}
	store, err := newFileOwnershipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity("topology-gen-hardening")
	lease, err := store.acquire(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Record(context.Background(), keeper, mapper, namespace); err != nil {
		_ = lease.Release()
		t.Fatal(err)
	}
	journalPath := lease.journalPath
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	fixture := &fileRecoveryFixture{store: store, identity: identity, namespace: namespace, keeper: keeper, mapper: mapper, journalPath: journalPath}
	t.Cleanup(func() {
		_ = namespace.Close()
		terminateTestProcess(t, mapper)
		terminateTestProcess(t, keeper)
	})
	return fixture
}

func (f *fileRecoveryFixture) recoveryStore(t *testing.T) RecoveryOwnershipStore {
	t.Helper()
	store, ok := any(f.store).(RecoveryOwnershipStore)
	if !ok {
		t.Fatal("file ownership store exposes no exact recovery claim")
	}
	return store
}

func (f *fileRecoveryFixture) rewriteJournal(t *testing.T, mutate func(map[string]any)) {
	t.Helper()
	payload, err := os.ReadFile(f.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	mutate(raw)
	payload, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateAtomic(f.journalPath, payload); err != nil {
		t.Fatal(err)
	}
}

func assertRecoveryRejectedAndRetained(t *testing.T, fixture *fileRecoveryFixture, identity Identity, namespace *NamespaceHandle) {
	t.Helper()
	recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
	if err == nil {
		if recovered.Namespace != nil {
			_ = recovered.Namespace.Close()
		}
		if recovered.Lease != nil {
			_ = recovered.Lease.Release()
		}
		t.Fatal("unsafe recovery unexpectedly succeeded")
	}
	if !errors.Is(err, ErrStaleTopologyUnverified) && !errors.Is(err, ErrIdentityMismatch) && !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("recovery error = %v, want sanitized fail-closed class", err)
	}
	if namespace == nil || namespace.Closed() {
		t.Fatal("failed recovery consumed caller-owned namespace")
	}
	if _, statErr := os.Lstat(fixture.journalPath); statErr != nil {
		t.Fatalf("failed recovery removed private journal: %v", statErr)
	}
}

func TestLinuxTopologyRecoveryRejectsReleasedLockWrongNamespace(t *testing.T) {
	fixture := newFileRecoveryFixture(t)
	wrong := newFakeNamespaces(t, nil).base
	if wrong.Correlates(fixture.namespace) {
		t.Fatal("wrong-namespace fixture accidentally correlates")
	}
	assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, wrong)
}

func TestLinuxTopologyRecoveryRejectsBootAndProcessIdentityMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "host boot", mutate: func(raw map[string]any) { raw["hostBootId"] = "00000000-0000-4000-8000-000000000000" }},
		{name: "keeper start time", mutate: func(raw map[string]any) { raw["keeper"].(map[string]any)["startTime"] = "1" }},
		{name: "mapper start time", mutate: func(raw map[string]any) { raw["mapper"].(map[string]any)["startTime"] = "1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			fixture.rewriteJournal(t, test.mutate)
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryRejectsExactZombieAndPermissionUncertainty(t *testing.T) {
	t.Run("zombie mapper", func(t *testing.T) {
		fixture := newFileRecoveryFixture(t)
		zombie, start := startDeterministicZombie(t)
		defer zombie.Wait()
		fixture.rewriteJournal(t, func(raw map[string]any) {
			raw["mapper"] = map[string]any{"pid": zombie.Process.Pid, "startTime": start}
		})
		assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
	})
	t.Run("foreign namespace permission or mismatch", func(t *testing.T) {
		fixture := newFileRecoveryFixture(t)
		start, err := readProcessStartTime(1)
		if err != nil {
			t.Fatal(err)
		}
		fixture.rewriteJournal(t, func(raw map[string]any) {
			raw["keeper"] = map[string]any{"pid": 1, "startTime": start}
		})
		assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		if _, err := os.Stat("/proc/1"); err != nil {
			t.Fatalf("recovery disturbed foreign process 1: %v", err)
		}
	})
}

func startDeterministicZombie(t *testing.T) (*exec.Cmd, string) {
	t.Helper()
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "read ignored <&3")
	command.ExtraFiles = []*os.File{gateRead}
	if err := command.Start(); err != nil {
		gateRead.Close()
		gateWrite.Close()
		t.Fatal(err)
	}
	gateRead.Close()
	start, err := readProcessStartTime(command.Process.Pid)
	if err != nil {
		gateWrite.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := gateWrite.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(command.Process.Pid), "stat"))
		if err != nil {
			_ = command.Wait()
			t.Fatalf("zombie disappeared before inspection: %v", err)
		}
		closing := strings.LastIndexByte(string(payload), ')')
		fields := strings.Fields(string(payload[closing+1:]))
		if len(fields) > 0 && fields[0] == "Z" {
			return command, start
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("child did not enter zombie state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLinuxTopologyRecoveryProcessExitRaceNeverAuthorizesReplacement(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		fixture := newFileRecoveryFixture(t)
		done := make(chan struct{})
		go func() {
			runtime.Gosched()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = fixture.mapper.Terminate(ctx)
			cancel()
			close(done)
		}()
		recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: fixture.identity, Namespace: fixture.namespace})
		<-done
		if err == nil {
			if recovered.Lease == nil || recovered.Namespace == nil || !recovered.Namespace.Correlates(fixture.namespace) {
				t.Fatalf("race recovery returned uncorrelated authority: %#v", recovered)
			}
			_ = recovered.Namespace.Close()
			_ = recovered.Lease.Release()
		} else if !errors.Is(err, ErrStaleTopologyUnverified) && !errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("race recovery leaked unstable outcome: %v", err)
		}
		if fixture.namespace.Closed() {
			t.Fatal("race recovery consumed caller namespace")
		}
	}
}

func TestLinuxTopologyRecoveryClosesEveryFailedClaimHandle(t *testing.T) {
	fixture := newFileRecoveryFixture(t)
	wrong := newFakeNamespaces(t, nil).base
	before := countOpenFileDescriptors(t)
	for range 32 {
		recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: fixture.identity, Namespace: wrong})
		if err == nil {
			if recovered.Namespace != nil {
				_ = recovered.Namespace.Close()
			}
			if recovered.Lease != nil {
				_ = recovered.Lease.Release()
			}
			t.Fatal("wrong namespace recovery succeeded")
		}
	}
	runtime.GC()
	after := countOpenFileDescriptors(t)
	if after > before {
		t.Fatalf("failed recovery leaked descriptors: before=%d after=%d", before, after)
	}
	if _, err := syscall.Getpgid(os.Getpid()); err != nil {
		t.Fatalf("process state changed during handle-close matrix: %v", err)
	}
}

func countOpenFileDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestLinuxTopologyRecoveryAcceptsDefinitelyAbsentHelpersWithRetainedNamespace(t *testing.T) {
	fixture := newFileRecoveryFixture(t)
	terminateTestProcess(t, fixture.mapper)
	terminateTestProcess(t, fixture.keeper)
	recovered, err := fixture.recoveryStore(t).AcquireRecovery(context.Background(), RecoveryRequest{Identity: fixture.identity, Namespace: fixture.namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Namespace.Close()
	defer recovered.Lease.Release()
	if recovered.Keeper != nil || recovered.Mapper != nil || recovered.Namespace == nil || !recovered.Namespace.Correlates(fixture.namespace) {
		t.Fatalf("absent recovery = keeper %T mapper %T namespace %T", recovered.Keeper, recovered.Mapper, recovered.Namespace)
	}
}

func TestLinuxTopologyFreshLifecycleRecoverStopProductionStoreMatrix(t *testing.T) {
	for _, test := range []struct {
		name       string
		stopKeeper bool
		stopMapper bool
		wantKeeper bool
		wantMapper bool
	}{
		{name: "live", wantKeeper: true, wantMapper: true},
		{name: "partial keeper only", stopMapper: true, wantKeeper: true},
		{name: "partial mapper only", stopKeeper: true, wantMapper: true},
		{name: "absent", stopKeeper: true, stopMapper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			keeperPID, mapperPID := fixture.keeper.PID(), fixture.mapper.PID()
			if test.stopKeeper {
				terminateTestProcess(t, fixture.keeper)
			}
			if test.stopMapper {
				terminateTestProcess(t, fixture.mapper)
			}
			lifecycle, _ := newSerializedRecoveryLifecycle(t, fixture.store)
			session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: fixture.identity, Namespace: fixture.namespace})
			if err != nil {
				t.Fatal(err)
			}
			if (session.keeper != nil) != test.wantKeeper || (session.mapper != nil) != test.wantMapper {
				t.Fatalf("recovered processes = keeper %T mapper %T", session.keeper, session.mapper)
			}
			metadata := session.Metadata()
			if metadata.Status != StatusRecoveryOnly || metadata.StructuralInspected || metadata.MappingReachable {
				t.Fatalf("recovered metadata = %#v", metadata)
			}
			owned := session.namespace
			stopped, err := lifecycle.Stop(context.Background(), fixture.identity)
			if err != nil || stopped.Status != StatusStopped {
				t.Fatalf("Stop(recovered) = %#v, %v", stopped, err)
			}
			if owned == nil || !owned.Closed() {
				t.Fatal("Stop did not close lifecycle-owned namespace duplicate")
			}
			if fixture.namespace.Closed() {
				t.Fatal("Stop consumed supervisor-owned namespace authority")
			}
			assertProcessPathAbsent(t, keeperPID)
			assertProcessPathAbsent(t, mapperPID)
			if _, err := os.Lstat(fixture.journalPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ownership journal remains after Stop: %v", err)
			}
			retired := filepath.Join(filepath.Dir(fixture.journalPath), "retired-"+fixture.identity.TopologyGenerationID)
			if info, err := os.Lstat(retired); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("retirement tombstone = %#v, %v", info, err)
			}
			if lease, err := fixture.store.acquire(context.Background(), fixture.identity); lease != nil || !errors.Is(err, ErrStaleGeneration) {
				t.Fatalf("retired generation claim = %T, %v", lease, err)
			}
			fresh := fixture.identity
			fresh.ExecutionID = "execution-after-recovery"
			fresh.ProxyGenerationID = "proxy-generation-after-recovery"
			fresh.TopologyGenerationID = "topology-gen-after-recovery"
			lease, err := fixture.store.acquire(context.Background(), fresh)
			if err != nil {
				t.Fatalf("ownership lock remained held: %v", err)
			}
			if err := lease.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertProcessPathAbsent(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, err := os.Stat(filepath.Join("/proc", fmtInt(pid)))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatalf("inspect process %d: %v", pid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d remained after recovered Stop", pid)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLinuxTopologyRecoveryRejectsIncompleteOrAmbiguousJournal(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]any)
		rewrite func([]byte) []byte
	}{
		{name: "missing mapper", mutate: func(raw map[string]any) { delete(raw, "mapper") }},
		{name: "mapping armed", mutate: func(raw map[string]any) {
			raw["mappingArmed"] = true
			raw["mappingCreator"] = raw["keeper"]
		}},
		{name: "malformed", rewrite: func([]byte) []byte { return []byte(`{"version":`) }},
		{name: "duplicate key", rewrite: func(payload []byte) []byte {
			marker := []byte(`"version":`)
			at := bytes.Index(payload, marker)
			if at < 0 {
				return payload
			}
			end := at + len(marker)
			for end < len(payload) && payload[end] >= '0' && payload[end] <= '9' {
				end++
			}
			return append(append(append([]byte(nil), payload[:end]...), []byte(`,"version":`)...), append(payload[at+len(marker):end], payload[end:]...)...)
		}},
		{name: "case variant", rewrite: func(payload []byte) []byte {
			return bytes.Replace(payload, []byte(`"version"`), []byte(`"Version"`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			if test.mutate != nil {
				fixture.rewriteJournal(t, test.mutate)
			} else {
				payload, err := os.ReadFile(fixture.journalPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := writePrivateAtomic(fixture.journalPath, test.rewrite(payload)); err != nil {
					t.Fatal(err)
				}
			}
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryRejectsStaleCompleteIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Identity)
	}{
		{name: "sandbox", mutate: func(identity *Identity) { identity.SandboxID = "sandbox-replaced" }},
		{name: "execution", mutate: func(identity *Identity) { identity.ExecutionID = "execution-replaced" }},
		{name: "worker", mutate: func(identity *Identity) { identity.WorkerID = "worker-replaced" }},
		{name: "runtime", mutate: func(identity *Identity) { identity.RuntimeID = "runtime-replaced" }},
		{name: "plan", mutate: func(identity *Identity) { identity.PlanID = "plan-replaced" }},
		{name: "policy", mutate: func(identity *Identity) { identity.PolicySnapshotID = "policy-replaced" }},
		{name: "proxy session", mutate: func(identity *Identity) { identity.ProxySessionID = "proxy-session-replaced" }},
		{name: "proxy generation", mutate: func(identity *Identity) { identity.ProxyGenerationID = "proxy-generation-replaced" }},
		{name: "topology generation", mutate: func(identity *Identity) { identity.TopologyGenerationID = "topology-gen-replaced" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			identity := fixture.identity
			test.mutate(&identity)
			assertRecoveryRejectedAndRetained(t, fixture, identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryRejectsIndependentUserOrNetworkNamespaceMismatch(t *testing.T) {
	for _, mismatch := range []string{"user", "network"} {
		t.Run(mismatch, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			user, err := os.Open(filepath.Join("/proc", fmtInt(fixture.keeper.PID()), "ns", "user"))
			if err != nil {
				t.Fatal(err)
			}
			network, err := os.Open(filepath.Join("/proc", fmtInt(fixture.keeper.PID()), "ns", "net"))
			if err != nil {
				user.Close()
				t.Fatal(err)
			}
			wrong, err := os.CreateTemp(t.TempDir(), mismatch+"-mismatch-")
			if err != nil {
				user.Close()
				network.Close()
				t.Fatal(err)
			}
			if mismatch == "user" {
				user.Close()
				user = wrong
			} else {
				network.Close()
				network = wrong
			}
			handle, err := NewNamespaceHandle(user, network)
			if err != nil {
				user.Close()
				network.Close()
				t.Fatal(err)
			}
			defer handle.Close()
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, handle)
		})
	}
}

func TestLinuxTopologyRecoveryStrictJournalFieldMatrix(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]any)
		rewrite func([]byte) []byte
	}{
		{name: "missing version", mutate: func(raw map[string]any) { delete(raw, "version") }},
		{name: "missing boot", mutate: func(raw map[string]any) { delete(raw, "hostBootId") }},
		{name: "missing identity", mutate: func(raw map[string]any) { delete(raw, "identity") }},
		{name: "missing keeper", mutate: func(raw map[string]any) { delete(raw, "keeper") }},
		{name: "missing mapper", mutate: func(raw map[string]any) { delete(raw, "mapper") }},
		{name: "missing namespace", mutate: func(raw map[string]any) { delete(raw, "namespace") }},
		{name: "unknown top level", mutate: func(raw map[string]any) { raw["endpoint"] = "private.example" }},
		{name: "unknown identity", mutate: func(raw map[string]any) { raw["identity"].(map[string]any)["pid"] = 42 }},
		{name: "unknown keeper", mutate: func(raw map[string]any) { raw["keeper"].(map[string]any)["path"] = "/private" }},
		{name: "unknown namespace", mutate: func(raw map[string]any) { raw["namespace"].(map[string]any)["fd"] = 9 }},
		{name: "stray creator", mutate: func(raw map[string]any) { raw["mappingCreator"] = raw["keeper"] }},
		{name: "trailing object", rewrite: func(payload []byte) []byte { return append(payload, []byte(`{}`)...) }},
		{name: "nested duplicate keeper pid", rewrite: func(payload []byte) []byte { return duplicateFirstJSONField(payload, "pid") }},
		{name: "nested duplicate identity", rewrite: func(payload []byte) []byte { return duplicateFirstJSONField(payload, "sandboxId") }},
		{name: "nested case variant", rewrite: func(payload []byte) []byte {
			return bytes.Replace(payload, []byte(`"startTime"`), []byte(`"StartTime"`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			if test.mutate != nil {
				fixture.rewriteJournal(t, test.mutate)
			} else {
				payload, err := os.ReadFile(fixture.journalPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := writePrivateAtomic(fixture.journalPath, test.rewrite(payload)); err != nil {
					t.Fatal(err)
				}
			}
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func duplicateFirstJSONField(payload []byte, field string) []byte {
	marker := []byte(`"` + field + `":`)
	at := bytes.Index(payload, marker)
	if at < 0 {
		return payload
	}
	valueStart := at + len(marker)
	valueEnd := valueStart
	if valueEnd < len(payload) && payload[valueEnd] == '"' {
		valueEnd++
		for valueEnd < len(payload) && payload[valueEnd] != '"' {
			valueEnd++
		}
		if valueEnd < len(payload) {
			valueEnd++
		}
	} else {
		for valueEnd < len(payload) && payload[valueEnd] >= '0' && payload[valueEnd] <= '9' {
			valueEnd++
		}
	}
	duplicate := append(append([]byte(nil), marker...), payload[valueStart:valueEnd]...)
	result := append([]byte(nil), payload[:valueEnd]...)
	result = append(result, ',')
	result = append(result, duplicate...)
	return append(result, payload[valueEnd:]...)
}

func TestLinuxTopologyRecoveryRejectsUnsafeJournalFile(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *fileRecoveryFixture)
	}{
		{name: "mode", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			if err := os.Chmod(fixture.journalPath, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			payload, err := os.ReadFile(fixture.journalPath)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(filepath.Dir(filepath.Dir(fixture.journalPath)), "outside.json")
			if err := os.WriteFile(target, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fixture.journalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, fixture.journalPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonregular", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			if err := os.Remove(fixture.journalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(fixture.journalPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "multiple links", mutate: func(t *testing.T, fixture *fileRecoveryFixture) {
			outside := filepath.Join(filepath.Dir(filepath.Dir(fixture.journalPath)), "journal-hardlink")
			if err := os.Link(fixture.journalPath, outside); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			test.mutate(t, fixture)
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
}

func TestLinuxTopologyRecoveryRejectsRootAndSandboxAncestorReplacement(t *testing.T) {
	for _, ancestor := range []string{"root", "sandbox"} {
		t.Run(ancestor, func(t *testing.T) {
			fixture := newFileRecoveryFixture(t)
			var path string
			if ancestor == "root" {
				path = fixture.store.root
			} else {
				path = filepath.Dir(fixture.journalPath)
			}
			real := path + "-replaced"
			if err := os.Rename(path, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.Remove(path)
				_ = os.Rename(real, path)
			})
			assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
		})
	}
	t.Run("fresh store through root symlink", func(t *testing.T) {
		fixture := newFileRecoveryFixture(t)
		link := fixture.store.root + "-link"
		if err := os.Symlink(fixture.store.root, link); err != nil {
			t.Fatal(err)
		}
		store, err := newFileOwnershipStore(link)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store = store
		assertRecoveryRejectedAndRetained(t, fixture, fixture.identity, fixture.namespace)
	})
}

func TestLinuxTopologyRecoverySourceRetainsPrivateOwnerAndPIDFDGuards(t *testing.T) {
	payload, err := os.ReadFile("ownership_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"AcquireRecovery", "stat.Uid != uint32(os.Geteuid())", "stat.Nlink != 1", "syscall.O_NOFOLLOW",
		"sysPIDFDOpen", "readProcessStartTime", "recordedNamespaceMatches", "HostBootID", "DisallowUnknownFields",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("production recovery source lacks %q", required)
		}
	}
}

type serializedRecoveryStore struct {
	base           *memoryOwnershipStore
	entered        chan struct{}
	release        chan struct{}
	once           sync.Once
	mu             sync.Mutex
	recoveries     int
	blockedSandbox string
}

func newSerializedRecoveryStore() *serializedRecoveryStore {
	return &serializedRecoveryStore{base: newMemoryOwnershipStore(), entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *serializedRecoveryStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	return s.base.Acquire(ctx, identity)
}

func (s *serializedRecoveryStore) AcquireRecovery(ctx context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
	s.mu.Lock()
	s.recoveries++
	s.mu.Unlock()
	if s.blockedSandbox == "" || s.blockedSandbox == request.Identity.SandboxID {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return RecoveredOwnership{}, ctx.Err()
		}
	}
	lease, err := s.base.Acquire(ctx, request.Identity)
	if err != nil {
		return RecoveredOwnership{}, err
	}
	namespace, err := request.Namespace.Duplicate()
	if err != nil {
		_ = lease.Release()
		return RecoveredOwnership{}, err
	}
	return RecoveredOwnership{Lease: lease, Namespace: namespace}, nil
}

func TestLinuxTopologyStartFirstRejectsRecoveryWithoutClaim(t *testing.T) {
	store := newSerializedRecoveryStore()
	close(store.release)
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	request := testRequest("topology-gen-start-first-recovery")
	started, err := lifecycle.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: request.Identity, Namespace: namespace}); recovered != nil || err == nil {
		t.Fatalf("Recover(after Start) = %T, %v", recovered, err)
	}
	if store.count() != 0 {
		t.Fatalf("Recover after live Start reached durable recovery store %d times", store.count())
	}
	if namespace.Closed() {
		t.Fatal("Recover after Start consumed caller namespace")
	}
	if _, err := lifecycle.Stop(context.Background(), started.identity); err != nil {
		t.Fatal(err)
	}
}

func (s *serializedRecoveryStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveries
}

func newSerializedRecoveryLifecycle(t *testing.T, store OwnershipStore) (*Lifecycle, *NamespaceHandle) {
	t.Helper()
	starter := newFakeStarter()
	namespaces := newFakeNamespaces(t, &starter.events)
	lifecycle, err := New(Config{Enabled: true, Tools: testTools(), Starter: starter,
		Runner: &fakeRunner{output: goodLinkJSON()}, OpenNamespaces: namespaces.Open,
		Reachability: &fakeReachabilityProber{}, Ownership: store,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10})
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := namespaces.base.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = namespace.Close() })
	return lifecycle, namespace
}

func TestLinuxTopologySerializesStartAgainstRecovery(t *testing.T) {
	store := newSerializedRecoveryStore()
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-serialized-start")
	recovered := make(chan error, 1)
	go func() {
		_, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
		recovered <- err
	}()
	select {
	case <-store.entered:
	case err := <-recovered:
		t.Fatalf("Recover returned before ownership claim: %v", err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Recover did not enter ownership claim")
	}
	started := make(chan error, 1)
	go func() {
		request := testRequest(identity.TopologyGenerationID)
		_, err := lifecycle.Start(context.Background(), request)
		started <- err
	}()
	select {
	case err := <-started:
		t.Fatalf("Start bypassed same-sandbox recovery: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(store.release)
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	if err := <-started; err == nil {
		t.Fatal("Start replaced recovered cleanup authority")
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

func TestLinuxTopologySerializesAndCoalescesExactRecovery(t *testing.T) {
	store := newSerializedRecoveryStore()
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-serialized-recover")
	type result struct {
		session *Session
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
			results <- result{session: session, err: err}
		}()
	}
	select {
	case <-store.entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Recover did not enter ownership claim")
	}
	close(store.release)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.session == nil || first.session != second.session {
		t.Fatalf("coalesced recovery = (%T,%v) (%T,%v)", first.session, first.err, second.session, second.err)
	}
	if store.count() != 1 {
		t.Fatalf("durable recovery claims = %d, want one", store.count())
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

func TestLinuxTopologyRecoveryNeverCoalescesMismatchedIdentityOrNamespace(t *testing.T) {
	store := newSerializedRecoveryStore()
	close(store.release)
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-no-unsafe-coalesce")
	first, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity := identity
	wrongIdentity.ExecutionID = "execution-no-coalesce"
	wrongNamespace := newFakeNamespaces(t, nil).base
	for _, request := range []RecoveryRequest{
		{Identity: wrongIdentity, Namespace: namespace},
		{Identity: identity, Namespace: wrongNamespace},
	} {
		if session, err := lifecycle.Recover(context.Background(), request); session != nil || err == nil {
			t.Fatalf("unsafe coalesced Recover = %T, %v", session, err)
		}
		if request.Namespace.Closed() {
			t.Fatal("noncoalesced recovery consumed caller namespace")
		}
	}
	if store.count() != 1 {
		t.Fatalf("mismatched recovery reached store: claims=%d", store.count())
	}
	if first.Metadata().Status != StatusRecoveryOnly {
		t.Fatalf("first recovery metadata changed: %#v", first.Metadata())
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

func TestLinuxTopologyRecoveryDoesNotBlockIndependentSandbox(t *testing.T) {
	firstIdentity := testIdentity("topology-gen-independent-recovery-a")
	firstIdentity.SandboxID = "sandbox-recovery-a"
	store := newSerializedRecoveryStore()
	store.blockedSandbox = firstIdentity.SandboxID
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	firstResult := make(chan error, 1)
	go func() {
		_, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: firstIdentity, Namespace: namespace})
		firstResult <- err
	}()
	select {
	case <-store.entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first recovery did not block at ownership claim")
	}
	secondIdentity := testIdentity("topology-gen-independent-recovery-b")
	secondIdentity.SandboxID = "sandbox-recovery-b"
	secondIdentity.ExecutionID = "execution-recovery-b"
	secondIdentity.ProxyGenerationID = "proxy-generation-recovery-b"
	second, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: secondIdentity, Namespace: namespace})
	if err != nil || second == nil {
		close(store.release)
		t.Fatalf("independent recovery = %T, %v", second, err)
	}
	close(store.release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	_, _ = lifecycle.Stop(context.Background(), firstIdentity)
	_, _ = lifecycle.Stop(context.Background(), secondIdentity)
}

func TestLinuxTopologyCanceledRecoveryWaiterCannotCoalesce(t *testing.T) {
	store := newSerializedRecoveryStore()
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	identity := testIdentity("topology-gen-canceled-waiter")
	firstResult := make(chan error, 1)
	go func() {
		_, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: namespace})
		firstResult <- err
	}()
	select {
	case <-store.entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first recovery did not enter claim")
	}
	waiterContext, cancel := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := lifecycle.Recover(waiterContext, RecoveryRequest{Identity: identity, Namespace: namespace})
		waiterResult <- err
	}()
	cancel()
	close(store.release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiterResult:
		if err == nil {
			t.Fatal("canceled recovery waiter coalesced live authority")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("canceled recovery waiter remained blocked")
	}
	if namespace.Closed() {
		t.Fatal("canceled waiter consumed caller namespace")
	}
	_, _ = lifecycle.Stop(context.Background(), identity)
}

type typedNilRecoveryStore struct{}

func (*typedNilRecoveryStore) Acquire(context.Context, Identity) (OwnershipLease, error) {
	panic("typed-nil ownership store called")
}
func (*typedNilRecoveryStore) AcquireRecovery(context.Context, RecoveryRequest) (RecoveredOwnership, error) {
	panic("typed-nil recovery store called")
}

func TestLinuxTopologyRecoverRejectsTypedNilStoreAndPreservesCallerNamespace(t *testing.T) {
	var store *typedNilRecoveryStore
	lifecycle, namespace := newSerializedRecoveryLifecycle(t, store)
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Recover panicked through typed-nil store: %v", recovered)
		}
	}()
	if session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: testIdentity("topology-gen-typed-nil"), Namespace: namespace}); session != nil || !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("Recover(typed nil) = %T, %v", session, err)
	}
	if namespace.Closed() {
		t.Fatal("typed-nil failure consumed caller namespace")
	}
}
