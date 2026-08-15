package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestSandboxLeaseRefContractIncludesOnlySafeAuditFields(t *testing.T) {
	acquiredAt := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	ref := sandbox.SandboxLeaseRef{
		ID:            "lease-123",
		HostID:        "host-123",
		HostName:      "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		ResourceKey:   "host:host-123",
		Holder:        "unsafe-holder-token",
		Purpose:       sandbox.SandboxLeasePurposeRun,
		RunID:         "exec-123",
		AcquiredAt:    acquiredAt,
		ExpiresAt:     acquiredAt.Add(30 * time.Minute),
	}

	assertSafeLeaseJSONObject(t, ref, "run")
}

func TestSandboxLeaseRefContractPersistsOnRunAutoAndFactoryMetadata(t *testing.T) {
	acquiredAt := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	target := &sandbox.SandboxState{
		ID:       "sandbox-123",
		Name:     "scheduled-target",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "host-123",
			Name:     "worker-a",
			Kind:     sandbox.SandboxHostKindWorker,
			Endpoint: "unix:///tmp/private/worker.sock",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-123",
			Image:          "localhost/hal-test:latest",
			WorkerID:       "worker-123",
		},
		Lease: &sandbox.SandboxLeaseRef{
			ID:            "lease-123",
			HostID:        "host-123",
			HostName:      "worker-a",
			RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
			ResourceKey:   "host:host-123",
			Holder:        "unsafe-holder-token",
			Purpose:       sandbox.SandboxLeasePurposeRun,
			RunID:         "exec-run",
			AcquiredAt:    acquiredAt,
			ExpiresAt:     acquiredAt.Add(30 * time.Minute),
		},
	}

	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:   "exec-run",
		SandboxName:   target.Name,
		ProjectDir:    "/tmp/private/repo",
		WorkDir:       "/workspace",
		RemoteCommand: []string{"hal", "run"},
		Security:      runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, acquiredAt, nil, target); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest, err := runStore.LoadManifest("exec-run")
	if err != nil {
		t.Fatalf("LoadManifest(run) error = %v", err)
	}
	assertSafeLeaseJSONObject(t, runManifest.Lease, "run")

	autoStore := newPrivateSandboxExecutionTestStore(t)
	target.Lease.Purpose = sandbox.SandboxLeasePurposeAuto
	target.Lease.RunID = "exec-auto"
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID:   "exec-auto",
		SandboxName:   target.Name,
		ProjectDir:    "/tmp/private/repo",
		WorkDir:       "/workspace",
		RemoteCommand: []string{"hal", "auto"},
		Security:      runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, acquiredAt, nil, target); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest, err := autoStore.LoadManifest("exec-auto")
	if err != nil {
		t.Fatalf("LoadManifest(auto) error = %v", err)
	}
	assertSafeLeaseJSONObject(t, autoManifest.Lease, "auto")

	target.Lease.Purpose = sandbox.SandboxLeasePurposeFactory
	target.Lease.RunID = "run-factory"
	_, factoryMetadata := factorySandboxMetadataFromState(target)
	if factoryMetadata == nil {
		t.Fatal("factorySandboxMetadataFromState() = nil")
	}
	assertSafeLeaseJSONObject(t, factoryMetadata.Lease, "factory")
}

func assertSafeLeaseJSONObject(t *testing.T, value any, purpose string) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(lease) error = %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"unsafe-holder-token",
		"unix:///tmp/private/worker.sock",
		"/tmp/private/repo",
		"git@github.com",
		"credential",
		"providerSecret",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("lease metadata leaked %q: %s", forbidden, payload)
		}
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(lease) error = %v", err)
	}
	assertLeaseJSONKeys(t, raw, []string{
		"id", "hostId", "hostName", "runtimeDriver", "resourceKey",
		"purpose", "runId", "acquiredAt", "expiresAt",
	})
	for _, forbiddenKey := range []string{
		"holder", "endpoint", "hostname", "path", "repo", "token", "secret", "credential",
		"providerCredentials", "bundlePath", "tempPath",
	} {
		if _, ok := raw[forbiddenKey]; ok {
			t.Fatalf("lease metadata serialized forbidden key %q: %#v", forbiddenKey, raw)
		}
	}
	if raw["id"] != "lease-123" {
		t.Fatalf("lease.id = %#v, want lease-123", raw["id"])
	}
	if raw["hostId"] != "host-123" || raw["hostName"] != "worker-a" {
		t.Fatalf("lease host identity = %#v/%#v, want host-123/worker-a", raw["hostId"], raw["hostName"])
	}
	if raw["runtimeDriver"] != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("lease.runtimeDriver = %#v, want rootless_podman", raw["runtimeDriver"])
	}
	if raw["purpose"] != purpose {
		t.Fatalf("lease.purpose = %#v, want %q", raw["purpose"], purpose)
	}
	if raw["acquiredAt"] != "2026-07-01T10:00:00Z" {
		t.Fatalf("lease.acquiredAt = %#v, want 2026-07-01T10:00:00Z", raw["acquiredAt"])
	}
	if raw["expiresAt"] != "2026-07-01T10:30:00Z" {
		t.Fatalf("lease.expiresAt = %#v, want 2026-07-01T10:30:00Z", raw["expiresAt"])
	}
}

func assertLeaseJSONKeys(t *testing.T, raw map[string]any, want []string) {
	t.Helper()
	if len(raw) != len(want) {
		t.Fatalf("lease keys = %#v, want exactly %v", raw, want)
	}
	for _, key := range want {
		if _, ok := raw[key]; !ok {
			t.Fatalf("lease missing key %q in %#v", key, raw)
		}
	}
}
