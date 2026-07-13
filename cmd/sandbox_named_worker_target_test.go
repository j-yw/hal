package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestResolveSandboxCommandExecutionTargetReusesNamedWorkerWithOneRegistryLoad(t *testing.T) {
	host := runSandboxSchedulerLeaseHost("worker-existing", "worker existing")
	existing := &sandbox.SandboxState{
		Name:     "named-existing-worker",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host:     cloneSandboxHost(host),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:    sandboxruntime.DriverRootlessPodman,
			RuntimeID: "existing-runtime",
			WorkerID:  host.ID,
		},
	}
	var loadCalls int

	target, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxName:    existing.Name,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			LoadContext:    "named worker sandbox",
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(name string) (*sandbox.SandboxState, error) {
				loadCalls++
				if name != existing.Name {
					t.Fatalf("loadSandbox name = %q, want %q", name, existing.Name)
				}
				return existing, nil
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				return []*sandbox.SandboxHost{host}, nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("legacy provisioning should not run for an existing named worker")
				return nil, nil
			},
		},
		sandboxCommandScheduledTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxName:    existing.Name,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("scheduler should not run for an existing named worker")
				return nil, nil
			},
			listLeases: func() ([]*sandbox.SandboxLease, error) {
				t.Fatal("lease listing should not run for an existing named worker")
				return nil, nil
			},
			acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
				t.Fatal("lease acquisition should not run for an existing named worker")
				return nil, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
	}
	if loadCalls != 1 {
		t.Fatalf("registry load calls = %d, want exactly 1", loadCalls)
	}
	if target == nil || target.Name != existing.Name || target.Runtime == nil || target.Runtime.RuntimeID != "existing-runtime" {
		t.Fatalf("resolved target = %#v, want existing named worker", target)
	}
	if target.Lease != nil {
		t.Fatalf("existing named worker lease = %#v, want unchanged lease policy", target.Lease)
	}
}

func TestResolveSandboxCommandExecutionTargetStopsOnNamedWorkerRegistryReadError(t *testing.T) {
	readErr := errors.New("registry checksum failed")
	name := "named-read-error"

	_, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeAuto,
			SandboxName:    name,
			SandboxHostID:  "worker-read-error",
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			LoadContext:    "worker sandbox",
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(requested string) (*sandbox.SandboxState, error) {
				if requested != name {
					t.Fatalf("loadSandbox name = %q, want %q", requested, name)
				}
				return nil, fmt.Errorf("read registry: %w", readErr)
			},
		},
		sandboxCommandScheduledTargetRequest{},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("scheduler should not run after registry read failure")
				return nil, fs.ErrNotExist
			},
		},
	)
	if !errors.Is(err, readErr) {
		t.Fatalf("resolve error = %v, want registry read cause", err)
	}
	for _, want := range []string{"load worker sandbox", name} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("resolve error = %q, want %q", err.Error(), want)
		}
	}
}
