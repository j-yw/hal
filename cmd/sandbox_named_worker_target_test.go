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

func TestResolveSandboxCommandExecutionTargetFreshNamedSSHMachineUsesLegacyProvisioning(t *testing.T) {
	name := "named-ssh-machine"
	provisioned := &sandbox.SandboxState{
		Name:     name,
		Provider: "digitalocean",
		Status:   sandbox.StatusRunning,
	}
	var loadCalls int
	var provisionCalls int

	target, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:             sandbox.SandboxLeasePurposeRun,
			SandboxName:         name,
			SandboxRuntime:      sandboxruntime.DriverSSHMachine,
			ProjectDir:          "/project",
			Branch:              "feature/named-ssh-machine",
			ProvisionRepository: "git@example.com:org/repo.git",
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(requested string) (*sandbox.SandboxState, error) {
				loadCalls++
				if requested != name {
					t.Fatalf("loadSandbox name = %q, want %q", requested, name)
				}
				return nil, fs.ErrNotExist
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("legacy named SSH-machine provisioning must not list hosts")
				return nil, nil
			},
			provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				provisionCalls++
				if req.Name != name || req.BranchName != "feature/named-ssh-machine" || req.Repo != "git@example.com:org/repo.git" {
					t.Fatalf("provision request = %#v, want exact named SSH-machine request", req)
				}
				return provisioned, nil
			},
		},
		sandboxCommandScheduledTargetRequest{
			SandboxName:    name,
			SandboxRuntime: sandboxruntime.DriverSSHMachine,
		},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("named SSH-machine provisioning must not invoke the scheduler")
				return nil, nil
			},
			listLeases: func() ([]*sandbox.SandboxLease, error) {
				t.Fatal("named SSH-machine provisioning must not list leases")
				return nil, nil
			},
			acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
				t.Fatal("named SSH-machine provisioning must not acquire a lease")
				return nil, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
	}
	if target != provisioned {
		t.Fatalf("resolved target = %#v, want provisioned target %#v", target, provisioned)
	}
	if loadCalls != 1 || provisionCalls != 1 {
		t.Fatalf("load/provision calls = %d/%d, want 1/1", loadCalls, provisionCalls)
	}
	if target.Provider == "local" {
		t.Fatalf("resolved provider = %q, must not synthesize local scheduled target", target.Provider)
	}
}

func TestResolveSandboxCommandExecutionTargetFreshNamedHostOnlyWorkerInfersRootlessRuntime(t *testing.T) {
	name := "named-host-only-worker"
	host := runSandboxSchedulerLeaseHost("worker-host-only", "worker host only")
	var hostListCalls int
	var leaseCalls int

	target, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:       sandbox.SandboxLeasePurposeAuto,
			SandboxName:   name,
			SandboxHostID: host.ID,
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				return nil, fs.ErrNotExist
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				hostListCalls++
				return []*sandbox.SandboxHost{host}, nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("host-only worker target must not use legacy provisioning")
				return nil, nil
			},
		},
		sandboxCommandScheduledTargetRequest{
			Purpose:       sandbox.SandboxLeasePurposeAuto,
			SandboxName:   name,
			SandboxHostID: host.ID,
			RunID:         "host-only-run",
		},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("scheduler must use the pinned host registry snapshot")
				return nil, nil
			},
			listLeases: func() ([]*sandbox.SandboxLease, error) {
				return nil, nil
			},
			now: func() time.Time {
				return time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
			},
			acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, _ time.Duration) (*sandbox.SandboxLease, error) {
				leaseCalls++
				if req.SandboxName != name || req.ResourceKey != "host:"+host.ID {
					t.Fatalf("lease request = %#v, want named host-only worker", req)
				}
				return &sandbox.SandboxLease{
					ID:          "host-only-lease",
					SandboxName: req.SandboxName,
					ResourceKey: req.ResourceKey,
					Purpose:     req.Purpose,
					RunID:       req.RunID,
					Status:      sandbox.SandboxLeaseStatusActive,
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
	}
	if hostListCalls != 1 || leaseCalls != 1 {
		t.Fatalf("host-list/lease calls = %d/%d, want 1/1", hostListCalls, leaseCalls)
	}
	if target == nil || target.Name != name || target.Provider != "local" {
		t.Fatalf("resolved target = %#v, want fresh named local worker target", target)
	}
	if target.Host == nil || target.Host.ID != host.ID || target.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("resolved host = %#v, want worker %q", target.Host, host.ID)
	}
	if target.Runtime == nil || target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || target.Runtime.WorkerID != host.ID {
		t.Fatalf("resolved runtime = %#v, want inferred rootless worker runtime", target.Runtime)
	}
	if target.Lease == nil || target.Lease.ID != "host-only-lease" {
		t.Fatalf("resolved lease = %#v, want acquired host-only lease", target.Lease)
	}
}

func TestResolveSandboxCommandExecutionTargetFreshNamedRootlessRejectsNonWorkerHostBeforeLease(t *testing.T) {
	name := "named-rootless-ssh-host"
	host := &sandbox.SandboxHost{
		ID:                "ssh-rootless-host",
		Name:              "ssh rootless host",
		Kind:              sandbox.SandboxHostKindSSH,
		SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		Health:            &sandbox.HostHealth{Status: "healthy"},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
	}

	_, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxName:    name,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				return nil, fs.ErrNotExist
			},
		},
		sandboxCommandScheduledTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxName:    name,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				return []*sandbox.SandboxHost{host}, nil
			},
			listLeases: func() ([]*sandbox.SandboxLease, error) {
				return nil, nil
			},
			now: func() time.Time {
				return time.Date(2026, 7, 13, 8, 5, 0, 0, time.UTC)
			},
			acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
				t.Fatal("non-worker rootless host must be rejected before lease acquisition")
				return nil, nil
			},
		},
	)
	if err == nil {
		t.Fatal("resolve error = nil, want non-worker rootless rejection")
	}
	for _, want := range []string{"runtime_unsupported", host.ID, sandboxruntime.DriverRootlessPodman} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("resolve error = %q, want %q", err.Error(), want)
		}
	}
}

func TestResolveSandboxCommandExecutionTargetFreshNamedHostOnlyNonWorkerPreservesSelectionError(t *testing.T) {
	name := "named-host-only-ssh"
	host := &sandbox.SandboxHost{
		ID:                "ssh-host-only",
		Name:              "ssh host only",
		Kind:              sandbox.SandboxHostKindSSH,
		SupportedRuntimes: []string{sandboxruntime.DriverSSHMachine},
		Health:            &sandbox.HostHealth{Status: "healthy"},
	}
	var hostListCalls int

	_, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:       sandbox.SandboxLeasePurposeRun,
			SandboxName:   name,
			SandboxHostID: host.ID,
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				return nil, fs.ErrNotExist
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				hostListCalls++
				return []*sandbox.SandboxHost{host}, nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("explicit non-worker host must not be ignored by legacy provisioning")
				return nil, nil
			},
		},
		sandboxCommandScheduledTargetRequest{},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("non-worker host-only target must not invoke scheduler")
				return nil, nil
			},
			acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
				t.Fatal("non-worker host-only target must not acquire lease")
				return nil, nil
			},
		},
	)
	if err == nil {
		t.Fatal("resolve error = nil, want explicit non-worker host provisioning rejection")
	}
	if hostListCalls != 1 {
		t.Fatalf("host list calls = %d, want pinned single read", hostListCalls)
	}
	for _, want := range []string{host.ID, "cannot be provisioned"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("resolve error = %q, want %q", err.Error(), want)
		}
	}
}

func TestResolveSandboxCommandExecutionTargetFreshNamedMicroVMRemainsUnsupported(t *testing.T) {
	name := "named-microvm-unsupported"
	host := &sandbox.SandboxHost{
		ID:                "worker-microvm-only",
		Name:              "worker microvm only",
		Kind:              sandbox.SandboxHostKindWorker,
		SupportedRuntimes: []string{sandboxruntime.DriverMicroVM},
		Health:            &sandbox.HostHealth{Status: "healthy"},
	}

	_, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeAuto,
			SandboxName:    name,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverMicroVM,
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				return nil, fs.ErrNotExist
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				return []*sandbox.SandboxHost{host}, nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("unsupported microVM target must not fall back to SSH provisioning")
				return nil, nil
			},
		},
		sandboxCommandScheduledTargetRequest{},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("fresh named microVM target must remain on selector rejection path")
				return nil, nil
			},
			acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
				t.Fatal("unsupported microVM target must not acquire a lease")
				return nil, nil
			},
		},
	)
	if err == nil {
		t.Fatal("resolve error = nil, want microVM unsupported rejection")
	}
	for _, want := range []string{name, "does not exist"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("resolve error = %q, want %q", err.Error(), want)
		}
	}
}
