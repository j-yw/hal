package cmd

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestResolveSandboxCommandExecutionTargetNamedSSHMachinePreservesSelectorContract(t *testing.T) {
	host := sandboxExecutionRouteHost("ssh-selector", sandbox.SandboxHostKindSSH, sandboxruntime.DriverSSHMachine)
	name := "named-ssh-selector"
	provisionErr := errors.New("cloud create failed")

	tests := []struct {
		name                 string
		purpose              string
		strict               bool
		listErr              error
		provisionErr         error
		wrapProvisionFailure bool
		wantErr              string
		wantProvisionCalls   int
		wantMetadata         bool
		wantWrappedProvision bool
	}{
		{
			name:               "applies selected host and runtime metadata",
			wantProvisionCalls: 1,
			wantMetadata:       true,
		},
		{
			name:               "strict readiness blocks before provisioning",
			strict:             true,
			wantErr:            "does not exist",
			wantProvisionCalls: 0,
		},
		{
			name:               "selection error stops provisioning",
			listErr:            errors.New("host registry corrupt"),
			wantErr:            "list cached sandbox hosts",
			wantProvisionCalls: 0,
		},
		{
			name:                 "factory provision failure remains wrapped",
			purpose:              sandbox.SandboxLeasePurposeFactory,
			provisionErr:         provisionErr,
			wrapProvisionFailure: true,
			wantErr:              provisionErr.Error(),
			wantProvisionCalls:   1,
			wantWrappedProvision: true,
		},
		{
			name:               "factory explicit target keeps strict gate exception",
			purpose:            sandbox.SandboxLeasePurposeFactory,
			strict:             true,
			wantProvisionCalls: 1,
			wantMetadata:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var loadCalls int
			var hostListCalls int
			var provisionCalls int
			partial := &sandbox.SandboxState{Name: name, Provider: "digitalocean", Status: sandbox.StatusStopped}
			gateMode := sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode("")
			if tt.strict {
				gateMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
			}
			purpose := tt.purpose
			if purpose == "" {
				purpose = sandbox.SandboxLeasePurposeRun
			}

			target, err := resolveSandboxCommandExecutionTarget(
				context.Background(),
				sandboxCommandTargetRequest{
					Purpose:                   purpose,
					SandboxName:               name,
					SandboxRuntime:            sandboxruntime.DriverSSHMachine,
					SecurityReadinessGateMode: gateMode,
					Branch:                    "feature/named-ssh-selector",
					ProvisionRepository:       "git@example.com:org/repo.git",
					WrapProvisionFailure:      tt.wrapProvisionFailure,
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
						hostListCalls++
						if tt.listErr != nil {
							return nil, tt.listErr
						}
						return []*sandbox.SandboxHost{host}, nil
					},
					provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
						provisionCalls++
						return partial, tt.provisionErr
					},
				},
				sandboxCommandScheduledTargetRequest{},
				sandboxCommandScheduledTargetDeps{
					listHosts: func() ([]*sandbox.SandboxHost, error) {
						t.Fatal("named SSH-machine request must not invoke scheduler")
						return nil, nil
					},
					acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
						t.Fatal("named SSH-machine request must not acquire lease")
						return nil, nil
					},
				},
			)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("resolve error = %v, want %q", err, tt.wantErr)
			}
			if hostListCalls != 1 {
				t.Fatalf("host list calls = %d, want 1 selector read", hostListCalls)
			}
			if loadCalls != 1 {
				t.Fatalf("sandbox registry load calls = %d, want 1 pinned read", loadCalls)
			}
			if provisionCalls != tt.wantProvisionCalls {
				t.Fatalf("provision calls = %d, want %d", provisionCalls, tt.wantProvisionCalls)
			}
			if tt.wantMetadata {
				if target == nil || target.Host == nil || target.Host.ID != host.ID {
					t.Fatalf("resolved host = %#v, want selected SSH host", target)
				}
				if target.Runtime == nil || target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
					t.Fatalf("resolved runtime = %#v, want ssh_machine metadata", target.Runtime)
				}
			}
			if tt.wantWrappedProvision {
				phaseErr, ok := sandboxexec.AsPhaseError(err)
				if !ok || phaseErr.Phase != sandboxexec.PhaseProvisionTarget || phaseErr.Target != partial || !errors.Is(err, provisionErr) {
					t.Fatalf("wrapped error = %#v, want provision phase with partial target", err)
				}
			}
		})
	}
}

func TestResolveSandboxCommandExecutionTargetUnnamedConstraintRouteMatrix(t *testing.T) {
	worker := sandboxExecutionRouteHost("worker-route", sandbox.SandboxHostKindWorker, sandboxruntime.DriverRootlessPodman)
	ssh := sandboxExecutionRouteHost("ssh-route", sandbox.SandboxHostKindSSH, sandboxruntime.DriverSSHMachine)
	sshRootless := sandboxExecutionRouteHost("ssh-rootless-route", sandbox.SandboxHostKindSSH, sandboxruntime.DriverRootlessPodman)
	microVMWorker := sandboxExecutionRouteHost("microvm-route", sandbox.SandboxHostKindWorker, sandboxruntime.DriverMicroVM)
	invalidEndpointWorker := sandboxExecutionRouteHost("worker-invalid-endpoint", sandbox.SandboxHostKindWorker, sandboxruntime.DriverRootlessPodman)
	invalidEndpointWorker.Endpoint = "https://worker.invalid.example.test/private"
	unhealthyWorker := sandboxExecutionRouteHost("worker-unhealthy", sandbox.SandboxHostKindWorker, sandboxruntime.DriverRootlessPodman)
	unhealthyWorker.Health.Status = "unhealthy"

	tests := []struct {
		name            string
		hostID          string
		runtime         string
		hosts           []*sandbox.SandboxHost
		wantErr         string
		wantScheduled   bool
		wantProvisioned bool
		wantRuntime     string
	}{
		{
			name:          "host-only worker infers rootless",
			hostID:        worker.ID,
			hosts:         []*sandbox.SandboxHost{worker},
			wantScheduled: true,
			wantRuntime:   sandboxruntime.DriverRootlessPodman,
		},
		{
			name:    "host-only nonworker preserves selector error",
			hostID:  ssh.ID,
			hosts:   []*sandbox.SandboxHost{ssh},
			wantErr: "cannot be provisioned",
		},
		{
			name:            "explicit ssh machine preserves legacy provisioning",
			runtime:         sandboxruntime.DriverSSHMachine,
			hosts:           []*sandbox.SandboxHost{ssh},
			wantProvisioned: true,
			wantRuntime:     sandboxruntime.DriverSSHMachine,
		},
		{
			name:    "explicit rootless rejects nonworker",
			hostID:  sshRootless.ID,
			runtime: sandboxruntime.DriverRootlessPodman,
			hosts:   []*sandbox.SandboxHost{sshRootless},
			wantErr: "cannot be provisioned",
		},
		{
			name:    "microvm stays on selector rejection path",
			hostID:  microVMWorker.ID,
			runtime: sandboxruntime.DriverMicroVM,
			hosts:   []*sandbox.SandboxHost{microVMWorker},
			wantErr: "runtime_unsupported",
		},
		{
			name:    "worker endpoint is validated before lease",
			hostID:  invalidEndpointWorker.ID,
			runtime: sandboxruntime.DriverRootlessPodman,
			hosts:   []*sandbox.SandboxHost{invalidEndpointWorker},
			wantErr: "worker_endpoint_invalid",
		},
		{
			name:    "worker health is validated before lease",
			hostID:  unhealthyWorker.ID,
			runtime: sandboxruntime.DriverRootlessPodman,
			hosts:   []*sandbox.SandboxHost{unhealthyWorker},
			wantErr: "not healthy",
		},
		{
			name:          "runtime-only rootless selects worker not nonworker",
			runtime:       sandboxruntime.DriverRootlessPodman,
			hosts:         []*sandbox.SandboxHost{sshRootless, worker},
			wantScheduled: true,
			wantRuntime:   sandboxruntime.DriverRootlessPodman,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hostListCalls int
			var leaseCalls int
			var provisionCalls int
			listHosts := func() ([]*sandbox.SandboxHost, error) {
				hostListCalls++
				return tt.hosts, nil
			}
			target, err := resolveSandboxCommandExecutionTarget(
				context.Background(),
				sandboxCommandTargetRequest{
					Purpose:             sandbox.SandboxLeasePurposeRun,
					SandboxHostID:       tt.hostID,
					SandboxRuntime:      tt.runtime,
					Branch:              "feature/route-matrix",
					ProvisionRepository: "git@example.com:org/repo.git",
				},
				sandboxCommandTargetDeps{
					loadSandbox: func(string) (*sandbox.SandboxState, error) {
						return nil, fs.ErrNotExist
					},
					listHosts: listHosts,
					provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
						provisionCalls++
						return &sandbox.SandboxState{Name: req.Name, Provider: "digitalocean", Status: sandbox.StatusStopped}, nil
					},
				},
				sandboxCommandScheduledTargetRequest{
					Purpose:        sandbox.SandboxLeasePurposeRun,
					SandboxHostID:  tt.hostID,
					SandboxRuntime: tt.runtime,
					Branch:         "feature/route-matrix",
					RunID:          "route-matrix-run",
				},
				sandboxCommandScheduledTargetDeps{
					listHosts: listHosts,
					listLeases: func() ([]*sandbox.SandboxLease, error) {
						return nil, nil
					},
					now: func() time.Time {
						return time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
					},
					acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, _ time.Duration) (*sandbox.SandboxLease, error) {
						leaseCalls++
						return &sandbox.SandboxLease{ID: "route-lease", SandboxName: req.SandboxName, ResourceKey: req.ResourceKey, Status: sandbox.SandboxLeaseStatusActive}, nil
					},
				},
			)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("resolve error = %v, want %q", err, tt.wantErr)
			}
			if hostListCalls != 1 {
				t.Fatalf("host list calls = %d, want 1 pinned read", hostListCalls)
			}
			if got := leaseCalls == 1; got != tt.wantScheduled {
				t.Fatalf("lease calls = %d, want scheduled=%v", leaseCalls, tt.wantScheduled)
			}
			if got := provisionCalls == 1; got != tt.wantProvisioned {
				t.Fatalf("provision calls = %d, want provisioned=%v", provisionCalls, tt.wantProvisioned)
			}
			if tt.wantErr != "" {
				if leaseCalls != 0 || provisionCalls != 0 {
					t.Fatalf("error route lease/provision calls = %d/%d, want 0/0", leaseCalls, provisionCalls)
				}
				return
			}
			if target == nil {
				t.Fatal("resolved target = nil")
			}
			if tt.wantScheduled && target.Provider != "local" {
				t.Fatalf("scheduled provider = %q, want local worker state", target.Provider)
			}
			if tt.wantProvisioned && target.Provider != "digitalocean" {
				t.Fatalf("legacy provider = %q, want digitalocean", target.Provider)
			}
			if tt.wantRuntime != "" && (target.Runtime == nil || target.Runtime.Driver != tt.wantRuntime) {
				t.Fatalf("resolved runtime = %#v, want %q", target.Runtime, tt.wantRuntime)
			}
		})
	}
}

func sandboxExecutionRouteHost(id, kind, runtimeDriver string) *sandbox.SandboxHost {
	host := &sandbox.SandboxHost{
		ID:       id,
		Name:     strings.ReplaceAll(id, "-", " "),
		Kind:     kind,
		Health:   &sandbox.HostHealth{Status: "healthy"},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
	}
	if runtimeDriver != "" {
		host.SupportedRuntimes = []string{runtimeDriver}
	}
	if kind == sandbox.SandboxHostKindWorker {
		host.Endpoint = workerSafeUnixEndpoint()
		host.Security = workerRootlessHostSecurity()
	}
	return host
}
