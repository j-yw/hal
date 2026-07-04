package sandboxworker

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestServiceStatusReportsStateAndRegisteredDrivers(t *testing.T) {
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: RuntimeDriverSSHMachine},
		&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman},
	)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: "/tmp/hal-sandboxworker.sock",
		Registry:   registry,
		Health: WorkerHealth{
			Status:  HealthStatusDegraded,
			Message: "warming runtime driver cache",
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 4,
			ActiveSandboxes:        1,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	status := service.Status()
	if err := status.Validate(); err != nil {
		t.Fatalf("Status().Validate() error: %v", err)
	}
	if status.ProtocolVersion != ProtocolVersion {
		t.Fatalf("status protocolVersion = %q, want %q", status.ProtocolVersion, ProtocolVersion)
	}
	if status.WorkerID != "worker-001" {
		t.Fatalf("status workerId = %q, want worker-001", status.WorkerID)
	}
	if status.HostKind != HostKindLocal {
		t.Fatalf("status hostKind = %q, want %q", status.HostKind, HostKindLocal)
	}
	if status.SocketPath != "/tmp/hal-sandboxworker.sock" {
		t.Fatalf("status socketPath = %q, want configured socket path", status.SocketPath)
	}
	wantDrivers := []string{RuntimeDriverRootlessPodman, RuntimeDriverSSHMachine}
	if !reflect.DeepEqual(status.SupportedRuntimeDrivers, wantDrivers) {
		t.Fatalf("status supported drivers = %#v, want %#v", status.SupportedRuntimeDrivers, wantDrivers)
	}
	if status.Health.Status != HealthStatusDegraded || status.Health.Message == "" {
		t.Fatalf("status health = %#v, want configured degraded health", status.Health)
	}
	if status.Capacity.MaxConcurrentSandboxes != 4 || status.Capacity.ActiveSandboxes != 1 {
		t.Fatalf("status capacity = %#v, want configured capacity", status.Capacity)
	}
	assertSecurityPolicyDoesNotOverclaim(t, status.Security)
	if status.Security.Requested.NetworkPolicy == status.Security.Enforced.NetworkPolicy {
		t.Fatalf("status security does not distinguish requested/enforced network policy: %#v", status.Security)
	}
}

func TestServiceCapabilitiesReportsRegisteredDriversAndHonestSecurity(t *testing.T) {
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: RuntimeDriverSSHMachine},
		&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman},
	)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	if capabilities.ProtocolVersion != ProtocolVersion {
		t.Fatalf("capabilities protocolVersion = %q, want %q", capabilities.ProtocolVersion, ProtocolVersion)
	}
	if capabilities.WorkerID != "worker-001" {
		t.Fatalf("capabilities workerId = %q, want worker-001", capabilities.WorkerID)
	}
	wantOps := []string{
		OperationStatus,
		OperationCapabilities,
		OperationCreate,
		OperationStart,
		OperationStop,
		OperationDelete,
		OperationInspect,
		OperationExec,
		OperationCopyIn,
		OperationCopyOut,
	}
	if !reflect.DeepEqual(capabilities.SupportedOperations, wantOps) {
		t.Fatalf("capabilities supported operations = %#v, want %#v", capabilities.SupportedOperations, wantOps)
	}
	if len(capabilities.RuntimeDrivers) != 2 {
		t.Fatalf("capabilities runtime drivers = %#v, want two registered drivers", capabilities.RuntimeDrivers)
	}
	if capabilities.RuntimeDrivers[0].ID != RuntimeDriverRootlessPodman || capabilities.RuntimeDrivers[1].ID != RuntimeDriverSSHMachine {
		t.Fatalf("capabilities runtime driver order = %#v, want registry-sorted drivers", capabilities.RuntimeDrivers)
	}
	for _, driver := range capabilities.RuntimeDrivers {
		if driver.HostKind != HostKindLocal {
			t.Fatalf("driver %q hostKind = %q, want local worker driver", driver.ID, driver.HostKind)
		}
		if driver.ID == RuntimeDriverRootlessPodman && driver.IsolationLevel != IsolationLevelContainer {
			t.Fatalf("rootless Podman isolationLevel = %q, want %q", driver.IsolationLevel, IsolationLevelContainer)
		}
		if driver.ID == RuntimeDriverSSHMachine && driver.IsolationLevel != IsolationLevelHost {
			t.Fatalf("ssh-machine isolationLevel = %q, want conservative host isolation", driver.IsolationLevel)
		}
		if !reflect.DeepEqual(driver.Operations, defaultRuntimeDriverOperations) {
			t.Fatalf("driver %q operations = %#v, want service-backed operations", driver.ID, driver.Operations)
		}
		assertSecurityPolicyDoesNotOverclaim(t, driver.Security)
	}
	assertSecurityPolicyDoesNotOverclaim(t, capabilities.Security)
}

func TestServiceRootlessPodmanCapabilityReportsExactLocalDevSecurity(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want exactly one rootless Podman driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != RuntimeDriverRootlessPodman {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, RuntimeDriverRootlessPodman)
	}
	if driver.HostKind != HostKindLocal {
		t.Fatalf("rootless Podman hostKind = %q, want %q", driver.HostKind, HostKindLocal)
	}
	if driver.IsolationLevel != IsolationLevelContainer {
		t.Fatalf("rootless Podman isolationLevel = %q, want %q", driver.IsolationLevel, IsolationLevelContainer)
	}
	if !reflect.DeepEqual(driver.Operations, defaultRuntimeDriverOperations) {
		t.Fatalf("rootless Podman operations = %#v, want %#v", driver.Operations, defaultRuntimeDriverOperations)
	}
	assertRootlessPodmanSecurityPolicy(t, driver.Security)
}

func TestServiceMicroVMCapabilityReportsConservativeRuntimeMetadata(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	for _, unsupported := range []string{OperationExec, OperationCopyIn, OperationCopyOut} {
		if containsString(capabilities.SupportedOperations, unsupported) {
			t.Fatalf("microVM worker supportedOperations claim unsupported %q support: %#v", unsupported, capabilities.SupportedOperations)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want exactly one microVM driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != RuntimeDriverMicroVM {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, RuntimeDriverMicroVM)
	}
	if driver.HostKind != HostKindLocal {
		t.Fatalf("microVM hostKind = %q, want %q", driver.HostKind, HostKindLocal)
	}
	if driver.IsolationLevel != IsolationLevelVM {
		t.Fatalf("microVM isolationLevel = %q, want %q", driver.IsolationLevel, IsolationLevelVM)
	}
	if !reflect.DeepEqual(driver.Operations, microVMRuntimeDriverOperations) {
		t.Fatalf("microVM operations = %#v, want lifecycle/inspect only %#v", driver.Operations, microVMRuntimeDriverOperations)
	}
	for _, unsupported := range []string{
		OperationExec,
		OperationCopyIn,
		OperationCopyOut,
		unsupportedCredentialModeProxy,
		"template",
		"templates",
		"kit",
		"kits",
	} {
		if containsString(driver.Operations, unsupported) {
			t.Fatalf("microVM operations claim unsupported %q support: %#v", unsupported, driver.Operations)
		}
	}
	assertMicroVMRuntimeDriverSecurityPolicy(t, driver.Security)
}

func TestServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-microvm",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want exactly one microVM driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != RuntimeDriverMicroVM {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, RuntimeDriverMicroVM)
	}
	assertCapabilityDoesNotClaimNetworkEnforcement(t, "worker", capabilities.Security)
	assertMicroVMCapabilityDoesNotRequestNetworkEnforcement(t, "runtime driver", driver.Security)
	assertCapabilityDoesNotClaimNetworkEnforcement(t, "runtime driver", driver.Security)
	if driver.NetworkEnforcement != nil ||
		driver.Security.Requested.NetworkEnforcementCapability != nil ||
		driver.Security.Enforced.NetworkEnforcementCapability != nil {
		t.Fatalf("unconfigured microVM capability included network enforcement metadata: %#v", driver)
	}
}

func TestServiceRuntimeDriverDescriptorProjectsNetworkSecurityFromActiveMetadataOnly(t *testing.T) {
	enforcingCapability := func(mode string) *sandboxruntime.RuntimeNetworkEnforcementCapability {
		return &sandboxruntime.RuntimeNetworkEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{mode, "https://api.internal.example.com"},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsLoopbackRules:      true,
			SupportsLinkLocalRules:     true,
			SupportsDefaultDenyPosture: true,
		}
	}
	requestedOnlySecurity := SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementProxyFirewall,
			IsolationLevel:     IsolationLevelVM,
		},
		Enforced: SecurityControls{
			NetworkPolicy:                NetworkPolicyDenyByDefault,
			NetworkEnforcement:           NetworkEnforcementRuntime,
			NetworkEnforcementCapability: enforcingCapability(NetworkEnforcementRuntime),
			IsolationLevel:               IsolationLevelVM,
		},
	}
	metadataSecurity := SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			IsolationLevel:     IsolationLevelVM,
		},
		Enforced: SecurityControls{
			NetworkPolicy:                NetworkPolicyDenyByDefault,
			NetworkEnforcement:           NetworkEnforcementProxyFirewall,
			NetworkEnforcementCapability: enforcingCapability(NetworkEnforcementProxyFirewall),
			IsolationLevel:               IsolationLevelVM,
		},
	}
	conservativeSecurity := SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			IsolationLevel:     IsolationLevelVM,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			IsolationLevel:     IsolationLevelVM,
		},
	}

	tests := []struct {
		name                     string
		security                 SecurityPolicy
		metadata                 *sandboxruntime.RuntimeNetworkEnforcementMetadata
		wantRequestedPolicy      string
		wantRequestedEnforcement string
		wantEnforcedPolicy       string
		wantEnforcedMode         string
		wantCapability           bool
		wantResultMode           string
		wantResultCapability     bool
	}{
		{
			name:                     "requested policy only",
			security:                 requestedOnlySecurity,
			wantRequestedPolicy:      NetworkPolicyDenyByDefault,
			wantRequestedEnforcement: NetworkEnforcementProxyFirewall,
			wantEnforcedPolicy:       NetworkPolicyBestEffort,
			wantEnforcedMode:         NetworkEnforcementNone,
		},
		{
			name:                     "planned enforcement",
			security:                 metadataSecurity,
			metadata:                 workerDescriptorNetworkMetadata("network-plan-planned", "planned", "firewall", nil),
			wantRequestedPolicy:      NetworkPolicyDenyByDefault,
			wantRequestedEnforcement: NetworkEnforcementNone,
			wantEnforcedPolicy:       NetworkPolicyBestEffort,
			wantEnforcedMode:         NetworkEnforcementNone,
		},
		{
			name:                     "partial success",
			security:                 metadataSecurity,
			metadata:                 workerDescriptorNetworkMetadata("network-plan-partial", "active", "firewall", workerDescriptorNetworkResult("success", NetworkEnforcementProxyFirewall, enforcingCapability(NetworkEnforcementProxyFirewall), "applied", "partial_enforcement")),
			wantRequestedPolicy:      NetworkPolicyDenyByDefault,
			wantRequestedEnforcement: NetworkEnforcementNone,
			wantEnforcedPolicy:       NetworkPolicyBestEffort,
			wantEnforcedMode:         NetworkEnforcementNone,
			wantResultMode:           NetworkEnforcementNone,
		},
		{
			name:                     "failure",
			security:                 metadataSecurity,
			metadata:                 workerDescriptorNetworkMetadata("network-plan-failure", "active", "firewall", workerDescriptorNetworkResult("failure", NetworkEnforcementProxyFirewall, enforcingCapability(NetworkEnforcementProxyFirewall), "adapter_failed", "sanitized_adapter_error")),
			wantRequestedPolicy:      NetworkPolicyDenyByDefault,
			wantRequestedEnforcement: NetworkEnforcementNone,
			wantEnforcedPolicy:       NetworkPolicyBestEffort,
			wantEnforcedMode:         NetworkEnforcementNone,
			wantResultMode:           NetworkEnforcementNone,
		},
		{
			name:                     "active success",
			security:                 conservativeSecurity,
			metadata:                 workerDescriptorNetworkMetadata("network-plan-active", "active", "firewall", workerDescriptorNetworkResult("success", NetworkEnforcementProxyFirewall, enforcingCapability(NetworkEnforcementProxyFirewall), "applied")),
			wantRequestedPolicy:      NetworkPolicyDenyByDefault,
			wantRequestedEnforcement: NetworkEnforcementNone,
			wantEnforcedPolicy:       NetworkPolicyDenyByDefault,
			wantEnforcedMode:         NetworkEnforcementProxyFirewall,
			wantCapability:           true,
			wantResultMode:           NetworkEnforcementProxyFirewall,
			wantResultCapability:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM})
			if err != nil {
				t.Fatalf("NewDriverRegistry() error: %v", err)
			}
			service, err := NewService(ServiceOptions{
				WorkerID: "worker-projection-" + strings.ReplaceAll(tt.name, " ", "-"),
				Registry: registry,
				RuntimeDrivers: map[string]RuntimeDriver{
					RuntimeDriverMicroVM: {
						ID:                 RuntimeDriverMicroVM,
						HostKind:           HostKindLocal,
						IsolationLevel:     IsolationLevelVM,
						Operations:         microVMRuntimeDriverOperations,
						Security:           tt.security,
						NetworkEnforcement: tt.metadata,
					},
				},
			})
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			capabilities := service.Capabilities()
			if err := capabilities.Validate(); err != nil {
				t.Fatalf("Capabilities().Validate() error: %v", err)
			}
			if len(capabilities.RuntimeDrivers) != 1 {
				t.Fatalf("runtime drivers = %#v, want one microVM driver", capabilities.RuntimeDrivers)
			}
			driver := capabilities.RuntimeDrivers[0]
			if driver.Security.Requested.NetworkPolicy != tt.wantRequestedPolicy ||
				driver.Security.Requested.NetworkEnforcement != tt.wantRequestedEnforcement {
				t.Fatalf("requested security = %#v, want policy %q enforcement %q", driver.Security.Requested, tt.wantRequestedPolicy, tt.wantRequestedEnforcement)
			}
			if driver.Security.Enforced.NetworkPolicy != tt.wantEnforcedPolicy ||
				driver.Security.Enforced.NetworkEnforcement != tt.wantEnforcedMode {
				t.Fatalf("enforced security = %#v, want policy %q enforcement %q", driver.Security.Enforced, tt.wantEnforcedPolicy, tt.wantEnforcedMode)
			}
			if gotCapability := driver.Security.Enforced.NetworkEnforcementCapability != nil; gotCapability != tt.wantCapability {
				t.Fatalf("enforced capability present = %v, want %v (%#v)", gotCapability, tt.wantCapability, driver.Security.Enforced.NetworkEnforcementCapability)
			}
			if tt.wantCapability {
				if !reflect.DeepEqual(driver.Security.Enforced.NetworkEnforcementCapability.Modes, []string{NetworkEnforcementProxyFirewall}) {
					t.Fatalf("enforced capability modes = %#v, want sanitized proxy_firewall only", driver.Security.Enforced.NetworkEnforcementCapability.Modes)
				}
			}
			if tt.metadata == nil {
				if driver.NetworkEnforcement != nil {
					t.Fatalf("NetworkEnforcement = %#v, want nil", driver.NetworkEnforcement)
				}
			} else {
				if driver.NetworkEnforcement == nil || driver.NetworkEnforcement.Plan == nil || driver.NetworkEnforcement.Orchestration == nil {
					t.Fatalf("NetworkEnforcement = %#v, want sanitized plan and orchestration metadata", driver.NetworkEnforcement)
				}
				if driver.NetworkEnforcement.Result != nil {
					if driver.NetworkEnforcement.Result.EnforcementMode != tt.wantResultMode {
						t.Fatalf("result enforcementMode = %q, want %q", driver.NetworkEnforcement.Result.EnforcementMode, tt.wantResultMode)
					}
					if gotCapability := driver.NetworkEnforcement.Result.Capability != nil; gotCapability != tt.wantResultCapability {
						t.Fatalf("result capability present = %v, want %v (%#v)", gotCapability, tt.wantResultCapability, driver.NetworkEnforcement.Result.Capability)
					}
				}
			}

			encoded, err := json.Marshal(driver)
			if err != nil {
				t.Fatalf("Marshal(driver) error: %v", err)
			}
			publicText := string(encoded)
			for _, unsafe := range []string{
				"api.internal.example.com",
				"/tmp/",
				"proxy.sock",
				"token",
				"secret",
				"://",
			} {
				if strings.Contains(publicText, unsafe) {
					t.Fatalf("driver descriptor leaked unsafe value %q in %s", unsafe, publicText)
				}
			}
		})
	}
}

func TestServiceStatusProjectsProxyActiveNetworkEnforcementProof(t *testing.T) {
	service, err := NewService(ServiceOptions{
		WorkerID:           "worker-proxy-active",
		NetworkEnforcement: workerStatusProxyNetworkMetadata("worker-proxy-active", "active", workerStatusProxyNetworkResult("success", NetworkEnforcementProxy, workerStatusProxyCapability(), "applied")),
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	status := service.Status()
	if err := status.Validate(); err != nil {
		t.Fatalf("Status().Validate() error: %v", err)
	}
	if status.Security.NetworkEnforcement == nil ||
		status.Security.NetworkEnforcement.Orchestration == nil ||
		status.Security.NetworkEnforcement.Orchestration.Proxy == nil ||
		status.Security.NetworkEnforcement.Result == nil {
		t.Fatalf("status security networkEnforcement = %#v, want sanitized proxy-active proof", status.Security.NetworkEnforcement)
	}
	if status.Security.Requested.NetworkPolicy != NetworkPolicyDenyByDefault {
		t.Fatalf("requested networkPolicy = %q, want %q", status.Security.Requested.NetworkPolicy, NetworkPolicyDenyByDefault)
	}
	if status.Security.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("enforced networkPolicy = %q, want proxy-only partial enforcement to remain %q", status.Security.Enforced.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if status.Security.Enforced.NetworkEnforcement != NetworkEnforcementProxy {
		t.Fatalf("enforced networkEnforcement = %q, want proxy-only enforcement", status.Security.Enforced.NetworkEnforcement)
	}
	if status.Security.Enforced.NetworkEnforcement == NetworkEnforcementProxyFirewall {
		t.Fatalf("status security overstated proxy_firewall enforcement: %#v", status.Security)
	}
	if status.Security.Enforced.NetworkEnforcementCapability == nil ||
		!reflect.DeepEqual(status.Security.Enforced.NetworkEnforcementCapability.Modes, []string{NetworkEnforcementProxy}) {
		t.Fatalf("enforced network capability = %#v, want sanitized proxy-only capability", status.Security.Enforced.NetworkEnforcementCapability)
	}
	if status.Security.Enforced.NetworkEnforcementCapability.SupportsDefaultDenyPosture {
		t.Fatalf("enforced network capability = %#v, want proxy-only proof without full default-deny claim", status.Security.Enforced.NetworkEnforcementCapability)
	}
	if status.Security.NetworkEnforcement.Result.EnforcementMode != NetworkEnforcementProxy {
		t.Fatalf("networkEnforcement result mode = %q, want %q", status.Security.NetworkEnforcement.Result.EnforcementMode, NetworkEnforcementProxy)
	}
	if status.Security.NetworkEnforcement.Orchestration.Proxy.Status != "active" {
		t.Fatalf("proxy lifecycle status = %q, want active", status.Security.NetworkEnforcement.Orchestration.Proxy.Status)
	}

	response := service.StatusResponse("status-proxy-active")
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal(StatusResponse) error: %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"operation":"status"`,
		`"status"`,
		`"networkEnforcement":"proxy"`,
		`"networkEnforcement"`,
		`"status":"active"`,
		`"proxy_active"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("status JSON %s missing %s", publicText, want)
		}
	}
	assertWorkerStatusNetworkProofRedacted(t, publicText)
}

func TestServiceStatusDoesNotUpgradeNetworkEnforcementWithoutActiveSuccessfulProxyProof(t *testing.T) {
	tests := []struct {
		name     string
		metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata
	}{
		{
			name:     "missing proof",
			metadata: nil,
		},
		{
			name:     "missing result",
			metadata: workerStatusProxyNetworkMetadata("worker-proxy-missing-result", "active", nil),
		},
		{
			name:     "missing proxy lifecycle proof",
			metadata: workerStatusProxyNetworkMetadataWithoutProxyLifecycle("worker-proxy-missing-proof"),
		},
		{
			name:     "failed result",
			metadata: workerStatusProxyNetworkMetadata("worker-proxy-failed", "active", workerStatusProxyNetworkResult("failure", NetworkEnforcementProxy, workerStatusProxyCapability(), "adapter_failed")),
		},
		{
			name:     "failed proxy lifecycle proof",
			metadata: workerStatusProxyNetworkMetadataWithProxyLifecycleStatus("worker-proxy-lifecycle-failed", "failed"),
		},
		{
			name:     "inactive proxy lifecycle",
			metadata: workerStatusProxyNetworkMetadata("worker-proxy-prepared", "prepared", workerStatusProxyNetworkResult("success", NetworkEnforcementProxy, workerStatusProxyCapability(), "applied")),
		},
		{
			name:     "proxy firewall result without rule proof",
			metadata: workerStatusProxyNetworkMetadata("worker-proxy-firewall-without-rules", "active", workerStatusProxyFirewallNetworkResultWithoutRuleProof()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(ServiceOptions{
				WorkerID:           "worker-" + strings.ReplaceAll(tt.name, " ", "-"),
				NetworkEnforcement: tt.metadata,
			})
			if err != nil {
				t.Fatalf("NewService() error: %v", err)
			}

			status := service.Status()
			if err := status.Validate(); err != nil {
				t.Fatalf("Status().Validate() error: %v", err)
			}
			if status.Security.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
				t.Fatalf("enforced networkPolicy = %q, want conservative best_effort", status.Security.Enforced.NetworkPolicy)
			}
			if status.Security.Enforced.NetworkEnforcement != NetworkEnforcementNone {
				t.Fatalf("enforced networkEnforcement = %q, want no enforcement upgrade", status.Security.Enforced.NetworkEnforcement)
			}
			if status.Security.Enforced.NetworkEnforcementCapability != nil {
				t.Fatalf("enforced capability = %#v, want nil without active successful proof", status.Security.Enforced.NetworkEnforcementCapability)
			}
			if status.Security.Enforced.NetworkEnforcement == NetworkEnforcementProxyFirewall {
				t.Fatalf("status security overstated proxy_firewall enforcement: %#v", status.Security)
			}

			encoded, err := json.Marshal(status)
			if err != nil {
				t.Fatalf("Marshal(status) error: %v", err)
			}
			assertWorkerStatusNetworkProofRedacted(t, string(encoded))
		})
	}
}

func TestServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	metadata := &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               "network-plan-worker",
			Source:           "worker",
			Operation:        "prepare_network",
			PolicySnapshotID: "policy-snapshot-worker",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "allowlist", "/tmp/raw-rules.sock"},
		},
		Orchestration: workerDescriptorActiveNetworkOrchestration("network-plan-worker"),
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "network-plan-worker",
			AdapterID:       "fake-worker-adapter",
			Outcome:         "success",
			EnforcementMode: NetworkEnforcementProxyFirewall,
			Mechanisms:      []string{"proxy", "firewall"},
			Operations:      []string{"proxy_route", "firewall_apply"},
			Capability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{NetworkEnforcementProxyFirewall},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	}
	capability := &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{NetworkEnforcementProxyFirewall},
		SupportsDomainRules:        true,
		SupportsEndpointRules:      true,
		SupportsPrivateRangeRules:  true,
		SupportsMetadataEndpoint:   true,
		SupportsDefaultDenyPosture: true,
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-explicit-network",
		Registry: registry,
		RuntimeDrivers: map[string]RuntimeDriver{
			RuntimeDriverMicroVM: {
				ID:             RuntimeDriverMicroVM,
				HostKind:       HostKindLocal,
				IsolationLevel: IsolationLevelVM,
				Operations:     microVMRuntimeDriverOperations,
				Security: SecurityPolicy{
					Requested: SecurityControls{
						NetworkPolicy:      NetworkPolicyDenyByDefault,
						NetworkEnforcement: NetworkEnforcementProxyFirewall,
						IsolationLevel:     IsolationLevelVM,
					},
					Enforced: SecurityControls{
						NetworkPolicy:                NetworkPolicyDenyByDefault,
						NetworkEnforcement:           NetworkEnforcementProxyFirewall,
						NetworkEnforcementCapability: capability,
						IsolationLevel:               IsolationLevelVM,
					},
				},
				NetworkEnforcement: metadata,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want one microVM driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.NetworkEnforcement == nil || driver.NetworkEnforcement.Result == nil {
		t.Fatalf("driver networkEnforcement = %#v, want explicit result metadata", driver.NetworkEnforcement)
	}
	if driver.NetworkEnforcement.Result.EnforcementMode != NetworkEnforcementProxyFirewall ||
		driver.NetworkEnforcement.Result.Capability == nil ||
		!driver.NetworkEnforcement.Result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("driver networkEnforcement result = %#v, want proxy_firewall capability", driver.NetworkEnforcement.Result)
	}
	if driver.Security.Enforced.NetworkEnforcementCapability == nil ||
		!driver.Security.Enforced.NetworkEnforcementCapability.Supported {
		t.Fatalf("driver security capability = %#v, want explicit supported capability", driver.Security.Enforced.NetworkEnforcementCapability)
	}

	encoded, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatalf("Marshal(capabilities) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/tmp/",
		"raw-rules.sock",
		"token",
		"secret",
		"://",
		"production",
		"egress",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("capabilities leaked or claimed %q in %s", unsafe, publicText)
		}
	}
}

func workerStatusProxyNetworkMetadata(planID, proxyStatus string, result *sandboxruntime.RuntimeNetworkEnforcementResultMetadata) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               planID,
			Source:           "worker",
			Operation:        "prepare_network",
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "https://api.internal.example.com", "token=secret"},
			Operations:       []string{"default_deny", "connect 10.0.0.5:443", "/tmp/proxy.sock"},
		},
		Orchestration: &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           planID,
			AdapterID:        "worker-proxy-adapter",
			Status:           proxyStatus,
			Mechanisms:       []string{"proxy", "169.254.169.254"},
			Operations:       []string{"active_proxy", "curl https://api.internal.example.com", "OPENAI_API_KEY"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               planID + "-proxy",
				PlanID:           planID,
				AdapterID:        "worker-proxy-adapter",
				Status:           proxyStatus,
				Mechanisms:       []string{"proxy"},
				Operations:       []string{"active_proxy", "listen 127.0.0.1:8080", "Authorization: Bearer secret"},
				PolicySnapshotID: planID + "-snapshot",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"proxy_active", "token_holder"},
				ReasonCode:       proxyStatus,
			},
			CapabilityLabels: []string{"proxy_active", "token_holder"},
			ReasonCode:       proxyStatus,
		},
		Result: result,
	}
}

func workerStatusProxyNetworkMetadataWithoutProxyLifecycle(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := workerStatusProxyNetworkMetadata(planID, "active", workerStatusProxyNetworkResult("success", NetworkEnforcementProxy, workerStatusProxyCapability(), "applied"))
	metadata.Orchestration.Proxy = nil
	return metadata
}

func workerStatusProxyNetworkMetadataWithProxyLifecycleStatus(planID, proxyStatus string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := workerStatusProxyNetworkMetadata(planID, "active", workerStatusProxyNetworkResult("success", NetworkEnforcementProxy, workerStatusProxyCapability(), "applied"))
	metadata.Orchestration.Proxy.Status = proxyStatus
	metadata.Orchestration.Proxy.ReasonCode = proxyStatus
	return metadata
}

func workerStatusProxyNetworkResult(outcome, mode string, capability *sandboxruntime.RuntimeNetworkEnforcementCapability, reason string) *sandboxruntime.RuntimeNetworkEnforcementResultMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
		PlanID:           "worker-proxy-result",
		AdapterID:        "worker-proxy-adapter",
		Outcome:          outcome,
		EnforcementMode:  mode,
		Mechanisms:       []string{"proxy"},
		Operations:       []string{"proxy_route", "connect https://api.internal.example.com:443", "/tmp/proxy.sock", "GITHUB_TOKEN"},
		PolicySnapshotID: "worker-proxy-result-snapshot",
		PolicyPreset:     "deny_by_default",
		Capability:       capability,
		ReasonCode:       reason,
	}
}

func workerStatusProxyFirewallNetworkResultWithoutRuleProof() *sandboxruntime.RuntimeNetworkEnforcementResultMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
		PlanID:           "worker-proxy-firewall-result",
		AdapterID:        "worker-proxy-adapter",
		Outcome:          "success",
		EnforcementMode:  NetworkEnforcementProxyFirewall,
		Mechanisms:       []string{"proxy", "firewall"},
		Operations:       []string{"proxy_route", "iptables -A OUTPUT", "/tmp/firewall.rules"},
		PolicySnapshotID: "worker-proxy-firewall-result-snapshot",
		PolicyPreset:     "deny_by_default",
		Capability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{NetworkEnforcementProxyFirewall},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsLoopbackRules:      true,
			SupportsLinkLocalRules:     true,
			SupportsDefaultDenyPosture: true,
		},
		ReasonCode: "applied",
	}
}

func workerStatusProxyCapability() *sandboxruntime.RuntimeNetworkEnforcementCapability {
	return &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{NetworkEnforcementProxy, "https://api.internal.example.com"},
		SupportsDomainRules:        true,
		SupportsEndpointRules:      true,
		SupportsPrivateRangeRules:  true,
		SupportsMetadataEndpoint:   true,
		SupportsLoopbackRules:      true,
		SupportsLinkLocalRules:     true,
		SupportsDefaultDenyPosture: true,
	}
}

func assertWorkerStatusNetworkProofRedacted(t *testing.T, publicText string) {
	t.Helper()
	for _, unsafe := range []string{
		"api.internal.example.com",
		"10.0.0.5",
		"127.0.0.1",
		"169.254.169.254",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"token",
		"secret",
		"/tmp/",
		"proxy.sock",
		"firewall.rules",
		"://",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("worker status JSON leaked unsafe value %q in %s", unsafe, publicText)
		}
	}
}

func workerDescriptorNetworkMetadata(planID, orchestrationStatus, ruleMechanism string, result *sandboxruntime.RuntimeNetworkEnforcementResultMetadata) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               planID,
			Source:           "worker",
			Operation:        "prepare_network",
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "allowlist", "iptables -A OUTPUT", "/tmp/proxy.sock", "token=secret"},
		},
		Orchestration: workerDescriptorNetworkOrchestration(planID, orchestrationStatus, ruleMechanism),
		Result:        result,
	}
}

func workerDescriptorNetworkResult(outcome, mode string, capability *sandboxruntime.RuntimeNetworkEnforcementCapability, reason string, warnings ...string) *sandboxruntime.RuntimeNetworkEnforcementResultMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
		PlanID:           "network-plan-result",
		AdapterID:        "fake-worker-adapter",
		Outcome:          outcome,
		EnforcementMode:  mode,
		Mechanisms:       []string{"proxy", "firewall"},
		Operations:       []string{"proxy_route", "firewall_apply", "connect api.internal.example.com:443", "/tmp/firewall.rules", "GITHUB_TOKEN"},
		PolicySnapshotID: "policy-snapshot-result",
		PolicyPreset:     "deny_by_default",
		Capability:       capability,
		ReasonCode:       reason,
		WarningCodes:     warnings,
	}
}

func workerDescriptorNetworkOrchestration(planID, status, ruleMechanism string) *sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata {
	if status == "active" {
		return workerDescriptorActiveNetworkOrchestration(planID)
	}
	return &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
		PlanID:           planID,
		AdapterID:        "fake-worker-adapter",
		Status:           status,
		Mechanisms:       []string{"proxy", "firewall"},
		Operations:       []string{"prepare_proxy", "plan_rules"},
		PolicySnapshotID: planID + "-snapshot",
		PolicyPreset:     "deny_by_default",
		Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
			ID:               planID + "-proxy",
			PlanID:           planID,
			AdapterID:        "fake-worker-adapter",
			Status:           "prepared",
			Mechanisms:       []string{"proxy"},
			Operations:       []string{"prepare_proxy"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			CapabilityLabels: []string{"proxy_prepared", "token_holder"},
			ReasonCode:       "prepared",
		},
		Rules: []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{{
			ID:               planID + "-rules",
			PlanID:           planID,
			AdapterID:        "fake-worker-adapter",
			Status:           "planned",
			Mechanisms:       []string{ruleMechanism},
			Operations:       []string{"plan_rules"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			CapabilityLabels: []string{"firewall_planned", "/tmp/rules"},
			ReasonCode:       "prepared",
		}},
		CapabilityLabels: []string{"network_planned", "token_holder"},
		ReasonCode:       "prepared",
		WarningCodes:     []string{"metadata_only_fallback"},
	}
}

func workerDescriptorActiveNetworkOrchestration(planID string) *sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
		PlanID:           planID,
		AdapterID:        "fake-worker-adapter",
		Status:           "active",
		Mechanisms:       []string{"proxy", "firewall"},
		Operations:       []string{"active_proxy", "active_rules"},
		PolicySnapshotID: planID + "-snapshot",
		PolicyPreset:     "deny_by_default",
		Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
			ID:               planID + "-proxy",
			PlanID:           planID,
			AdapterID:        "fake-worker-adapter",
			Status:           "active",
			Mechanisms:       []string{"proxy"},
			Operations:       []string{"active_proxy", "/tmp/proxy.sock"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			CapabilityLabels: []string{"proxy_active", "token_holder"},
			ReasonCode:       "active",
		},
		Rules: []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{{
			ID:               planID + "-rules",
			PlanID:           planID,
			AdapterID:        "fake-worker-adapter",
			Status:           "active",
			Mechanisms:       []string{"firewall"},
			Operations:       []string{"active_rules", "iptables -A OUTPUT"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     "deny_by_default",
			CapabilityLabels: []string{"firewall_active", "secret_rule"},
			ReasonCode:       "active",
		}},
		CapabilityLabels: []string{"proxy_active", "firewall_active", "token_holder"},
		ReasonCode:       "active",
	}
}

func TestServiceMicroVMWorkerIORequestsAreRejectedBeforeDriverDispatch(t *testing.T) {
	driver := &fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	execReq := validWorkerExecRequest()
	execReq.DriverID = RuntimeDriverMicroVM
	execReq.Exec.Target = lifecycleWorkerTarget(RuntimeDriverMicroVM, "microvm-dev", "running")

	copyInReq := validWorkerCopyInRequest()
	copyInReq.DriverID = RuntimeDriverMicroVM
	copyInReq.CopyIn.Target = lifecycleWorkerTarget(RuntimeDriverMicroVM, "microvm-dev", "running")
	copyInReq.CopyIn.Payload = workerCopyPayload("payload", MaxCopyInPayloadBytes)

	copyOutReq := validWorkerCopyOutRequest()
	copyOutReq.DriverID = RuntimeDriverMicroVM
	copyOutReq.CopyOut.Target = lifecycleWorkerTarget(RuntimeDriverMicroVM, "microvm-dev", "running")

	for _, req := range []Request{execReq, copyInReq, copyOutReq} {
		resp := service.HandleRequest(context.Background(), req)
		if err := resp.Validate(); err != nil {
			t.Fatalf("%s response Validate() error: %v", req.Operation, err)
		}
		if resp.OK || resp.Error == nil || resp.Error.Code != ErrorCodeUnsupportedOp {
			t.Fatalf("%s response = %#v, want unsupported operation", req.Operation, resp)
		}
	}
	if driver.execCalls != 0 || driver.copyInCalls != 0 || driver.copyOutCalls != 0 {
		t.Fatalf("driver dispatch calls = exec:%d copyIn:%d copyOut:%d, want zero", driver.execCalls, driver.copyInCalls, driver.copyOutCalls)
	}
}

func TestServiceProtocolResponsesValidate(t *testing.T) {
	service, err := NewService(ServiceOptions{WorkerID: "worker-001"})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	statusResp := service.StatusResponse(" req-001 ")
	if err := statusResp.Validate(); err != nil {
		t.Fatalf("StatusResponse().Validate() error: %v", err)
	}
	if statusResp.RequestID != "req-001" || statusResp.Operation != OperationStatus || statusResp.Status == nil {
		t.Fatalf("status response = %#v, want trimmed request ID and status payload", statusResp)
	}

	capabilitiesResp := service.CapabilitiesResponse("req-002")
	if err := capabilitiesResp.Validate(); err != nil {
		t.Fatalf("CapabilitiesResponse().Validate() error: %v", err)
	}
	if capabilitiesResp.RequestID != "req-002" || capabilitiesResp.Operation != OperationCapabilities || capabilitiesResp.Capabilities == nil {
		t.Fatalf("capabilities response = %#v, want request ID and capabilities payload", capabilitiesResp)
	}
}

func TestServiceHandleRequestReturnsContextProtocolErrors(t *testing.T) {
	service, err := NewService(ServiceOptions{WorkerID: "worker-001"})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledResp := service.HandleRequest(canceledCtx, Request{
		RequestID: "req-canceled",
		Operation: OperationStatus,
	})
	if err := canceledResp.Validate(); err != nil {
		t.Fatalf("canceled response Validate() error: %v", err)
	}
	if canceledResp.OK || canceledResp.Operation != OperationStatus || canceledResp.Error == nil {
		t.Fatalf("canceled response = %#v, want structured cancellation error", canceledResp)
	}
	if canceledResp.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled error code = %q, want %q", canceledResp.Error.Code, ErrorCodeRequestCanceled)
	}

	timeoutCtx, timeoutCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer timeoutCancel()
	timeoutResp := service.HandleRequest(timeoutCtx, Request{
		RequestID: "req-timeout",
		Operation: OperationCapabilities,
	})
	if err := timeoutResp.Validate(); err != nil {
		t.Fatalf("timeout response Validate() error: %v", err)
	}
	if timeoutResp.OK || timeoutResp.Operation != OperationCapabilities || timeoutResp.Error == nil {
		t.Fatalf("timeout response = %#v, want structured timeout error", timeoutResp)
	}
	if timeoutResp.Error.Code != ErrorCodeRequestTimeout {
		t.Fatalf("timeout error code = %q, want %q", timeoutResp.Error.Code, ErrorCodeRequestTimeout)
	}
}

func TestServiceRejectsInvalidState(t *testing.T) {
	tests := []struct {
		name    string
		options ServiceOptions
		want    string
	}{
		{
			name:    "missing worker id",
			options: ServiceOptions{WorkerID: "  "},
			want:    "workerId is required",
		},
		{
			name: "unsupported host kind",
			options: ServiceOptions{
				WorkerID: "worker-001",
				HostKind: "hosted",
			},
			want: "hostKind",
		},
		{
			name: "active exceeds max capacity",
			options: ServiceOptions{
				WorkerID: "worker-001",
				Capacity: WorkerCapacity{
					MaxConcurrentSandboxes: 1,
					ActiveSandboxes:        2,
				},
			},
			want: "activeSandboxes",
		},
		{
			name: "capabilities overstate credential proxy",
			options: ServiceOptions{
				WorkerID: "worker-001",
				Security: SecurityPolicy{
					Requested: DefaultWorkerSecurityPolicy().Requested,
					Enforced: SecurityControls{
						NetworkPolicy:       NetworkPolicyBestEffort,
						NetworkEnforcement:  NetworkEnforcementNone,
						CredentialModes:     []string{CredentialModeEnv},
						IsolationLevel:      IsolationLevelHost,
						CredentialProxyMode: true,
					},
				},
			},
			want: "credentialProxyMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(tt.options)
			if err == nil {
				t.Fatalf("NewService() error = nil, want %q (service %#v)", tt.want, service)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewService() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestServiceUsesCustomRuntimeDriverDescriptorsFromRegistry(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: "fake_runtime"})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
		RuntimeDrivers: map[string]RuntimeDriver{
			"fake_runtime": {
				HostKind:       HostKindLocal,
				IsolationLevel: IsolationLevelHost,
				Operations:     []string{OperationInspect},
				Security:       defaultRuntimeDriverSecurityPolicy(IsolationLevelHost),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want one fake driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != "fake_runtime" {
		t.Fatalf("custom driver ID = %q, want descriptor ID defaulted from registry", driver.ID)
	}
	if !reflect.DeepEqual(driver.Operations, []string{OperationInspect}) {
		t.Fatalf("custom driver operations = %#v, want inspect only", driver.Operations)
	}
}

func TestServiceCapabilitiesCanRemainConservativeWhenOperationsAreDisabled(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: "fake_runtime"})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
		SupportedOperations: []string{
			OperationStatus,
			OperationCapabilities,
		},
		RuntimeDrivers: map[string]RuntimeDriver{
			"fake_runtime": {
				HostKind:       HostKindLocal,
				IsolationLevel: IsolationLevelHost,
				Operations:     []string{OperationInspect},
				Security:       defaultRuntimeDriverSecurityPolicy(IsolationLevelHost),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	capabilities := service.Capabilities()
	for _, operation := range []string{OperationExec, OperationCopyIn, OperationCopyOut} {
		if containsString(capabilities.SupportedOperations, operation) {
			t.Fatalf("disabled capabilities supportedOperations include %q: %#v", operation, capabilities.SupportedOperations)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want one fake driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	for _, operation := range []string{OperationExec, OperationCopyIn, OperationCopyOut} {
		if containsString(driver.Operations, operation) {
			t.Fatalf("disabled driver operations include %q: %#v", operation, driver.Operations)
		}
	}
	assertSecurityPolicyDoesNotOverclaim(t, capabilities.Security)
	assertSecurityPolicyDoesNotOverclaim(t, driver.Security)
}

func TestServiceCapabilitiesRejectInvalidRuntimeDriverDescriptor(t *testing.T) {
	registry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: "fake_runtime"})
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
		RuntimeDrivers: map[string]RuntimeDriver{
			"fake_runtime": {
				ID:             "fake_runtime",
				HostKind:       HostKindLocal,
				IsolationLevel: unsupportedIsolationLevelMicroVM,
				Operations:     []string{OperationInspect},
				Security:       DefaultWorkerSecurityPolicy(),
			},
		},
	})
	if err == nil {
		t.Fatalf("NewService() error = nil, want invalid descriptor error (service %#v)", service)
	}
	if !strings.Contains(err.Error(), "isolationLevel") {
		t.Fatalf("NewService() error = %q, want isolationLevel validation error", err.Error())
	}
}

func assertSecurityPolicyDoesNotOverclaim(t *testing.T, policy SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("security policy Validate() error: %v", err)
	}
	if policy.Enforced.NetworkPolicy == NetworkPolicyDenyByDefault {
		t.Fatalf("security policy claims deny-by-default enforcement: %#v", policy)
	}
	switch policy.Enforced.NetworkEnforcement {
	case "", NetworkEnforcementNone, NetworkEnforcementRuntime:
	default:
		t.Fatalf("security policy claims unsupported network enforcement: %#v", policy)
	}
	if policy.Enforced.CredentialProxyMode || containsString(policy.Enforced.CredentialModes, unsupportedCredentialModeProxy) {
		t.Fatalf("security policy claims credential proxy support: %#v", policy)
	}
	if policy.Enforced.IsolationLevel == unsupportedIsolationLevelMicroVM {
		t.Fatalf("security policy claims microVM isolation: %#v", policy)
	}
}

func assertRootlessPodmanSecurityPolicy(t *testing.T, policy SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("rootless Podman security policy Validate() error: %v", err)
	}
	if policy.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("rootless Podman enforced networkPolicy = %q, want %q", policy.Enforced.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Enforced.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("rootless Podman enforced networkEnforcement = %q, want %q", policy.Enforced.NetworkEnforcement, NetworkEnforcementNone)
	}
	if policy.Enforced.CredentialProxyMode {
		t.Fatalf("rootless Podman enforced credentialProxyMode = true, want false")
	}
	for _, value := range append([]string{
		policy.Enforced.NetworkPolicy,
		policy.Enforced.NetworkEnforcement,
		policy.Enforced.IsolationLevel,
	}, policy.Enforced.CredentialModes...) {
		switch value {
		case unsupportedIsolationLevelMicroVM,
			unsupportedNetworkEnforcementFirewall,
			unsupportedNetworkEnforcementProxy,
			"proxy_firewall",
			unsupportedCredentialModeProxy,
			"secret_broker":
			t.Fatalf("rootless Podman enforced security advertises unsupported capability %q: %#v", value, policy.Enforced)
		}
	}
}

func assertMicroVMRuntimeDriverSecurityPolicy(t *testing.T, policy SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("microVM security policy Validate() error: %v", err)
	}
	if policy.Requested.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("microVM requested networkPolicy = %q, want %q", policy.Requested.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Requested.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("microVM requested networkEnforcement = %q, want %q", policy.Requested.NetworkEnforcement, NetworkEnforcementNone)
	}
	if len(policy.Requested.CredentialModes) != 0 || policy.Requested.CredentialProxyMode {
		t.Fatalf("microVM requested credential controls overclaim support: %#v", policy.Requested)
	}
	if policy.Requested.IsolationLevel != IsolationLevelVM {
		t.Fatalf("microVM requested isolationLevel = %q, want %q", policy.Requested.IsolationLevel, IsolationLevelVM)
	}
	if policy.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("microVM enforced networkPolicy = %q, want %q", policy.Enforced.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Enforced.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("microVM enforced networkEnforcement = %q, want %q", policy.Enforced.NetworkEnforcement, NetworkEnforcementNone)
	}
	if len(policy.Enforced.CredentialModes) != 0 || policy.Enforced.CredentialProxyMode {
		t.Fatalf("microVM enforced credential controls overclaim support: %#v", policy.Enforced)
	}
	if policy.Enforced.IsolationLevel != IsolationLevelVM {
		t.Fatalf("microVM enforced isolationLevel = %q, want %q", policy.Enforced.IsolationLevel, IsolationLevelVM)
	}
}

func assertMicroVMCapabilityDoesNotRequestNetworkEnforcement(t *testing.T, label string, policy SecurityPolicy) {
	t.Helper()
	if policy.Requested.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("%s requested networkPolicy = %q, want %q", label, policy.Requested.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Requested.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("%s requested networkEnforcement = %q, want %q", label, policy.Requested.NetworkEnforcement, NetworkEnforcementNone)
	}
}

func assertCapabilityDoesNotClaimNetworkEnforcement(t *testing.T, label string, policy SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("%s security policy Validate() error: %v", label, err)
	}
	if policy.Enforced.NetworkPolicy != NetworkPolicyBestEffort {
		t.Fatalf("%s enforced networkPolicy = %q, want %q", label, policy.Enforced.NetworkPolicy, NetworkPolicyBestEffort)
	}
	if policy.Enforced.NetworkPolicy == NetworkPolicyDenyByDefault {
		t.Fatalf("%s enforced networkPolicy claims deny-by-default enforcement: %#v", label, policy)
	}
	if policy.Enforced.NetworkEnforcement != NetworkEnforcementNone {
		t.Fatalf("%s enforced networkEnforcement = %q, want %q", label, policy.Enforced.NetworkEnforcement, NetworkEnforcementNone)
	}
}
