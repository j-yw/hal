package sandboxworker

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
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
