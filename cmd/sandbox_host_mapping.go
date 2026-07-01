package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

type sandboxHostWorkerMetadataRequest struct {
	WorkerID     string
	SocketPath   string
	Status       *sandboxworker.Status
	Capabilities *sandboxworker.Capabilities
	CheckedAt    time.Time
}

func sandboxHostFromWorkerMetadata(req sandboxHostWorkerMetadataRequest) (*sandbox.SandboxHost, error) {
	workerID := strings.TrimSpace(req.WorkerID)
	if workerID == "" && req.Status != nil {
		workerID = strings.TrimSpace(req.Status.WorkerID)
	}
	if workerID == "" && req.Capabilities != nil {
		workerID = strings.TrimSpace(req.Capabilities.WorkerID)
	}
	if workerID == "" {
		return nil, fmt.Errorf("worker id is required")
	}

	endpoint, err := sandboxHostWorkerEndpoint(req.SocketPath, req.Status)
	if err != nil {
		return nil, err
	}

	host := &sandbox.SandboxHost{
		ID:       workerID,
		Name:     workerID,
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: endpoint,
		Health: &sandbox.HostHealth{
			Status: sandboxworker.HealthStatusUnknown,
		},
	}

	if req.Status == nil && req.Capabilities == nil {
		return host, nil
	}

	if err := validateSandboxHostWorkerPayloads(workerID, req.Status, req.Capabilities); err != nil {
		return nil, err
	}

	if req.Status != nil {
		host.Health = sandboxHostHealthFromWorker(req.Status.Health, req.CheckedAt)
		host.Capacity = sandboxHostCapacityFromWorker(req.Status.Capacity)
	}
	host.SupportedRuntimes = sandboxHostSupportedRuntimes(req.Status, req.Capabilities)
	host.Security = sandboxHostSecurityFromWorker(req.Status, req.Capabilities)

	return host, nil
}

func sandboxHostWorkerEndpoint(socketPath string, status *sandboxworker.Status) (string, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" && status != nil {
		socketPath = strings.TrimSpace(status.SocketPath)
	}
	if socketPath == "" {
		return "", fmt.Errorf("worker socket path is required")
	}

	path, err := sandboxHostLocalWorkerSocketPath(socketPath)
	if err != nil {
		return "", err
	}
	return "unix://" + path, nil
}

func validateSandboxHostWorkerPayloads(workerID string, status *sandboxworker.Status, capabilities *sandboxworker.Capabilities) error {
	if status != nil {
		normalized := status.WithDefaults()
		if err := normalized.Validate(); err != nil {
			return fmt.Errorf("worker status metadata: %w", err)
		}
		if normalized.WorkerID != workerID {
			return fmt.Errorf("worker status id %q does not match host id %q", normalized.WorkerID, workerID)
		}
	}
	if capabilities != nil {
		normalized := capabilities.WithDefaults()
		if err := normalized.Validate(); err != nil {
			return fmt.Errorf("worker capabilities metadata: %w", err)
		}
		if normalized.WorkerID != workerID {
			return fmt.Errorf("worker capabilities id %q does not match host id %q", normalized.WorkerID, workerID)
		}
	}
	return nil
}

func sandboxHostHealthFromWorker(health sandboxworker.WorkerHealth, checkedAt time.Time) *sandbox.HostHealth {
	status := strings.TrimSpace(health.Status)
	if status == "" {
		status = sandboxworker.HealthStatusUnknown
	}
	return &sandbox.HostHealth{
		Status:    status,
		CheckedAt: checkedAt,
		Message:   strings.TrimSpace(health.Message),
	}
}

func sandboxHostCapacityFromWorker(capacity sandboxworker.WorkerCapacity) *sandbox.HostCapacity {
	if capacity.MaxConcurrentSandboxes <= 0 {
		return nil
	}
	return &sandbox.HostCapacity{
		MaxConcurrentSandboxes: capacity.MaxConcurrentSandboxes,
	}
}

func sandboxHostSupportedRuntimes(status *sandboxworker.Status, capabilities *sandboxworker.Capabilities) []string {
	if capabilities != nil && len(capabilities.RuntimeDrivers) > 0 {
		runtimes := make([]string, 0, len(capabilities.RuntimeDrivers))
		for _, driver := range capabilities.RuntimeDrivers {
			runtimes = append(runtimes, driver.ID)
		}
		return sortedUniqueStrings(runtimes)
	}
	if status == nil {
		return nil
	}
	return sortedUniqueStrings(status.SupportedRuntimeDrivers)
}

func sandboxHostSecurityFromWorker(status *sandboxworker.Status, capabilities *sandboxworker.Capabilities) *sandbox.SandboxSecurity {
	policy, ok := sandboxHostWorkerSecurityPolicy(status, capabilities)
	if !ok {
		return nil
	}

	security := &sandbox.SandboxSecurity{}
	if policy.Requested.NetworkPolicy != "" || policy.Enforced.NetworkPolicy != "" || policy.Enforced.NetworkEnforcement != "" {
		security.Network = &sandbox.SandboxNetworkSecurity{
			PolicyRequested: strings.TrimSpace(policy.Requested.NetworkPolicy),
			PolicyEnforced:  strings.TrimSpace(policy.Enforced.NetworkPolicy),
			EnforcementMode: strings.TrimSpace(policy.Enforced.NetworkEnforcement),
		}
	}
	if len(policy.Requested.CredentialModes) > 0 || len(policy.Enforced.CredentialModes) > 0 {
		security.Secrets = &sandbox.SandboxSecretSecurity{
			RequestedModes: sortedUniqueStrings(policy.Requested.CredentialModes),
			ActiveModes:    sortedUniqueStrings(policy.Enforced.CredentialModes),
		}
	}
	if security.Network == nil && security.Secrets == nil {
		return nil
	}
	return security
}

func sandboxHostWorkerSecurityPolicy(status *sandboxworker.Status, capabilities *sandboxworker.Capabilities) (sandboxworker.SecurityPolicy, bool) {
	if capabilities != nil && !zeroSandboxHostWorkerSecurityPolicy(capabilities.Security) {
		return capabilities.Security, true
	}
	if status != nil && !zeroSandboxHostWorkerSecurityPolicy(status.Security) {
		return status.Security, true
	}
	return sandboxworker.SecurityPolicy{}, false
}

func zeroSandboxHostWorkerSecurityPolicy(policy sandboxworker.SecurityPolicy) bool {
	return policy.Requested.NetworkPolicy == "" &&
		policy.Requested.NetworkEnforcement == "" &&
		len(policy.Requested.CredentialModes) == 0 &&
		policy.Requested.IsolationLevel == "" &&
		!policy.Requested.CredentialProxyMode &&
		policy.Enforced.NetworkPolicy == "" &&
		policy.Enforced.NetworkEnforcement == "" &&
		len(policy.Enforced.CredentialModes) == 0 &&
		policy.Enforced.IsolationLevel == "" &&
		!policy.Enforced.CredentialProxyMode
}

func sortedUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil
	}
	return result
}
