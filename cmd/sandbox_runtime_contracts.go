package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const SandboxRuntimeListContractType = "sandbox-runtime-list"
const SandboxRuntimeListContractVersion = "sandbox-runtime-list-v1"
const SandboxRuntimeStatusContractType = "sandbox-runtime-status"
const SandboxRuntimeStatusContractVersion = "sandbox-runtime-status-v1"

const (
	SandboxRuntimeSourceCached          = "cached"
	SandboxRuntimeSourceLiveRefreshed   = "live-refreshed"
	SandboxRuntimeSourceUnsupportedLive = "unsupported-live"
)

const (
	SandboxRuntimeReadinessReady       = "ready"
	SandboxRuntimeReadinessUnavailable = "unavailable"
	SandboxRuntimeReadinessUnknown     = "unknown"
)

const (
	SandboxRuntimeStatusErrorHostNotFound        = "host_not_found"
	SandboxRuntimeStatusErrorRuntimeNotFound     = "runtime_not_found"
	SandboxRuntimeStatusErrorLiveUnsupported     = "live_unsupported"
	SandboxRuntimeStatusErrorWorkerRefreshFailed = "worker_refresh_failed"
)

// SandboxRuntimeListResponse is the machine-readable JSON output for
// hal sandbox runtime list <host-id> --json.
type SandboxRuntimeListResponse struct {
	ContractType    string                        `json:"contractType"`
	ContractVersion string                        `json:"contractVersion"`
	Host            SandboxRuntimeHost            `json:"host"`
	Source          SandboxRuntimeSource          `json:"source"`
	Runtimes        []SandboxRuntimeListEntry     `json:"runtimes"`
	Capacity        SandboxRuntimeCapacitySummary `json:"capacity"`
	Security        SandboxRuntimeSecuritySummary `json:"security"`
	Diagnostics     []SandboxRuntimeDiagnostic    `json:"diagnostics"`
	Errors          []SandboxRuntimeError         `json:"errors"`
}

// SandboxRuntimeStatusResponse is the machine-readable JSON output for
// hal sandbox runtime status <host-id> <runtime-id> --json.
type SandboxRuntimeStatusResponse struct {
	ContractType        string                        `json:"contractType"`
	ContractVersion     string                        `json:"contractVersion"`
	Host                SandboxRuntimeHost            `json:"host"`
	Runtime             SandboxRuntimeStatusRuntime   `json:"runtime"`
	Source              SandboxRuntimeSource          `json:"source"`
	SupportedOperations []string                      `json:"supportedOperations"`
	Capacity            SandboxRuntimeCapacitySummary `json:"capacity"`
	Readiness           SandboxRuntimeReadiness       `json:"readiness"`
	Security            SandboxRuntimeSecuritySummary `json:"security"`
	Diagnostics         []SandboxRuntimeDiagnostic    `json:"diagnostics"`
	Errors              []SandboxRuntimeError         `json:"errors"`
}

// SandboxRuntimeHost identifies the inspected host without exposing raw
// endpoint values.
type SandboxRuntimeHost struct {
	ID       string                        `json:"id"`
	Name     string                        `json:"name"`
	Kind     string                        `json:"kind"`
	Endpoint SandboxRuntimeEndpointSummary `json:"endpoint"`
}

// SandboxRuntimeEndpointSummary summarizes an endpoint without raw socket
// paths, hostnames, credentials, query strings, or temp paths.
type SandboxRuntimeEndpointSummary struct {
	Type    string  `json:"type"`
	Summary string  `json:"summary"`
	Scheme  *string `json:"scheme"`
}

// SandboxRuntimeSource identifies where runtime metadata came from.
type SandboxRuntimeSource struct {
	Mode          string     `json:"mode"`
	RequestedLive bool       `json:"requestedLive"`
	CacheUpdated  bool       `json:"cacheUpdated"`
	RefreshedAt   *time.Time `json:"refreshedAt"`
	Summary       string     `json:"summary"`
}

// SandboxRuntimeStatusRuntime identifies a single runtime driver on a host.
type SandboxRuntimeStatusRuntime struct {
	ID             string  `json:"id"`
	HostKind       *string `json:"hostKind"`
	IsolationLevel *string `json:"isolationLevel"`
}

// SandboxRuntimeListEntry summarizes a runtime driver available on a host.
type SandboxRuntimeListEntry struct {
	ID                  string                        `json:"id"`
	HostKind            *string                       `json:"hostKind"`
	IsolationLevel      *string                       `json:"isolationLevel"`
	SupportedOperations []string                      `json:"supportedOperations"`
	Security            SandboxRuntimeSecuritySummary `json:"security"`
	Diagnostics         []SandboxRuntimeDiagnostic    `json:"diagnostics"`
}

// SandboxRuntimeCapacitySummary is a safe host capacity summary.
type SandboxRuntimeCapacitySummary struct {
	Summary                string `json:"summary"`
	CPUCores               *int   `json:"cpuCores"`
	MemoryMB               *int   `json:"memoryMb"`
	DiskGB                 *int   `json:"diskGb"`
	MaxConcurrentSandboxes *int   `json:"maxConcurrentSandboxes"`
	ActiveSandboxes        *int   `json:"activeSandboxes"`
}

// SandboxRuntimeReadiness is a safe runtime readiness summary.
type SandboxRuntimeReadiness struct {
	Status    string     `json:"status"`
	CheckedAt *time.Time `json:"checkedAt"`
	Summary   string     `json:"summary"`
}

// SandboxRuntimeSecuritySummary separates requested controls from controls
// actually enforced by durable metadata or live worker capabilities.
type SandboxRuntimeSecuritySummary struct {
	Requested SandboxRuntimeSecurityControls `json:"requested"`
	Enforced  SandboxRuntimeSecurityControls `json:"enforced"`
}

// SandboxRuntimeSecurityControls captures safe security posture metadata.
type SandboxRuntimeSecurityControls struct {
	NetworkPolicy       *string  `json:"networkPolicy,omitempty"`
	NetworkEnforcement  *string  `json:"networkEnforcement,omitempty"`
	CredentialModes     []string `json:"credentialModes,omitempty"`
	CredentialProxyMode *bool    `json:"credentialProxyMode,omitempty"`
	IsolationLevel      *string  `json:"isolationLevel,omitempty"`
}

// SandboxRuntimeDiagnostic is a non-fatal runtime inspection diagnostic.
type SandboxRuntimeDiagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// SandboxRuntimeError is a safe fatal runtime inspection error entry.
type SandboxRuntimeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newSandboxRuntimeListCachedResponse(host *sandbox.SandboxHost) SandboxRuntimeListResponse {
	return newSandboxRuntimeListResponse(host, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceCached,
		RequestedLive: false,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       "cached durable runtime metadata",
	}, nil, nil)
}

func newSandboxRuntimeListUnsupportedLiveResponse(host *sandbox.SandboxHost) SandboxRuntimeListResponse {
	hostKind := sandboxHostDisplayValue("", "unknown")
	if host != nil {
		hostKind = sandboxHostDisplayValue(host.Kind, "unknown")
	}
	return newSandboxRuntimeListResponse(host, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceUnsupportedLive,
		RequestedLive: true,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       fmt.Sprintf("live runtime inspection is unsupported for host kind %s; using cached durable metadata", hostKind),
	}, []SandboxRuntimeDiagnostic{
		{
			Code:     SandboxRuntimeStatusErrorLiveUnsupported,
			Severity: "warning",
			Message:  "live runtime inspection is unsupported for this host kind",
		},
	}, nil)
}

func newSandboxRuntimeListLiveResponse(host *sandbox.SandboxHost, status *sandboxworker.Status, capabilities *sandboxworker.Capabilities, refreshedAt time.Time) SandboxRuntimeListResponse {
	refreshedAt = refreshedAt.UTC()
	return SandboxRuntimeListResponse{
		ContractType:    SandboxRuntimeListContractType,
		ContractVersion: SandboxRuntimeListContractVersion,
		Host:            newSandboxRuntimeHost(host),
		Source: SandboxRuntimeSource{
			Mode:          SandboxRuntimeSourceLiveRefreshed,
			RequestedLive: true,
			CacheUpdated:  false,
			RefreshedAt:   &refreshedAt,
			Summary:       "live worker runtime capabilities",
		},
		Runtimes:    newSandboxRuntimeListEntriesFromWorkerCapabilities(capabilities),
		Capacity:    newSandboxRuntimeCapacitySummaryFromWorkerStatus(status, sandboxRuntimeHostCapacity(host)),
		Security:    newSandboxRuntimeSecuritySummaryFromWorkerCapabilities(capabilities),
		Diagnostics: []SandboxRuntimeDiagnostic{},
		Errors:      []SandboxRuntimeError{},
	}
}

func newSandboxRuntimeListResponse(host *sandbox.SandboxHost, source SandboxRuntimeSource, diagnostics []SandboxRuntimeDiagnostic, responseErrors []SandboxRuntimeError) SandboxRuntimeListResponse {
	if diagnostics == nil {
		diagnostics = []SandboxRuntimeDiagnostic{}
	}
	if responseErrors == nil {
		responseErrors = []SandboxRuntimeError{}
	}
	return SandboxRuntimeListResponse{
		ContractType:    SandboxRuntimeListContractType,
		ContractVersion: SandboxRuntimeListContractVersion,
		Host:            newSandboxRuntimeHost(host),
		Source:          source,
		Runtimes:        newSandboxRuntimeListEntries(sandboxRuntimeHostSupportedRuntimes(host)),
		Capacity:        newSandboxRuntimeCapacitySummary(sandboxRuntimeHostCapacity(host)),
		Security:        newSandboxRuntimeSecuritySummary(sandboxRuntimeHostSecurity(host)),
		Diagnostics:     diagnostics,
		Errors:          responseErrors,
	}
}

func newSandboxRuntimeHost(host *sandbox.SandboxHost) SandboxRuntimeHost {
	if host == nil {
		return SandboxRuntimeHost{
			Kind:     "unknown",
			Endpoint: newSandboxRuntimeEndpointSummary(""),
		}
	}
	return SandboxRuntimeHost{
		ID:       sandboxHostDisplayValue(host.ID, ""),
		Name:     sandboxHostDisplayValue(host.Name, host.ID),
		Kind:     sandboxHostDisplayValue(host.Kind, "unknown"),
		Endpoint: newSandboxRuntimeEndpointSummary(host.Endpoint),
	}
}

func newSandboxRuntimeEndpointSummary(endpoint string) SandboxRuntimeEndpointSummary {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return SandboxRuntimeEndpointSummary{
			Type:    "none",
			Summary: "none",
			Scheme:  nil,
		}
	}

	lowerEndpoint := strings.ToLower(endpoint)
	if strings.HasPrefix(lowerEndpoint, "unix://") || strings.HasPrefix(lowerEndpoint, "unix:") {
		scheme := "unix"
		return SandboxRuntimeEndpointSummary{
			Type:    "unix_socket",
			Summary: "local Unix socket",
			Scheme:  &scheme,
		}
	}

	if index := strings.Index(endpoint, ":"); index > 0 {
		scheme := strings.ToLower(strings.TrimSpace(endpoint[:index]))
		if scheme != "" {
			return SandboxRuntimeEndpointSummary{
				Type:    "endpoint",
				Summary: scheme + " endpoint",
				Scheme:  &scheme,
			}
		}
	}

	return SandboxRuntimeEndpointSummary{
		Type:    "configured",
		Summary: "configured",
		Scheme:  nil,
	}
}

func newSandboxRuntimeListEntries(runtimeIDs []string) []SandboxRuntimeListEntry {
	runtimeIDs = sortedUniqueStrings(runtimeIDs)
	if len(runtimeIDs) == 0 {
		return []SandboxRuntimeListEntry{}
	}
	entries := make([]SandboxRuntimeListEntry, 0, len(runtimeIDs))
	for _, runtimeID := range runtimeIDs {
		entries = append(entries, SandboxRuntimeListEntry{
			ID:                  runtimeID,
			HostKind:            nil,
			IsolationLevel:      nil,
			SupportedOperations: []string{},
			Security:            newSandboxRuntimeSecuritySummary(nil),
			Diagnostics:         []SandboxRuntimeDiagnostic{},
		})
	}
	return entries
}

func newSandboxRuntimeListEntriesFromWorkerCapabilities(capabilities *sandboxworker.Capabilities) []SandboxRuntimeListEntry {
	if capabilities == nil || len(capabilities.RuntimeDrivers) == 0 {
		return []SandboxRuntimeListEntry{}
	}
	drivers := append([]sandboxworker.RuntimeDriver(nil), capabilities.RuntimeDrivers...)
	sort.SliceStable(drivers, func(i, j int) bool {
		return strings.TrimSpace(drivers[i].ID) < strings.TrimSpace(drivers[j].ID)
	})

	entries := make([]SandboxRuntimeListEntry, 0, len(drivers))
	for _, driver := range drivers {
		runtimeID := strings.TrimSpace(driver.ID)
		if runtimeID == "" {
			continue
		}
		operations := sandboxRuntimeStringSlice(driver.Operations)
		if operations == nil {
			operations = []string{}
		}
		entries = append(entries, SandboxRuntimeListEntry{
			ID:                  runtimeID,
			HostKind:            sandboxRuntimeStringPtr(driver.HostKind),
			IsolationLevel:      sandboxRuntimeStringPtr(driver.IsolationLevel),
			SupportedOperations: operations,
			Security:            newSandboxRuntimeSecuritySummaryFromWorkerPolicy(driver.Security),
			Diagnostics:         []SandboxRuntimeDiagnostic{},
		})
	}
	if len(entries) == 0 {
		return []SandboxRuntimeListEntry{}
	}
	return entries
}

func newSandboxRuntimeCapacitySummary(capacity *sandbox.HostCapacity) SandboxRuntimeCapacitySummary {
	if capacity == nil {
		return SandboxRuntimeCapacitySummary{
			Summary:                sandboxHostCapacitySummary(nil),
			CPUCores:               nil,
			MemoryMB:               nil,
			DiskGB:                 nil,
			MaxConcurrentSandboxes: nil,
			ActiveSandboxes:        nil,
		}
	}
	return SandboxRuntimeCapacitySummary{
		Summary:                sandboxHostCapacitySummary(capacity),
		CPUCores:               sandboxRuntimePositiveIntPtr(capacity.CPUCores),
		MemoryMB:               sandboxRuntimePositiveIntPtr(capacity.MemoryMB),
		DiskGB:                 sandboxRuntimePositiveIntPtr(capacity.DiskGB),
		MaxConcurrentSandboxes: sandboxRuntimePositiveIntPtr(capacity.MaxConcurrentSandboxes),
		ActiveSandboxes:        nil,
	}
}

func newSandboxRuntimeCapacitySummaryFromWorkerStatus(status *sandboxworker.Status, fallback *sandbox.HostCapacity) SandboxRuntimeCapacitySummary {
	if status == nil {
		return newSandboxRuntimeCapacitySummary(fallback)
	}
	capacity := status.Capacity
	if capacity.MaxConcurrentSandboxes <= 0 && capacity.ActiveSandboxes <= 0 {
		return newSandboxRuntimeCapacitySummary(fallback)
	}

	summary := "unknown"
	switch {
	case capacity.MaxConcurrentSandboxes > 0:
		summary = fmt.Sprintf("%d of %d sandboxes active", capacity.ActiveSandboxes, capacity.MaxConcurrentSandboxes)
	case capacity.ActiveSandboxes == 1:
		summary = "1 sandbox active"
	case capacity.ActiveSandboxes > 1:
		summary = fmt.Sprintf("%d sandboxes active", capacity.ActiveSandboxes)
	}
	return SandboxRuntimeCapacitySummary{
		Summary:                summary,
		CPUCores:               nil,
		MemoryMB:               nil,
		DiskGB:                 nil,
		MaxConcurrentSandboxes: sandboxRuntimePositiveIntPtr(capacity.MaxConcurrentSandboxes),
		ActiveSandboxes:        sandboxRuntimeNonNegativeIntPtr(capacity.ActiveSandboxes),
	}
}

func newSandboxRuntimeSecuritySummary(security *sandbox.SandboxSecurity) SandboxRuntimeSecuritySummary {
	if security == nil {
		return SandboxRuntimeSecuritySummary{
			Requested: SandboxRuntimeSecurityControls{},
			Enforced:  SandboxRuntimeSecurityControls{},
		}
	}

	var requested SandboxRuntimeSecurityControls
	var enforced SandboxRuntimeSecurityControls
	if security.Network != nil {
		requested.NetworkPolicy = sandboxRuntimeStringPtr(security.Network.PolicyRequested)
		enforced.NetworkPolicy = sandboxRuntimeStringPtr(security.Network.PolicyEnforced)
		enforced.NetworkEnforcement = sandboxRuntimeStringPtr(security.Network.EnforcementMode)
	}
	if security.Secrets != nil {
		requested.CredentialModes = sandboxRuntimeStringSlice(security.Secrets.RequestedModes)
		enforced.CredentialModes = sandboxRuntimeStringSlice(security.Secrets.ActiveModes)
	}

	return SandboxRuntimeSecuritySummary{
		Requested: requested,
		Enforced:  enforced,
	}
}

func newSandboxRuntimeSecuritySummaryFromWorkerCapabilities(capabilities *sandboxworker.Capabilities) SandboxRuntimeSecuritySummary {
	if capabilities == nil {
		return newSandboxRuntimeSecuritySummaryFromWorkerPolicy(sandboxworker.SecurityPolicy{})
	}
	return newSandboxRuntimeSecuritySummaryFromWorkerPolicy(capabilities.Security)
}

func newSandboxRuntimeSecuritySummaryFromWorkerPolicy(policy sandboxworker.SecurityPolicy) SandboxRuntimeSecuritySummary {
	if sandboxRuntimeWorkerSecurityPolicyEmpty(policy) {
		return SandboxRuntimeSecuritySummary{
			Requested: SandboxRuntimeSecurityControls{},
			Enforced:  SandboxRuntimeSecurityControls{},
		}
	}
	return SandboxRuntimeSecuritySummary{
		Requested: sandboxRuntimeSecurityControlsFromWorker(policy.Requested),
		Enforced:  sandboxRuntimeSecurityControlsFromWorker(policy.Enforced),
	}
}

func sandboxRuntimeSecurityControlsFromWorker(controls sandboxworker.SecurityControls) SandboxRuntimeSecurityControls {
	if sandboxRuntimeWorkerSecurityControlsEmpty(controls) {
		return SandboxRuntimeSecurityControls{}
	}
	return SandboxRuntimeSecurityControls{
		NetworkPolicy:       sandboxRuntimeStringPtr(controls.NetworkPolicy),
		NetworkEnforcement:  sandboxRuntimeStringPtr(controls.NetworkEnforcement),
		CredentialModes:     sandboxRuntimeStringSlice(controls.CredentialModes),
		CredentialProxyMode: sandboxRuntimeBoolPtr(controls.CredentialProxyMode),
		IsolationLevel:      sandboxRuntimeStringPtr(controls.IsolationLevel),
	}
}

func sandboxRuntimeWorkerSecurityPolicyEmpty(policy sandboxworker.SecurityPolicy) bool {
	return sandboxRuntimeWorkerSecurityControlsEmpty(policy.Requested) && sandboxRuntimeWorkerSecurityControlsEmpty(policy.Enforced)
}

func sandboxRuntimeWorkerSecurityControlsEmpty(controls sandboxworker.SecurityControls) bool {
	return strings.TrimSpace(controls.NetworkPolicy) == "" &&
		strings.TrimSpace(controls.NetworkEnforcement) == "" &&
		len(controls.CredentialModes) == 0 &&
		strings.TrimSpace(controls.IsolationLevel) == "" &&
		!controls.CredentialProxyMode
}

func sandboxRuntimeHostSupportedRuntimes(host *sandbox.SandboxHost) []string {
	if host == nil {
		return nil
	}
	return host.SupportedRuntimes
}

func sandboxRuntimeHostCapacity(host *sandbox.SandboxHost) *sandbox.HostCapacity {
	if host == nil {
		return nil
	}
	return host.Capacity
}

func sandboxRuntimeHostSecurity(host *sandbox.SandboxHost) *sandbox.SandboxSecurity {
	if host == nil {
		return nil
	}
	return host.Security
}

func sandboxRuntimePositiveIntPtr(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func sandboxRuntimeNonNegativeIntPtr(value int) *int {
	if value < 0 {
		return nil
	}
	return &value
}

func sandboxRuntimeStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func sandboxRuntimeStringSlice(values []string) []string {
	values = sortedUniqueStrings(values)
	if len(values) == 0 {
		return nil
	}
	return values
}

func sandboxRuntimeBoolPtr(value bool) *bool {
	return &value
}
