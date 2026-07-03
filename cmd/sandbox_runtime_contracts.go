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
	Requested                      SandboxRuntimeSecurityControls                               `json:"requested"`
	Enforced                       SandboxRuntimeSecurityControls                               `json:"enforced"`
	NetworkPolicyResult            *sandbox.SandboxNetworkPolicyResult                          `json:"networkPolicyResult,omitempty"`
	CapabilityReadiness            *sandbox.SandboxSecurityCapabilityReadinessOutput            `json:"capabilityReadiness,omitempty"`
	CapabilityReadinessDiagnostics *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary `json:"capabilityReadinessDiagnostics,omitempty"`
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

func newSandboxRuntimeListHostNotFoundResponse(hostID string) SandboxRuntimeListResponse {
	resp := newSandboxRuntimeListResponse(nil, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceCached,
		RequestedLive: false,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       "cached durable runtime metadata",
	}, nil, []SandboxRuntimeError{
		{
			Code:    SandboxRuntimeStatusErrorHostNotFound,
			Message: "host record was not found",
		},
	})
	resp.Host.ID = sandboxHostDisplayValue(hostID, "")
	resp.Host.Name = sandboxHostDisplayValue("", hostID)
	return resp
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

func newSandboxRuntimeStatusCachedResponse(host *sandbox.SandboxHost, runtimeID string) SandboxRuntimeStatusResponse {
	return newSandboxRuntimeStatusResponse(host, runtimeID, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceCached,
		RequestedLive: false,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       "cached durable runtime metadata",
	}, SandboxRuntimeReadiness{
		Status:    SandboxRuntimeReadinessUnknown,
		CheckedAt: nil,
		Summary:   "cached metadata confirms runtime registration; live readiness unknown",
	}, newSandboxRuntimeSecuritySummary(sandboxRuntimeHostSecurity(host)), nil, nil)
}

func newSandboxRuntimeStatusUnsupportedLiveResponse(host *sandbox.SandboxHost, runtimeID string) SandboxRuntimeStatusResponse {
	hostKind := sandboxHostDisplayValue("", "unknown")
	if host != nil {
		hostKind = sandboxHostDisplayValue(host.Kind, "unknown")
	}
	return newSandboxRuntimeStatusResponse(host, runtimeID, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceUnsupportedLive,
		RequestedLive: true,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       fmt.Sprintf("live runtime inspection is unsupported for host kind %s; using cached durable metadata", hostKind),
	}, SandboxRuntimeReadiness{
		Status:    SandboxRuntimeReadinessUnknown,
		CheckedAt: nil,
		Summary:   "cached metadata confirms runtime registration; live readiness unsupported",
	}, newSandboxRuntimeSecuritySummary(sandboxRuntimeHostSecurity(host)), []SandboxRuntimeDiagnostic{
		{
			Code:     SandboxRuntimeStatusErrorLiveUnsupported,
			Severity: "warning",
			Message:  "live runtime inspection is unsupported for this host kind",
		},
	}, nil)
}

func newSandboxRuntimeStatusUnsupportedLiveRuntimeNotFoundResponse(host *sandbox.SandboxHost, runtimeID string) SandboxRuntimeStatusResponse {
	hostKind := sandboxHostDisplayValue("", "unknown")
	if host != nil {
		hostKind = sandboxHostDisplayValue(host.Kind, "unknown")
	}
	return newSandboxRuntimeStatusResponse(host, runtimeID, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceUnsupportedLive,
		RequestedLive: true,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       fmt.Sprintf("live runtime inspection is unsupported for host kind %s; using cached durable metadata", hostKind),
	}, SandboxRuntimeReadiness{
		Status:    SandboxRuntimeReadinessUnavailable,
		CheckedAt: nil,
		Summary:   "runtime is not registered for this host",
	}, newSandboxRuntimeSecuritySummary(sandboxRuntimeHostSecurity(host)), []SandboxRuntimeDiagnostic{
		{
			Code:     SandboxRuntimeStatusErrorLiveUnsupported,
			Severity: "warning",
			Message:  "live runtime inspection is unsupported for this host kind",
		},
	}, []SandboxRuntimeError{
		{
			Code:    SandboxRuntimeStatusErrorRuntimeNotFound,
			Message: "runtime is not registered for this host",
		},
	})
}

func newSandboxRuntimeStatusLiveResponse(host *sandbox.SandboxHost, runtimeID string, status *sandboxworker.Status, capabilities *sandboxworker.Capabilities, refreshedAt time.Time) (SandboxRuntimeStatusResponse, bool) {
	driver, ok := sandboxRuntimeWorkerDriver(capabilities, runtimeID)
	if !ok {
		return SandboxRuntimeStatusResponse{}, false
	}
	refreshedAt = refreshedAt.UTC()
	return SandboxRuntimeStatusResponse{
		ContractType:        SandboxRuntimeStatusContractType,
		ContractVersion:     SandboxRuntimeStatusContractVersion,
		Host:                newSandboxRuntimeHost(host),
		Runtime:             newSandboxRuntimeStatusRuntimeFromWorkerDriver(runtimeID, driver),
		Source:              newSandboxRuntimeStatusLiveSource(refreshedAt),
		SupportedOperations: sandboxRuntimeWorkerOperations(driver.Operations),
		Capacity:            newSandboxRuntimeCapacitySummaryFromWorkerStatus(status, sandboxRuntimeHostCapacity(host)),
		Readiness:           newSandboxRuntimeReadinessFromWorkerStatus(status, refreshedAt),
		Security:            newSandboxRuntimeSecuritySummaryFromWorkerDriver(driver),
		Diagnostics:         []SandboxRuntimeDiagnostic{},
		Errors:              []SandboxRuntimeError{},
	}, true
}

func newSandboxRuntimeStatusLiveRuntimeNotFoundResponse(host *sandbox.SandboxHost, runtimeID string, status *sandboxworker.Status, refreshedAt time.Time) SandboxRuntimeStatusResponse {
	refreshedAt = refreshedAt.UTC()
	return SandboxRuntimeStatusResponse{
		ContractType:        SandboxRuntimeStatusContractType,
		ContractVersion:     SandboxRuntimeStatusContractVersion,
		Host:                newSandboxRuntimeHost(host),
		Runtime:             newSandboxRuntimeStatusRuntime(runtimeID),
		Source:              newSandboxRuntimeStatusLiveSource(refreshedAt),
		SupportedOperations: []string{},
		Capacity:            newSandboxRuntimeCapacitySummaryFromWorkerStatus(status, sandboxRuntimeHostCapacity(host)),
		Readiness: SandboxRuntimeReadiness{
			Status:    SandboxRuntimeReadinessUnavailable,
			CheckedAt: &refreshedAt,
			Summary:   "runtime is not advertised by this worker",
		},
		Security:    newSandboxRuntimeSecuritySummary(nil),
		Diagnostics: []SandboxRuntimeDiagnostic{},
		Errors: []SandboxRuntimeError{
			{
				Code:    SandboxRuntimeStatusErrorRuntimeNotFound,
				Message: "runtime is not advertised by this worker",
			},
		},
	}
}

func newSandboxRuntimeStatusHostNotFoundResponse(hostID, runtimeID string) SandboxRuntimeStatusResponse {
	resp := newSandboxRuntimeStatusResponse(nil, runtimeID, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceCached,
		RequestedLive: false,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       "cached durable runtime metadata",
	}, SandboxRuntimeReadiness{
		Status:    SandboxRuntimeReadinessUnavailable,
		CheckedAt: nil,
		Summary:   "host record was not found",
	}, newSandboxRuntimeSecuritySummary(nil), nil, []SandboxRuntimeError{
		{
			Code:    SandboxRuntimeStatusErrorHostNotFound,
			Message: "host record was not found",
		},
	})
	resp.Host.ID = sandboxHostDisplayValue(hostID, "")
	resp.Host.Name = sandboxHostDisplayValue("", hostID)
	return resp
}

func newSandboxRuntimeStatusRuntimeNotFoundResponse(host *sandbox.SandboxHost, runtimeID string) SandboxRuntimeStatusResponse {
	return newSandboxRuntimeStatusResponse(host, runtimeID, SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceCached,
		RequestedLive: false,
		CacheUpdated:  false,
		RefreshedAt:   nil,
		Summary:       "cached durable runtime metadata",
	}, SandboxRuntimeReadiness{
		Status:    SandboxRuntimeReadinessUnavailable,
		CheckedAt: nil,
		Summary:   "runtime is not registered for this host",
	}, newSandboxRuntimeSecuritySummary(nil), nil, []SandboxRuntimeError{
		{
			Code:    SandboxRuntimeStatusErrorRuntimeNotFound,
			Message: "runtime is not registered for this host",
		},
	})
}

func newSandboxRuntimeStatusResponse(host *sandbox.SandboxHost, runtimeID string, source SandboxRuntimeSource, readiness SandboxRuntimeReadiness, security SandboxRuntimeSecuritySummary, diagnostics []SandboxRuntimeDiagnostic, responseErrors []SandboxRuntimeError) SandboxRuntimeStatusResponse {
	if diagnostics == nil {
		diagnostics = []SandboxRuntimeDiagnostic{}
	}
	if responseErrors == nil {
		responseErrors = []SandboxRuntimeError{}
	}
	return SandboxRuntimeStatusResponse{
		ContractType:        SandboxRuntimeStatusContractType,
		ContractVersion:     SandboxRuntimeStatusContractVersion,
		Host:                newSandboxRuntimeHost(host),
		Runtime:             newSandboxRuntimeStatusRuntime(runtimeID),
		Source:              source,
		SupportedOperations: []string{},
		Capacity:            newSandboxRuntimeCapacitySummary(sandboxRuntimeHostCapacity(host)),
		Readiness:           readiness,
		Security:            security,
		Diagnostics:         diagnostics,
		Errors:              responseErrors,
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
	if strings.HasPrefix(endpoint, "/") {
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

func newSandboxRuntimeStatusRuntime(runtimeID string) SandboxRuntimeStatusRuntime {
	return SandboxRuntimeStatusRuntime{
		ID:             sandboxHostDisplayValue(runtimeID, ""),
		HostKind:       nil,
		IsolationLevel: nil,
	}
}

func newSandboxRuntimeStatusRuntimeFromWorkerDriver(runtimeID string, driver sandboxworker.RuntimeDriver) SandboxRuntimeStatusRuntime {
	return SandboxRuntimeStatusRuntime{
		ID:             sandboxHostDisplayValue(runtimeID, driver.ID),
		HostKind:       sandboxRuntimeStringPtr(driver.HostKind),
		IsolationLevel: sandboxRuntimeStringPtr(driver.IsolationLevel),
	}
}

func newSandboxRuntimeStatusLiveSource(refreshedAt time.Time) SandboxRuntimeSource {
	refreshedAt = refreshedAt.UTC()
	return SandboxRuntimeSource{
		Mode:          SandboxRuntimeSourceLiveRefreshed,
		RequestedLive: true,
		CacheUpdated:  false,
		RefreshedAt:   &refreshedAt,
		Summary:       "live worker runtime capabilities",
	}
}

func newSandboxRuntimeReadinessFromWorkerStatus(status *sandboxworker.Status, checkedAt time.Time) SandboxRuntimeReadiness {
	checkedAt = checkedAt.UTC()
	healthStatus := sandboxworker.HealthStatusUnknown
	if status != nil {
		healthStatus = strings.TrimSpace(status.Health.Status)
	}
	readinessStatus := SandboxRuntimeReadinessUnknown
	switch healthStatus {
	case sandboxworker.HealthStatusHealthy:
		readinessStatus = SandboxRuntimeReadinessReady
	case sandboxworker.HealthStatusUnhealthy:
		readinessStatus = SandboxRuntimeReadinessUnavailable
	case sandboxworker.HealthStatusDegraded, sandboxworker.HealthStatusUnknown:
		readinessStatus = SandboxRuntimeReadinessUnknown
	case "":
		healthStatus = sandboxworker.HealthStatusUnknown
	default:
		readinessStatus = SandboxRuntimeReadinessUnknown
	}
	return SandboxRuntimeReadiness{
		Status:    readinessStatus,
		CheckedAt: &checkedAt,
		Summary:   "worker health is " + healthStatus,
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

func sandboxRuntimeWorkerDriver(capabilities *sandboxworker.Capabilities, runtimeID string) (sandboxworker.RuntimeDriver, bool) {
	runtimeID = strings.TrimSpace(runtimeID)
	if capabilities == nil || runtimeID == "" {
		return sandboxworker.RuntimeDriver{}, false
	}
	for _, driver := range capabilities.RuntimeDrivers {
		if strings.TrimSpace(driver.ID) == runtimeID {
			return driver, true
		}
	}
	return sandboxworker.RuntimeDriver{}, false
}

func sandboxRuntimeWorkerOperations(operations []string) []string {
	sorted := sandboxRuntimeStringSlice(operations)
	if sorted == nil {
		return []string{}
	}
	return sorted
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
			Security:            newSandboxRuntimeSecuritySummaryFromWorkerDriver(driver),
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
	security = sanitizeCommandSandboxSecurity(security)
	if security == nil {
		return SandboxRuntimeSecuritySummary{
			Requested: SandboxRuntimeSecurityControls{},
			Enforced:  SandboxRuntimeSecurityControls{},
		}
	}

	var requested SandboxRuntimeSecurityControls
	var enforced SandboxRuntimeSecurityControls
	var policyResult *sandbox.SandboxNetworkPolicyResult
	capabilityReadiness := sandboxRuntimeCapabilityReadinessFromSandboxSecurity(security)
	if security.Network != nil {
		requested.NetworkPolicy = sandboxRuntimeStringPtr(security.Network.PolicyRequested)
		enforced.NetworkPolicy = sandboxRuntimeStringPtr(security.Network.PolicyEnforced)
		enforced.NetworkEnforcement = sandboxRuntimeStringPtr(security.Network.EnforcementMode)
		policyResult = sandbox.CloneSandboxNetworkPolicyResultPtr(security.Network.PolicyResult)
	}
	if security.Secrets != nil {
		requested.CredentialModes = sandboxRuntimeStringSlice(security.Secrets.RequestedModes)
		enforced.CredentialModes = sandboxRuntimeStringSlice(security.Secrets.ActiveModes)
	}

	return SandboxRuntimeSecuritySummary{
		Requested:                      requested,
		Enforced:                       enforced,
		NetworkPolicyResult:            policyResult,
		CapabilityReadiness:            capabilityReadiness,
		CapabilityReadinessDiagnostics: sandboxRuntimeCapabilityReadinessDiagnostics(capabilityReadiness),
	}
}

func newSandboxRuntimeSecuritySummaryFromWorkerCapabilities(capabilities *sandboxworker.Capabilities) SandboxRuntimeSecuritySummary {
	if capabilities == nil {
		return newSandboxRuntimeSecuritySummaryFromWorkerPolicy(sandboxworker.SecurityPolicy{})
	}
	return newSandboxRuntimeSecuritySummaryFromWorkerPolicy(capabilities.Security)
}

func newSandboxRuntimeSecuritySummaryFromWorkerDriver(driver sandboxworker.RuntimeDriver) SandboxRuntimeSecuritySummary {
	return newSandboxRuntimeSecuritySummaryFromWorkerPolicyAndRuntime(driver.Security, sandboxRuntimeStateFromWorkerDriver(driver))
}

func newSandboxRuntimeSecuritySummaryFromWorkerPolicy(policy sandboxworker.SecurityPolicy) SandboxRuntimeSecuritySummary {
	return newSandboxRuntimeSecuritySummaryFromWorkerPolicyAndRuntime(policy, nil)
}

func newSandboxRuntimeSecuritySummaryFromWorkerPolicyAndRuntime(policy sandboxworker.SecurityPolicy, runtime *sandbox.SandboxRuntimeState) SandboxRuntimeSecuritySummary {
	capabilityReadiness := sandboxRuntimeCapabilityReadinessFromWorkerPolicy(policy, runtime)
	if sandboxRuntimeWorkerSecurityPolicyEmpty(policy) && capabilityReadiness == nil {
		return SandboxRuntimeSecuritySummary{
			Requested: SandboxRuntimeSecurityControls{},
			Enforced:  SandboxRuntimeSecurityControls{},
		}
	}
	policyResult := sandboxNetworkPolicyResultFromWorkerPolicy(policy)
	requested := sandboxRuntimeSecurityControlsFromWorker(policy.Requested)
	enforced := sandboxRuntimeSecurityControlsFromWorker(policy.Enforced)
	if network := sanitizeCommandSandboxNetworkSecurity(&sandbox.SandboxNetworkSecurity{
		PolicyRequested: strings.TrimSpace(policy.Requested.NetworkPolicy),
		PolicyEnforced:  strings.TrimSpace(policy.Enforced.NetworkPolicy),
		EnforcementMode: strings.TrimSpace(policy.Enforced.NetworkEnforcement),
		PolicyResult:    policyResult,
	}); network != nil {
		requested.NetworkPolicy = sandboxRuntimeStringPtr(network.PolicyRequested)
		enforced.NetworkPolicy = sandboxRuntimeStringPtr(network.PolicyEnforced)
		enforced.NetworkEnforcement = sandboxRuntimeStringPtr(network.EnforcementMode)
		policyResult = sandbox.CloneSandboxNetworkPolicyResultPtr(network.PolicyResult)
	}
	return SandboxRuntimeSecuritySummary{
		Requested:                      requested,
		Enforced:                       enforced,
		NetworkPolicyResult:            policyResult,
		CapabilityReadiness:            capabilityReadiness,
		CapabilityReadinessDiagnostics: sandboxRuntimeCapabilityReadinessDiagnostics(capabilityReadiness),
	}
}

func sandboxRuntimeCapabilityReadinessDiagnostics(readiness *sandbox.SandboxSecurityCapabilityReadinessOutput) *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary {
	readiness = sandbox.CloneSandboxSecurityCapabilityReadinessOutputPtr(readiness)
	if readiness == nil {
		return nil
	}
	summary := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	return &summary
}

func sandboxRuntimeCapabilityReadinessFromSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurityCapabilityReadinessOutput {
	if security == nil {
		return nil
	}
	if capabilityReadiness := sandbox.CloneSandboxSecurityCapabilityReadinessOutputPtr(security.CapabilityReadiness); capabilityReadiness != nil {
		return capabilityReadiness
	}
	return sandbox.EvaluateProjectedSandboxSecurityCapabilityReadiness(
		sandbox.ProjectSandboxSecurityCapabilityReadinessInput(security),
	)
}

func sandboxRuntimeCapabilityReadinessFromWorkerPolicy(policy sandboxworker.SecurityPolicy, runtime *sandbox.SandboxRuntimeState) *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return sandbox.EvaluateProjectedSandboxSecurityCapabilityReadiness(
		sandbox.ProjectSandboxSecurityCapabilityReadinessInput(sandboxSecurityFromWorkerPolicy(policy)),
		sandbox.ProjectSandboxWorkerRuntimeCapabilityReadinessInput(sandbox.SandboxWorkerRuntimeCapabilityReadinessProjection{
			Runtime:        runtime,
			WorkerPostures: []sandbox.SandboxSecurityCapabilityWorkerPostureMetadata{sandboxRuntimeWorkerPostureFromPolicy(policy)},
		}),
	)
}

func sandboxRuntimeStateFromWorkerDriver(driver sandboxworker.RuntimeDriver) *sandbox.SandboxRuntimeState {
	runtimeID := strings.TrimSpace(driver.ID)
	isolationLevel := strings.TrimSpace(driver.IsolationLevel)
	if runtimeID == "" && isolationLevel == "" {
		return nil
	}
	return &sandbox.SandboxRuntimeState{
		Driver:         runtimeID,
		IsolationLevel: isolationLevel,
	}
}

func sandboxRuntimeWorkerPostureFromPolicy(policy sandboxworker.SecurityPolicy) sandbox.SandboxSecurityCapabilityWorkerPostureMetadata {
	return sandbox.SandboxSecurityCapabilityWorkerPostureMetadata{
		IsolationLevel:      strings.TrimSpace(policy.Enforced.IsolationLevel),
		NetworkPolicy:       strings.TrimSpace(policy.Enforced.NetworkPolicy),
		NetworkEnforcement:  sandboxNetworkEnforcementModeFromWorker(policy.Enforced.NetworkEnforcement),
		CredentialModes:     sandboxRuntimeStringSlice(policy.Enforced.CredentialModes),
		CredentialProxyMode: policy.Enforced.CredentialProxyMode,
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
