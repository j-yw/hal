package cmd

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const SandboxHostListContractVersion = "sandbox-host-list-v1"
const SandboxHostStatusContractVersion = "sandbox-host-status-v1"

const (
	SandboxHostStatusSourceCached        = "cached"
	SandboxHostStatusSourceLiveRefreshed = "live-refreshed"
)

// SandboxHostListResponse is the machine-readable JSON output for
// hal sandbox host list --json.
type SandboxHostListResponse struct {
	ContractVersion string                 `json:"contractVersion"`
	Hosts           []SandboxHostListEntry `json:"hosts"`
	Totals          SandboxHostListTotals  `json:"totals"`
}

// SandboxHostListEntry is the safe host summary embedded by host list JSON.
type SandboxHostListEntry struct {
	ID                string                  `json:"id"`
	Name              string                  `json:"name"`
	Kind              string                  `json:"kind"`
	Endpoint          SandboxHostListEndpoint `json:"endpoint"`
	Health            SandboxHostListHealth   `json:"health"`
	SupportedRuntimes []string                `json:"supportedRuntimes"`
	Capacity          SandboxHostListCapacity `json:"capacity"`
}

// SandboxHostListEndpoint summarizes an endpoint without exposing raw paths,
// hostnames, credentials, or query strings.
type SandboxHostListEndpoint struct {
	Type    string `json:"type"`
	Summary string `json:"summary"`
	Scheme  string `json:"scheme,omitempty"`
}

// SandboxHostListHealth represents cached durable host health.
type SandboxHostListHealth struct {
	Status          string     `json:"status"`
	CheckedAt       *time.Time `json:"checkedAt,omitempty"`
	LastHeartbeatAt *time.Time `json:"lastHeartbeatAt,omitempty"`
	Message         string     `json:"message,omitempty"`
}

// SandboxHostListCapacity represents cached durable host capacity.
type SandboxHostListCapacity struct {
	Summary                string `json:"summary"`
	CPUCores               int    `json:"cpuCores,omitempty"`
	MemoryMB               int    `json:"memoryMb,omitempty"`
	DiskGB                 int    `json:"diskGb,omitempty"`
	MaxConcurrentSandboxes int    `json:"maxConcurrentSandboxes,omitempty"`
}

// SandboxHostListTotals holds aggregate counts for host list JSON.
type SandboxHostListTotals struct {
	Total int `json:"total"`
}

// SandboxHostStatusResponse is the machine-readable JSON output for
// hal sandbox host status --json.
type SandboxHostStatusResponse struct {
	ContractVersion string                   `json:"contractVersion"`
	Source          SandboxHostStatusSource  `json:"source"`
	Refresh         SandboxHostStatusRefresh `json:"refresh"`
	Host            SandboxHostStatusHost    `json:"host"`
}

// SandboxHostStatusSource identifies whether status came from cached durable
// state or a live worker refresh.
type SandboxHostStatusSource struct {
	Mode    string `json:"mode"`
	Summary string `json:"summary"`
}

// SandboxHostStatusRefresh records request/refresh metadata for status JSON.
type SandboxHostStatusRefresh struct {
	RequestedLive bool       `json:"requestedLive"`
	CacheUpdated  bool       `json:"cacheUpdated"`
	RefreshedAt   *time.Time `json:"refreshedAt,omitempty"`
}

// SandboxHostStatusHost is the safe host payload embedded by status JSON.
type SandboxHostStatusHost struct {
	ID                string                  `json:"id"`
	Name              string                  `json:"name"`
	Kind              string                  `json:"kind"`
	Endpoint          SandboxHostListEndpoint `json:"endpoint"`
	Health            SandboxHostListHealth   `json:"health"`
	SupportedRuntimes []string                `json:"supportedRuntimes"`
	Capacity          SandboxHostListCapacity `json:"capacity"`
}

func newSandboxHostListResponse(hosts []*sandbox.SandboxHost) SandboxHostListResponse {
	entries := make([]SandboxHostListEntry, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}
		entries = append(entries, newSandboxHostListEntry(host))
	}
	return SandboxHostListResponse{
		ContractVersion: SandboxHostListContractVersion,
		Hosts:           entries,
		Totals: SandboxHostListTotals{
			Total: len(entries),
		},
	}
}

func newSandboxHostStatusResponse(host *sandbox.SandboxHost, live bool) SandboxHostStatusResponse {
	mode := SandboxHostStatusSourceCached
	summary := "cached durable registry (not live)"
	if live {
		mode = SandboxHostStatusSourceLiveRefreshed
		summary = "live worker refresh (durable cache updated)"
	}

	return SandboxHostStatusResponse{
		ContractVersion: SandboxHostStatusContractVersion,
		Source: SandboxHostStatusSource{
			Mode:    mode,
			Summary: summary,
		},
		Refresh: SandboxHostStatusRefresh{
			RequestedLive: live,
			CacheUpdated:  live,
			RefreshedAt:   sandboxHostStatusRefreshedAt(host, live),
		},
		Host: newSandboxHostStatusHost(host),
	}
}

func newSandboxHostStatusHost(host *sandbox.SandboxHost) SandboxHostStatusHost {
	if host == nil {
		return SandboxHostStatusHost{
			Kind:              "unknown",
			Endpoint:          newSandboxHostListEndpoint(""),
			Health:            newSandboxHostListHealth(nil),
			SupportedRuntimes: []string{},
			Capacity:          newSandboxHostListCapacity(nil),
		}
	}
	return SandboxHostStatusHost{
		ID:                sandboxHostDisplayValue(host.ID, ""),
		Name:              sandboxHostDisplayValue(host.Name, host.ID),
		Kind:              sandboxHostDisplayValue(host.Kind, "unknown"),
		Endpoint:          newSandboxHostListEndpoint(host.Endpoint),
		Health:            newSandboxHostListHealth(host.Health),
		SupportedRuntimes: sandboxHostListStringSlice(host.SupportedRuntimes),
		Capacity:          newSandboxHostListCapacity(host.Capacity),
	}
}

func sandboxHostStatusRefreshedAt(host *sandbox.SandboxHost, live bool) *time.Time {
	if !live || host == nil || host.Health == nil || host.Health.CheckedAt.IsZero() {
		return nil
	}
	value := host.Health.CheckedAt
	return &value
}

func newSandboxHostListEntry(host *sandbox.SandboxHost) SandboxHostListEntry {
	return SandboxHostListEntry{
		ID:                sandboxHostDisplayValue(host.ID, ""),
		Name:              sandboxHostDisplayValue(host.Name, host.ID),
		Kind:              sandboxHostDisplayValue(host.Kind, "unknown"),
		Endpoint:          newSandboxHostListEndpoint(host.Endpoint),
		Health:            newSandboxHostListHealth(host.Health),
		SupportedRuntimes: sandboxHostListStringSlice(host.SupportedRuntimes),
		Capacity:          newSandboxHostListCapacity(host.Capacity),
	}
}

func newSandboxHostListEndpoint(endpoint string) SandboxHostListEndpoint {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return SandboxHostListEndpoint{
			Type:    "none",
			Summary: "none",
		}
	}

	lowerEndpoint := strings.ToLower(endpoint)
	if strings.HasPrefix(lowerEndpoint, "unix://") || strings.HasPrefix(lowerEndpoint, "unix:") {
		return SandboxHostListEndpoint{
			Type:    "unix_socket",
			Summary: "local Unix socket",
			Scheme:  "unix",
		}
	}

	if index := strings.Index(endpoint, ":"); index > 0 {
		scheme := strings.ToLower(strings.TrimSpace(endpoint[:index]))
		if scheme != "" {
			return SandboxHostListEndpoint{
				Type:    "endpoint",
				Summary: scheme + " endpoint",
				Scheme:  scheme,
			}
		}
	}

	return SandboxHostListEndpoint{
		Type:    "configured",
		Summary: "configured",
	}
}

func newSandboxHostListHealth(health *sandbox.HostHealth) SandboxHostListHealth {
	if health == nil {
		return SandboxHostListHealth{Status: sandboxworker.HealthStatusUnknown}
	}

	var checkedAt *time.Time
	if !health.CheckedAt.IsZero() {
		value := health.CheckedAt
		checkedAt = &value
	}

	return SandboxHostListHealth{
		Status:          sandboxHostHealthSummary(health),
		CheckedAt:       checkedAt,
		LastHeartbeatAt: health.LastHeartbeatAt,
		Message:         strings.TrimSpace(health.Message),
	}
}

func newSandboxHostListCapacity(capacity *sandbox.HostCapacity) SandboxHostListCapacity {
	if capacity == nil {
		return SandboxHostListCapacity{Summary: sandboxHostCapacitySummary(nil)}
	}
	return SandboxHostListCapacity{
		Summary:                sandboxHostCapacitySummary(capacity),
		CPUCores:               capacity.CPUCores,
		MemoryMB:               capacity.MemoryMB,
		DiskGB:                 capacity.DiskGB,
		MaxConcurrentSandboxes: capacity.MaxConcurrentSandboxes,
	}
}

func sandboxHostListStringSlice(values []string) []string {
	values = sortedUniqueStrings(values)
	if values == nil {
		return []string{}
	}
	return values
}
