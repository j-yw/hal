//go:build linux

package cmd

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestL11ResourceCensusPreparedLinux(t *testing.T) {
	t.Run("zero_resource_leaks", l11RunZeroResourceLeaks)
}

func l11RunZeroResourceLeaks(t *testing.T) {
	owner := l11ResourceOwner{Scope: "rootless-harness", Generation: 2}
	historical := l11ResourceOwner{Scope: owner.Scope, Generation: 1}
	inventory := newL11ResourceInventory()
	for _, kind := range l11ExactOwnedResourceKinds() {
		inventory.Add(historical, kind)
	}
	baseline, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture owned-resource baseline: %v", err)
	}
	if baseline.OwnedTotal() != 0 || baseline.Total() != len(l11ExactOwnedResourceKinds()) {
		t.Fatalf("baseline owned/all totals = %d/%d", baseline.OwnedTotal(), baseline.Total())
	}
	for _, kind := range l11ExactOwnedResourceKinds() {
		inventory.Add(owner, kind)
	}
	active, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture active census: %v", err)
	}
	if active.OwnedTotal() != len(l11ExactOwnedResourceKinds()) {
		t.Fatalf("active owned total = %d, want %d", active.OwnedTotal(), len(l11ExactOwnedResourceKinds()))
	}

	inventory.Cleanup(owner)
	inventory.Cleanup(owner)
	final, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture final census: %v", err)
	}
	if err := l11RequireExactResourceZero(baseline, final); err != nil {
		t.Fatalf("exact zero census: %v", err)
	}
	if final.Total() != baseline.Total() {
		t.Fatalf("unrelated resource total changed = %d, want %d", final.Total(), baseline.Total())
	}
}

func TestL11ResourceCensusRejectsLeaksAndInventoryDrift(t *testing.T) {
	owner := l11ResourceOwner{Scope: "rootless-harness", Generation: 7}
	inventory := newL11ResourceInventory()
	baseline, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	inventory.Add(owner, l11ResourceContainer)
	leaked, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture leaked census: %v", err)
	}
	if err := l11RequireExactResourceZero(baseline, leaked); !errors.Is(err, errL11ResourceLeak) {
		t.Fatalf("leak error = %v, want resource_leak", err)
	}

	inventory.Cleanup(owner)
	inventory.Add(l11ResourceOwner{Scope: "unrelated", Generation: 1}, l11ResourceSocket)
	drifted, err := inventory.Capture(owner)
	if err != nil {
		t.Fatalf("capture drifted census: %v", err)
	}
	if err := l11RequireExactResourceZero(baseline, drifted); !errors.Is(err, errL11ResourceCensusDrift) {
		t.Fatalf("drift error = %v, want evidence_mismatch", err)
	}

	malformed := baseline
	malformed.owned = l11ZeroResourceCounts()
	delete(malformed.owned, l11ResourceContainer)
	if err := l11RequireExactResourceZero(baseline, malformed); !errors.Is(err, errL11ResourceCensusDrift) {
		t.Fatalf("catalog-shape error = %v, want evidence_mismatch", err)
	}
}

type l11ResourceKind string

const (
	l11ResourceContainer                l11ResourceKind = "containers"
	l11ResourceFirecrackerProcess       l11ResourceKind = "firecracker_processes"
	l11ResourceCredentialHelper         l11ResourceKind = "credential_helpers"
	l11ResourceListenerConnection       l11ResourceKind = "listeners_connections"
	l11ResourceNamespace                l11ResourceKind = "namespaces"
	l11ResourceMount                    l11ResourceKind = "mounts"
	l11ResourceMonitor                  l11ResourceKind = "monitors"
	l11ResourceCgroup                   l11ResourceKind = "cgroups"
	l11ResourceSocket                   l11ResourceKind = "sockets"
	l11ResourceNetworkRuleRoute         l11ResourceKind = "network_rules_routes"
	l11ResourceLock                     l11ResourceKind = "locks"
	l11ResourceLease                    l11ResourceKind = "leases"
	l11ResourceCredentialTicketBuffer   l11ResourceKind = "credential_tickets_buffers_sessions"
	l11ResourceTemporaryArtifactStaging l11ResourceKind = "temporary_cache_artifact_staging"
)

var (
	errL11ResourceLeak        = errors.New("resource_leak")
	errL11ResourceCensusDrift = errors.New("evidence_mismatch")
)

type l11ResourceOwner struct {
	Scope      string
	Generation uint64
}

type l11ResourceInventory struct {
	mu        sync.Mutex
	resources map[l11ResourceOwner]map[l11ResourceKind]int
}

type l11ResourceCensus struct {
	owner  l11ResourceOwner
	owned  map[l11ResourceKind]int
	totals map[l11ResourceKind]int
}

func l11ExactOwnedResourceKinds() []l11ResourceKind {
	return []l11ResourceKind{
		l11ResourceContainer,
		l11ResourceFirecrackerProcess,
		l11ResourceCredentialHelper,
		l11ResourceListenerConnection,
		l11ResourceNamespace,
		l11ResourceMount,
		l11ResourceMonitor,
		l11ResourceCgroup,
		l11ResourceSocket,
		l11ResourceNetworkRuleRoute,
		l11ResourceLock,
		l11ResourceLease,
		l11ResourceCredentialTicketBuffer,
		l11ResourceTemporaryArtifactStaging,
	}
}

func newL11ResourceInventory() *l11ResourceInventory {
	return &l11ResourceInventory{resources: make(map[l11ResourceOwner]map[l11ResourceKind]int)}
}

func (inventory *l11ResourceInventory) Add(owner l11ResourceOwner, kind l11ResourceKind) {
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	if !l11ValidResourceOwner(owner) || !l11KnownResourceKind(kind) {
		panic("invalid L11 test resource identity")
	}
	if inventory.resources[owner] == nil {
		inventory.resources[owner] = make(map[l11ResourceKind]int)
	}
	inventory.resources[owner][kind]++
}

func (inventory *l11ResourceInventory) Release(owner l11ResourceOwner, kind l11ResourceKind) {
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	resources := inventory.resources[owner]
	if resources == nil || resources[kind] == 0 {
		return
	}
	resources[kind]--
	if resources[kind] == 0 {
		delete(resources, kind)
	}
	if len(resources) == 0 {
		delete(inventory.resources, owner)
	}
}

func (inventory *l11ResourceInventory) Cleanup(owner l11ResourceOwner) {
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	delete(inventory.resources, owner)
}

func (inventory *l11ResourceInventory) Capture(owner l11ResourceOwner) (l11ResourceCensus, error) {
	inventory.mu.Lock()
	defer inventory.mu.Unlock()
	if !l11ValidResourceOwner(owner) {
		return l11ResourceCensus{}, fmt.Errorf("capture L11 resource census: %w", errL11ResourceCensusDrift)
	}
	census := l11ResourceCensus{
		owner:  owner,
		owned:  l11ZeroResourceCounts(),
		totals: l11ZeroResourceCounts(),
	}
	for candidate, resources := range inventory.resources {
		if !l11ValidResourceOwner(candidate) {
			return l11ResourceCensus{}, fmt.Errorf("capture L11 resource census: %w", errL11ResourceCensusDrift)
		}
		for kind, count := range resources {
			if !l11KnownResourceKind(kind) || count < 0 {
				return l11ResourceCensus{}, fmt.Errorf("capture L11 resource census: %w", errL11ResourceCensusDrift)
			}
			census.totals[kind] += count
			if candidate == owner {
				census.owned[kind] += count
			}
		}
	}
	return census, nil
}

func (census l11ResourceCensus) OwnedTotal() int { return l11ResourceCountTotal(census.owned) }

func (census l11ResourceCensus) Total() int { return l11ResourceCountTotal(census.totals) }

func l11RequireExactResourceZero(baseline, final l11ResourceCensus) error {
	if baseline.owner != final.owner || !l11ExactResourceCatalog(baseline.owned) ||
		!l11ExactResourceCatalog(baseline.totals) || !l11ExactResourceCatalog(final.owned) ||
		!l11ExactResourceCatalog(final.totals) {
		return fmt.Errorf("L11 resource census changed shape: %w", errL11ResourceCensusDrift)
	}
	if final.OwnedTotal() != 0 {
		return fmt.Errorf("L11 owned-resource census is nonzero: %w", errL11ResourceLeak)
	}
	for _, kind := range l11ExactOwnedResourceKinds() {
		if baseline.totals[kind] != final.totals[kind] {
			return fmt.Errorf("L11 unrelated-resource census changed: %w", errL11ResourceCensusDrift)
		}
	}
	return nil
}

func l11ZeroResourceCounts() map[l11ResourceKind]int {
	counts := make(map[l11ResourceKind]int, len(l11ExactOwnedResourceKinds()))
	for _, kind := range l11ExactOwnedResourceKinds() {
		counts[kind] = 0
	}
	return counts
}

func l11ResourceCountTotal(counts map[l11ResourceKind]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func l11ExactResourceCatalog(counts map[l11ResourceKind]int) bool {
	if len(counts) != len(l11ExactOwnedResourceKinds()) {
		return false
	}
	for _, kind := range l11ExactOwnedResourceKinds() {
		if _, ok := counts[kind]; !ok {
			return false
		}
	}
	return true
}

func l11KnownResourceKind(candidate l11ResourceKind) bool {
	switch candidate {
	case l11ResourceContainer,
		l11ResourceFirecrackerProcess,
		l11ResourceCredentialHelper,
		l11ResourceListenerConnection,
		l11ResourceNamespace,
		l11ResourceMount,
		l11ResourceMonitor,
		l11ResourceCgroup,
		l11ResourceSocket,
		l11ResourceNetworkRuleRoute,
		l11ResourceLock,
		l11ResourceLease,
		l11ResourceCredentialTicketBuffer,
		l11ResourceTemporaryArtifactStaging:
		return true
	default:
		return false
	}
}

func l11ValidResourceOwner(owner l11ResourceOwner) bool {
	if owner.Generation == 0 || owner.Scope == "" || owner.Scope != strings.TrimSpace(owner.Scope) {
		return false
	}
	for _, character := range owner.Scope {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}
