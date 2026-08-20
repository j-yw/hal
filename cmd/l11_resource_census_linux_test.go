//go:build linux

package cmd

import (
	"errors"
	"testing"
)

func TestL11ResourceCensusPreparedLinux(t *testing.T) {
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

	t.Run("zero_resource_leaks", func(t *testing.T) {
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
	})
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
}
