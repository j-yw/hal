package firecrackerhost

import (
	"context"
	"testing"
)

// The identity reservation survives as busy, but its journal cannot recover
// cgroup/root ownership. A strict launch also needs the existing runtime owner
// to retain those exact leases across daemon loss. Keep this literal explicit
// so future fixture defaults cannot supply the missing owner implicitly.
func TestJailerRecoveryCoordinatorRejectsLaunchWithoutSurvivingOwner(t *testing.T) {
	events := []string{}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	fixture := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, lifecycle)
	authority, identityStore := newFakeJailerIdentityAuthority()
	request := validStrictJailerCoordinatorRequest(t)
	if err := validateStrictJailerCoordinatorConfig(request); err != nil {
		t.Fatal("invalid unrelated config fixture", err)
	}
	deps := strictJailerCoordinatorDependencies{
		identity:      authority,
		prepareCgroup: fixture.deps.prepareCgroup,
		inspect:       fixture.deps.inspect,
		newFilesystem: fixture.deps.newFilesystem,
		stage:         fixture.deps.stage,
		plan:          fixture.deps.plan,
		lifecycle:     lifecycle,
	}
	prepareCgroup := deps.prepareCgroup
	deps.prepareCgroup = func(ctx context.Context, request strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
		events = append(events, "allocate-cgroup")
		return prepareCgroup(ctx, request)
	}
	coordinator := newStrictJailerCoordinatorWithDependencies(deps)
	defer func() { _ = coordinator.generationIdentityForTest().close() }()
	_, err := coordinator.start(context.Background(), request)
	record, recordErr := readJailerIdentityRecord(identityStore.snapshot(), authority.slot)
	if err == nil || len(events) != 0 || coordinator.generation != nil || recordErr != nil || record.State != "idle" {
		t.Fatalf("launch without surviving owner: error=%v events=%v retainedGeneration=%t identityState=%q recordError=%v", err, events, coordinator.generation != nil, record.State, recordErr)
	}
}
