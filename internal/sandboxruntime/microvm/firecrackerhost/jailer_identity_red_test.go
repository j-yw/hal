package firecrackerhost

import (
	"context"
	"testing"
)

// A numeric non-root identity is not an exclusive prepared-host reservation.
// Keep this dependency literal explicit: future fixture helpers must not
// silently inject the authority whose absence this regression exercises.
func TestJailerIdentityCoordinatorRejectsNumericIdentityWithoutReservation(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	fixture := coordinatorForStateTest(&events, root, lifecycle)
	request := validStrictJailerCoordinatorRequest(t)
	if err := validateStrictJailerCoordinatorConfig(request); err != nil {
		t.Fatalf("invalid unrelated config fixture: %v", err)
	}
	if request.inspection.runtimeUID == 0 || request.inspection.runtimeGID == 0 {
		t.Fatal("fixture must supply the currently accepted non-root numeric pair")
	}
	deps := strictJailerCoordinatorDependencies{
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
	_, err := coordinator.start(context.Background(), request)
	if err == nil || len(events) != 0 || coordinator.generation != nil {
		t.Fatalf("numeric pair authorized resource allocation without reservation: error=%v events=%v retainedGeneration=%t", err, events, coordinator.generation != nil)
	}
}
