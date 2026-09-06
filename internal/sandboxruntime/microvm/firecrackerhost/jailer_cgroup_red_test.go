package firecrackerhost

import (
	"context"
	"slices"
	"testing"
)

func TestJailerCgroupCoordinatorRejectsMissingResourceAuthority(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator := coordinatorForStateTest(&events, root, lifecycle)
	fixture := validStrictJailerCoordinatorRequest(t)
	// Explicit old fields intentionally omit the new resource authority.
	request := strictJailerCoordinatorRequest{runtimeID: fixture.runtimeID, inspection: fixture.inspection,
		jailPaths: fixture.jailPaths, kernel: fixture.kernel, rootfs: fixture.rootfs, config: fixture.config, support: fixture.support}
	_, err := coordinator.start(context.Background(), request)
	if err == nil || slices.Contains(events, "start") {
		t.Fatalf("missing cgroup allowed launch: error=%v events=%v", err, events)
	}
}
