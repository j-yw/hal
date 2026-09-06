package firecrackerhost

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestJailerIdentityCoordinatorCommitsBeforeAllocationAndReleasesLast(t *testing.T) {
	events := []string{}
	coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, &coordinatorFakeLifecycle{events: &events})
	authority, store := newFakeJailerIdentityAuthority()
	coordinator.deps.identity = authority
	request := validStrictJailerCoordinatorRequest(t)
	inspect := coordinator.deps.inspect
	coordinator.deps.inspect = func(r strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
		record, err := readJailerIdentityRecord(store.snapshot(), authority.slot)
		if err != nil || record.State != "busy" || record.RuntimeID != request.runtimeID || record.Config != request.config.SHA256 || record.UID != r.runtimeUID || record.GID != r.runtimeGID {
			t.Fatal("inspection reached before exact durable busy record")
		}
		events = append(events, "inspect")
		return inspect(r)
	}
	store.hook = func(op string) {
		if op == "sync" {
			record, err := readJailerIdentityRecord(store.snapshot(), authority.slot)
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, "sync-"+record.State)
		}
	}
	session, err := coordinator.start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.stop(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	busy, inspectIndex := slices.Index(events, "sync-busy"), slices.Index(events, "inspect")
	root, forget, idle := slices.Index(events, "release"), slices.Index(events, "forget"), slices.Index(events, "sync-idle")
	if busy < 0 || inspectIndex < busy || root < 0 || forget < root || idle < forget {
		t.Fatalf("unsafe identity ordering: %v", events)
	}
	if store.owner != nil || coordinator.generation != nil {
		t.Fatal("terminal generation retained identity")
	}
}

func TestJailerIdentityCoordinatorSharesAuthorityAndQuarantinesPartialCleanup(t *testing.T) {
	for _, failure := range []string{"root", "forget", "cgroup kill", "idle sync"} {
		t.Run(failure, func(t *testing.T) {
			authority, store := newFakeJailerIdentityAuthority()
			events, otherEvents := []string{}, []string{}
			root := &coordinatorFakeRoot{events: &events}
			life := &coordinatorFakeLifecycle{events: &events}
			first := coordinatorForStateTest(&events, root, life)
			other := coordinatorForStateTest(&otherEvents, &coordinatorFakeRoot{events: &otherEvents}, &coordinatorFakeLifecycle{events: &otherEvents})
			first.deps.identity, other.deps.identity = authority, authority
			fs := newFakeJailerCgroupFilesystem()
			first.deps.prepareCgroup = func(ctx context.Context, r strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
				return prepareFakeJailerCgroup(ctx, r, fs)
			}
			session, err := first.start(context.Background(), validStrictJailerCoordinatorRequest(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = first.generationIdentityForTest().close() })
			if _, err := other.start(context.Background(), validStrictJailerCoordinatorRequest(t)); err == nil || len(otherEvents) != 0 {
				t.Fatal("second coordinator reused active pair")
			}
			switch failure {
			case "root":
				root.removeErrors = []error{errors.New("fixture removal"), nil}
			case "forget":
				life.forgetErrors = []error{errors.New("fixture forget"), nil}
			case "cgroup kill":
				fs.fail = "write:cgroup.kill"
			case "idle sync":
				store.fail = "sync"
			}
			if err := first.stop(context.Background(), session); !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) || first.generation == nil {
				t.Fatal("partial cleanup lost identity quarantine")
			}
			if _, err := other.start(context.Background(), validStrictJailerCoordinatorRequest(t)); err == nil || len(otherEvents) != 0 {
				t.Fatal("partial cleanup released pair")
			}
			if failure == "idle sync" {
				store.fail = ""
				if first.retryCleanup(context.Background(), session) == nil {
					t.Fatal("uncertain idle write was repaired as proof")
				}
				return
			}
			fs.fail = ""
			if err := first.retryCleanup(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			next, err := other.start(context.Background(), validStrictJailerCoordinatorRequest(t))
			if err != nil {
				t.Fatal("clean pair was not reusable", err)
			}
			if first.retryCleanup(context.Background(), session) == nil {
				t.Fatal("stale session reached new generation")
			}
			if err := other.stop(context.Background(), next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func (coordinator *strictJailerCoordinator) generationIdentityForTest() *strictJailerIdentityLease {
	if coordinator.generation == nil {
		return nil
	}
	return coordinator.generation.identity
}

func TestJailerIdentityCoordinatorCancellationNeverAllocatesBeforeBusy(t *testing.T) {
	for _, phase := range []string{"before", "busy sync", "inspect", "plan"} {
		t.Run(phase, func(t *testing.T) {
			events := []string{}
			coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, &coordinatorFakeLifecycle{events: &events})
			authority, store := newFakeJailerIdentityAuthority()
			coordinator.deps.identity = authority
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inspect := coordinator.deps.inspect
			coordinator.deps.inspect = func(r strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
				events = append(events, "inspect")
				if phase == "inspect" {
					cancel()
				}
				return inspect(r)
			}
			plan := coordinator.deps.plan
			coordinator.deps.plan = func(r strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
				if phase == "plan" {
					cancel()
				}
				return plan(r)
			}
			if phase == "before" {
				cancel()
			}
			if phase == "busy sync" {
				store.hook = func(op string) {
					if op == "sync" {
						cancel()
					}
				}
			}
			_, err := coordinator.start(ctx, validStrictJailerCoordinatorRequest(t))
			if err == nil || slices.Contains(events, "start") {
				t.Fatal("canceled request started")
			}
			if (phase == "before" || phase == "busy sync") && len(events) != 0 {
				t.Fatal("cancellation before busy reached host allocation", events)
			}
			if store.owner != nil || coordinator.generation != nil {
				t.Fatal("known clean canceled generation leaked identity")
			}
			record, err := readJailerIdentityRecord(store.snapshot(), authority.slot)
			if err != nil || record.State != "idle" {
				t.Fatal("clean cancellation did not release exact lease")
			}
		})
	}
}

func TestJailerIdentityCoordinatorRevokedBeforeLaunchStaysQuarantined(t *testing.T) {
	events := []string{}
	coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, &coordinatorFakeLifecycle{events: &events})
	plan := coordinator.deps.plan
	coordinator.deps.plan = func(r strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
		if coordinator.generation.identity.close() != nil {
			t.Fatal("close")
		}
		return plan(r)
	}
	_, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err == nil || slices.Contains(events, "start") || coordinator.generation == nil {
		t.Fatal("closed reservation authorized launch or reuse")
	}
}

func TestJailerIdentityCoordinatorCloseRetryCannotForgetSuccessor(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	events, nextEvents := []string{}, []string{}
	first := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, &coordinatorFakeLifecycle{events: &events})
	next := coordinatorForStateTest(&nextEvents, &coordinatorFakeRoot{events: &nextEvents}, &coordinatorFakeLifecycle{events: &nextEvents})
	first.deps.identity, next.deps.identity = authority, authority
	session, err := first.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	old := first.generation.identity
	store.fail = "close"
	if first.stop(context.Background(), session) == nil || !old.idleCommitted || old.closeErr == nil {
		t.Fatal("terminal close failure lost")
	}
	store.fail = ""
	successor, err := next.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err != nil {
		t.Fatal("durably idle slot could not be reserved", err)
	}
	if err := first.retryCleanup(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if first.generation != nil || old.closeErr == nil || next.generation.identity.verify(context.Background()) != nil {
		t.Fatal("close retry changed later owner or erased failure")
	}
	forgets := 0
	for _, event := range events {
		if event == "forget" {
			forgets++
		}
	}
	if forgets != 1 || slices.Contains(nextEvents, "forget") {
		t.Fatal("old generation forgot successor")
	}
	if err := next.stop(context.Background(), successor); err != nil {
		t.Fatal(err)
	}
}
