package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchSelectedOwnerResultsRemainConservative(t *testing.T) {
	for _, mode := range []string{"owner", "nil", "typed nil", "partial error", "wrong identity", "no claim", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f, s, p := minimalLaunchMatrixFixture(t)
			p.mode = mode
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if response.OK || p.starts != 1 || len(s.jobs.minimalLive) != 1 || len(minimalLaunchRecordFiles(t, f.stateDir)) != 1 {
				t.Fatal("owner result manufactured success or lost dispatch ownership")
			}
			for _, entry := range s.jobs.minimalLive {
				wantOwner := mode == "owner" || mode == "partial error" || mode == "wrong identity" || mode == "no claim"
				if (entry.owner != nil) != wantOwner {
					t.Fatal("partial owner was not retained before interpreting result")
				}
				if mode != "owner" && entry.reservation.Context().Err() == nil {
					t.Fatal("failed dispatch retained a live grant")
				}
			}
			if s.jobs.minimalPoisoned != (mode != "owner") {
				t.Fatal("unknown owner result was not quarantined")
			}
		})
	}
}

func TestMinimalLaunchSelectedDuplicateConflictAndRuntimeOccupancy(t *testing.T) {
	for _, mode := range []string{"duplicate", "conflict", "occupied runtime"} {
		t.Run(mode, func(t *testing.T) {
			f, s, p := minimalLaunchMatrixFixture(t)
			_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			request := f.request
			start := cloneJobStartRequestV2(*request.JobStartV2)
			request.JobStartV2 = &start
			if mode == "conflict" {
				start.PlanID = "different-plan"
			}
			if mode == "occupied runtime" {
				start.SubmissionID = "new-submission"
				start.Exec.OperationID = "new-execution"
				p.generation = "different-generation"
			}
			if err := request.Validate(); err != nil {
				t.Fatal(err)
			}
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, request)
			if response.OK != (mode == "duplicate") || p.starts != 1 || len(s.jobs.states) != 1 {
				t.Fatal("submission identity or occupied runtime permitted another attempt")
			}
			if mode != "occupied runtime" && p.resolves != 1 {
				t.Fatal("duplicate/conflict re-entered provider selection")
			}
		})
	}
}

func TestMinimalLaunchClientDisconnectDoesNotCancelDurableOwner(t *testing.T) {
	f, s, p := minimalLaunchMatrixFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sync, calls := s.jobs.store.minimalOps.sync, 0
	s.jobs.store.minimalOps.sync = func() error {
		calls++
		if calls == 2 {
			cancel()
		} // First reservation's independent readback completed.
		return sync()
	}
	_ = s.HandleAuthenticatedRequest(ctx, f.principal, f.request)
	if ctx.Err() == nil || p.starts != 1 || s.jobs.minimalPoisoned {
		t.Fatal("client disconnect revoked durably owned preparation")
	}
	for _, entry := range s.jobs.minimalLive {
		if entry.reservation.Context().Err() != nil {
			t.Fatal("accepted reservation inherited client cancellation")
		}
	}
}

func TestMinimalLaunchConfiguredScopeSupportsRepeatedJobs(t *testing.T) {
	f, s, p := minimalLaunchMatrixFixture(t)
	for index := range 24 {
		request := f.request
		start := cloneJobStartRequestV2(*request.JobStartV2)
		request.JobStartV2 = &start
		start.SubmissionID = fmt.Sprintf("submission-%d", index)
		start.Exec.OperationID = fmt.Sprintf("execution-%d", index)
		start.Exec.Target.Runtime.RuntimeID = fmt.Sprintf("runtime-%d", index)
		if err := request.Validate(); err != nil {
			t.Fatal(err)
		}
		_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, request)
	}
	if p.starts != 24 || p.resolves != 24 || len(s.jobs.states) != 24 || s.jobs.minimalPoisoned {
		t.Fatal("reusable configured scope imposed a fixed per-service job limit")
	}
	ids := make(map[string]bool)
	for _, state := range s.jobs.states {
		for _, id := range []string{state.JobV2.ID, state.MinimalLaunch.JobGeneration, state.MinimalLaunch.LaunchGrantID} {
			if id == "" || ids[id] {
				t.Fatal("separate allocated identities were reused")
			}
			ids[id] = true
		}
	}
}

type minimalLaunchMatrixProvider struct {
	fixture          *minimalLaunchDispatchFixture
	service          *L8Service
	t                *testing.T
	mode, generation string
	starts, resolves int
}

func (p *minimalLaunchMatrixProvider) ResolveMinimalSelection(_ context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	p.resolves++
	return &minimalLaunchDispatchSelection{identity: sandboxruntime.MinimalLaunchSelectionIdentity{WorkerID: "worker-l8-neutral", HostID: "host-minimal", RuntimeID: hints.RuntimeID, RuntimeGeneration: p.generation,
		PlanID: hints.PlanID, TemplatePolicyID: hints.TemplatePolicyID, WorkspacePolicyID: hints.WorkspacePolicyID, NetworkPolicyID: "network-minimal"}}, nil
}

func (p *minimalLaunchMatrixProvider) StartMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, _ sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	p.starts++
	if !p.service.jobs.mu.TryLock() {
		p.t.Fatal("provider entry ran under manager lock")
	}
	p.service.jobs.mu.Unlock()
	if ctx.Err() != nil {
		p.t.Fatal("provider received canceled launch context")
	}
	identity := reservation.Identity()
	if p.mode != "no claim" {
		var err error
		identity, err = reservation.ClaimLaunch(ctx)
		if err != nil {
			p.t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(p.fixture.stateDir, identity.WorkerJobID+".json"))
	if err != nil {
		p.t.Fatal(err)
	}
	var state storedJobStateV2
	if json.Unmarshal(data, &state) != nil || state.Validate() != nil || state.MinimalLaunch.Phase != "dispatching" || state.MinimalLaunch.Revision != 2 || state.MinimalLaunch.JobGeneration != identity.JobGeneration || state.MinimalLaunch.LaunchGrantID != identity.LaunchGrantID {
		p.t.Fatal("provider did not independently observe its exact dispatch record")
	}
	owner := &minimalLaunchMatrixOwner{identity: identity}
	switch p.mode {
	case "nil":
		return nil, nil
	case "typed nil":
		return (*minimalLaunchMatrixOwner)(nil), nil
	case "partial error":
		return owner, errors.New("test-only partial owner failure")
	case "wrong identity":
		owner.identity.JobGeneration = "foreign-generation"
	case "panic":
		panic("test-only start panic")
	}
	return owner, nil
}

func (*minimalLaunchMatrixProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

type minimalLaunchMatrixOwner struct {
	identity sandboxruntime.MinimalLaunchIdentity
}

func (owner *minimalLaunchMatrixOwner) Identity() sandboxruntime.MinimalLaunchIdentity {
	return owner.identity
}
func (*minimalLaunchMatrixOwner) Finalize(context.Context) (sandboxruntime.MinimalLaunchCleanupReceipt, error) {
	return sandboxruntime.MinimalLaunchCleanupReceipt{}, sandboxruntime.ErrMinimalLaunchUnavailable
}

func minimalLaunchMatrixFixture(t *testing.T) (*minimalLaunchDispatchFixture, *L8Service, *minimalLaunchMatrixProvider) {
	t.Helper()
	f := newMinimalLaunchDispatchFixture(t)
	p := &minimalLaunchMatrixProvider{fixture: f, t: t, mode: "owner", generation: "runtime-generation-minimal"}
	f.binding = minimalLaunchDispatchBinding(t, p)
	var err error
	f.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(f.authority, f.binding, []sandboxruntime.MinimalLaunchScope{{PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker", WorkerID: "worker-l8-neutral", HostID: "host-minimal", NetworkPolicyID: "network-minimal",
		TemplatePolicyID: f.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: f.request.JobStartV2.WorkspacePolicyID}})
	if err != nil {
		t.Fatal(err)
	}
	p.service = f.service(t)
	return f, p.service, p
}
