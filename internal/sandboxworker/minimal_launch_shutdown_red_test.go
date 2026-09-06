package sandboxworker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchShutdownCancelsAndJoinsBlockedCurrent(t *testing.T) {
	for _, call := range []int32{1, 2} {
		name := "initial selection"
		if call == 2 {
			name = "pre-reservation currentness"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			provider := &minimalLaunchBlockedCurrentProvider{base: fixture.provider, blockCall: call, entered: make(chan context.Context, 1), release: make(chan struct{})}
			fixture.binding = minimalLaunchDispatchBinding(t, provider)
			var err error
			fixture.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(fixture.authority, fixture.binding, []sandboxruntime.MinimalLaunchScope{{
				PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker", WorkerID: "worker-l8-neutral", HostID: "host-minimal",
				NetworkPolicyID: "network-minimal", TemplatePolicyID: fixture.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: fixture.request.JobStartV2.WorkspacePolicyID,
			}})
			if err != nil {
				t.Fatal(err)
			}
			service := fixture.service(t)
			responseDone, closeDone := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(provider.release) }) }
			t.Cleanup(release)
			go func() {
				defer close(responseDone)
				service.HandleAuthenticatedRequest(context.Background(), fixture.principal, fixture.request)
			}()
			var current context.Context
			select {
			case current = <-provider.entered:
			case <-time.After(time.Second):
				release()
				t.Fatal("selected provider did not enter blocked Current")
			}
			// A provider may wait for cancellation, but it must never own the
			// bookkeeping mutex which shutdown needs to revoke reservations.
			if service.jobs.mu.TryLock() {
				service.jobs.mu.Unlock()
			} else {
				t.Error("provider Current executes under manager mutex")
			}
			go func() { service.Close(); close(closeDone) }()
			select {
			case <-current.Done():
			case <-time.After(250 * time.Millisecond):
				t.Error("shutdown did not cancel the active Current observation")
			}
			select {
			case <-closeDone:
				t.Error("shutdown released state ownership before Current returned")
			default:
			}
			release()
			for _, done := range []<-chan struct{}{responseDone, closeDone} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("blocked-current regression did not quiesce")
				}
			}
			if provider.starts.Load() != 0 || len(minimalLaunchRecordFiles(t, fixture.stateDir)) != 0 {
				t.Fatal("shutdown admitted work from unresolved currentness")
			}
		})
	}
}

type minimalLaunchBlockedCurrentProvider struct {
	base      *minimalLaunchDispatchProvider
	blockCall int32
	calls     atomic.Int32
	starts    atomic.Int32
	entered   chan context.Context
	release   chan struct{}
}

func (provider *minimalLaunchBlockedCurrentProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	source, err := provider.base.ResolveMinimalSelection(ctx, hints)
	if err != nil {
		return nil, err
	}
	return &minimalLaunchBlockedCurrentSelection{provider: provider, source: source}, nil
}

func (provider *minimalLaunchBlockedCurrentProvider) StartMinimalJob(context.Context, *sandboxruntime.MinimalLaunchReservation, sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	provider.starts.Add(1)
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

func (*minimalLaunchBlockedCurrentProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

type minimalLaunchBlockedCurrentSelection struct {
	provider *minimalLaunchBlockedCurrentProvider
	source   sandboxruntime.MinimalLaunchSelection
}

func (selection *minimalLaunchBlockedCurrentSelection) Current(ctx context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	if selection.provider.calls.Add(1) == selection.provider.blockCall {
		selection.provider.entered <- ctx
		<-selection.provider.release
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return selection.source.Current(ctx)
}

func (selection *minimalLaunchBlockedCurrentSelection) Close() error { return selection.source.Close() }
