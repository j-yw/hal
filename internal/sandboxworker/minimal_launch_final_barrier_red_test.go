package sandboxworker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// The final provider currentness callback replaces only an ordinary test
// directory, after both durable publications. No live runtime is involved.
func TestMinimalLaunchFinalCurrentCannotReplaceDispatchAuthority(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	p := &minimalLaunchFinalReplacingProvider{minimalLaunchDispatchProvider: f.provider}
	f.binding = minimalLaunchDispatchBinding(t, p)
	var err error
	f.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(f.authority, f.binding, []sandboxruntime.MinimalLaunchScope{{
		PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker",
		WorkerID: "worker-l8-neutral", HostID: "host-minimal", NetworkPolicyID: "network-minimal",
		TemplatePolicyID: f.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: f.request.JobStartV2.WorkspacePolicyID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := f.service(t)
	response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	if p.currentCalls != 3 || !p.replaced {
		t.Fatalf("final currentness boundary not reached: calls=%d replaced=%t", p.currentCalls, p.replaced)
	}
	if response.OK || p.startCalls != 0 {
		t.Errorf("provider entries after final Current replaced root = %d, want 0; responseOK=%t", p.startCalls, response.OK)
	}
	if len(minimalLaunchRecordFiles(t, f.stateDir+".original")) != 1 || len(minimalLaunchRecordFiles(t, f.stateDir)) != 0 {
		t.Fatal("original dispatched record not retained independently of empty successor")
	}
	data, err := os.ReadFile(filepath.Join(f.stateDir, "successor-canary"))
	if err != nil || string(data) != "final current successor\n" {
		t.Fatal("successor canary changed")
	}
	s.jobs.mu.Lock()
	poisoned, live := s.jobs.minimalPoisoned, len(s.jobs.minimalLive)
	s.jobs.mu.Unlock()
	if !poisoned || live != 1 {
		t.Fatal("failed final barrier released or forgot uncertain dispatch ownership")
	}
}

type minimalLaunchFinalReplacingProvider struct {
	*minimalLaunchDispatchProvider
	currentCalls int
	replaced     bool
}

func (p *minimalLaunchFinalReplacingProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	if _, err := p.minimalLaunchDispatchProvider.ResolveMinimalSelection(ctx, hints); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *minimalLaunchFinalReplacingProvider) Current(ctx context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	p.currentCalls++
	if p.currentCalls == 3 {
		root := p.fixture.stateDir
		if len(minimalLaunchRecordFiles(p.t, root)) != 1 {
			p.t.Fatal("final currentness did not follow durable dispatch")
		}
		if err := os.Rename(root, root+".original"); err != nil {
			p.t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			p.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "successor-canary"), []byte("final current successor\n"), 0o600); err != nil {
			p.t.Fatal(err)
		}
		p.replaced = true
	}
	return p.selection.Current(ctx)
}

func (p *minimalLaunchFinalReplacingProvider) Close() error { return p.selection.Close() }

func (p *minimalLaunchFinalReplacingProvider) StartMinimalJob(context.Context, *sandboxruntime.MinimalLaunchReservation, sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	p.startCalls++
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}
