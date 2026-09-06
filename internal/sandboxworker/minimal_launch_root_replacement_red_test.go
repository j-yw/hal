package sandboxworker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// This is an ordinary fixture-only ownership race, not a guest/VM observation.
func TestMinimalLaunchRejectsReplacedStoreRoot(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	p := &minimalLaunchRelocatingProvider{minimalLaunchDispatchProvider: f.provider, t: t}
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
	heldBefore, err := s.jobs.stateLock.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	heldAfter, err := s.jobs.stateLock.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	originalLock, err := os.Lstat(filepath.Join(f.stateDir+".original", jobStateLockFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(heldBefore, heldAfter) || !os.SameFile(heldBefore, originalLock) {
		t.Fatal("original held lock changed")
	}
	if _, err := os.Lstat(filepath.Join(f.stateDir, jobStateLockFileName)); !os.IsNotExist(err) {
		t.Fatalf("successor unexpectedly has manager lock: %v", err)
	}
	canary, err := os.ReadFile(filepath.Join(f.stateDir, "successor-canary"))
	if err != nil || string(canary) != "distinct successor bytes\n" {
		t.Fatalf("successor canary modified: %q, %v", canary, err)
	}
	oldRecords := minimalLaunchRecordFiles(t, f.stateDir+".original")
	newRecords := minimalLaunchRecordFiles(t, f.stateDir)
	t.Logf("held lock unchanged; successor has no lock; canary intact; old records=%d successor records=%d provider starts=%d responseOK=%t", len(oldRecords), len(newRecords), f.provider.startCalls, response.OK)
	if f.provider.startCalls != 0 || len(newRecords) != 0 || len(oldRecords) != 0 {
		t.Fatal("replaced store root accepted: provider entered after durable publication in unowned successor")
	}
}

type minimalLaunchRelocatingProvider struct {
	*minimalLaunchDispatchProvider
	t *testing.T
}

func (p *minimalLaunchRelocatingProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	selection, err := p.minimalLaunchDispatchProvider.ResolveMinimalSelection(ctx, hints)
	if err != nil {
		return nil, err
	}
	root := p.fixture.stateDir
	if err := os.Rename(root, root+".original"); err != nil {
		p.t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "successor-canary"), []byte("distinct successor bytes\n"), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return selection, nil
}
