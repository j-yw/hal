//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type minimalTemplateHandoffContextKey struct{}

type minimalTemplateHandoffFixture struct {
	inputs     *minimalTemplateFixture
	provider   *minimalLaunchProvider
	binding    *sandboxruntime.MinimalLaunchProviderBinding
	authorizer *sandboxruntime.MinimalLaunchAuthorizer
	principal  sandboxruntime.AuthenticatedWorkerPrincipal
	selected   *sandboxruntime.MinimalLaunchPreparedSelection
	ctx, owned context.Context
}

func newMinimalTemplateHandoffFixture(t *testing.T) *minimalTemplateHandoffFixture {
	t.Helper()
	f := &minimalTemplateHandoffFixture{inputs: newMinimalTemplateFixture(t)}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	f.owned, cancel = context.WithTimeout(context.WithValue(context.Background(), minimalTemplateHandoffContextKey{}, "original-owner"), 5*time.Second)
	t.Cleanup(cancel)
	var err error
	f.provider, err = newMinimalLaunchProvider(f.inputs.association, f.inputs.options)
	if err != nil {
		t.Fatal("real provider constructor", err)
	}
	f.binding, err = sandboxruntime.NewMinimalLaunchProviderBinding(f.provider)
	if err != nil {
		t.Fatal("actual provider binding", err)
	}
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("handoff-authority", "handoff-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	f.principal, err = authority.IssueAuthenticatedWorkerPrincipal(f.inputs.association.scope.PrincipalID, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(authority, f.binding, []sandboxruntime.MinimalLaunchScope{f.inputs.association.scope})
	if err != nil {
		t.Fatal("actual authorizer", err)
	}
	t.Cleanup(f.authorizer.Close)
	f.selected, err = f.authorizer.ResolveSelection(f.ctx, f.principal, f.inputs.association.scope.WorkerID, minimalTemplateHints(), f.inputs.association.template)
	if err != nil || f.selected == nil {
		t.Fatal("authenticated real provider selection", err)
	}
	t.Cleanup(func() {
		if err := f.selected.Close(); err != nil {
			t.Error("selected source cleanup", err)
		}
	})
	if f.inputs.requests.Load() != 2 || f.selected.Current(f.ctx) != nil {
		t.Fatal("actual measured acquisition/local currentness was not reached")
	}
	return f
}

func (f *minimalTemplateHandoffFixture) reserve(t *testing.T) *sandboxruntime.MinimalLaunchReservation {
	t.Helper()
	r, err := f.selected.Reserve(f.ctx, f.owned, "handoff-job", "handoff-job-generation", "request-v2-"+strings.Repeat("c", 64), time.Now().Add(2*time.Second),
		sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: "original-admission", AdmissionGrantRevision: 7})
	if err != nil || r == nil {
		t.Fatal("actual bounded reservation", err)
	}
	t.Cleanup(r.Revoke)
	return r
}

// This is an independent neutral Claim control, not evidence that production
// Start claims or transfers. The source remains genuinely current/untransferred.
func TestMinimalTemplateHandoffActualAcquisitionAndClaimControl(t *testing.T) {
	f := newMinimalTemplateHandoffFixture(t)
	r := f.reserve(t)
	if err := r.ArmDispatch(f.ctx, r.Identity()); err != nil {
		t.Fatal("actual arm", err)
	}
	claimed, err := r.ClaimLaunch(r.Context())
	if err != nil || claimed != r.Identity() {
		t.Fatal("actual neutral Claim", err)
	}
	scope, source, hints := f.inputs.association.scope, f.selected.Identity(), minimalTemplateHints()
	if claimed.PrincipalID != scope.PrincipalID || claimed.WorkerID != scope.WorkerID || claimed.HostID != scope.HostID ||
		claimed.LaunchPolicyID != scope.PolicyID || claimed.LaunchPolicyRevision != scope.Revision || claimed.RuntimeGeneration != source.RuntimeGeneration ||
		claimed.RuntimeID != hints.RuntimeID || claimed.PlanID != hints.PlanID || claimed.SandboxID != hints.SandboxID || claimed.ExecutionID != hints.ExecutionID || claimed.SubmissionID != hints.SubmissionID ||
		claimed.RequestKey != "request-v2-"+strings.Repeat("c", 64) || claimed.LaunchGrantID == "original-admission" {
		t.Fatal("actual claim lost original scope/source/request identity")
	}
	if original, err := r.TemplateIdentity(); err != nil || original != f.inputs.association.template {
		t.Fatal("original acquired template tuple unavailable", err)
	}
	if original, err := r.RequestCorrelation(); err != nil || original != (sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: "original-admission", AdmissionGrantRevision: 7}) {
		t.Fatal("original request correlation unavailable", err)
	}
	wantDeadline, _ := f.owned.Deadline()
	gotDeadline, ok := r.OwnedContext().Deadline()
	if !ok || !gotDeadline.Equal(wantDeadline) || r.OwnedContext().Value(minimalTemplateHandoffContextKey{}) != "original-owner" || r.Context().Err() != nil || r.OwnedContext().Err() != nil {
		t.Fatal("actual reservation lost original owner lifetime")
	}
	if _, err := r.ClaimLaunch(r.Context()); err == nil || f.selected.Current(f.ctx) != nil || f.inputs.requests.Load() != 2 {
		t.Fatal("claim replay succeeded or control transferred/reacquired files")
	}
}

func TestMinimalTemplateHandoffNeutralRejectionsAndRecoveryControl(t *testing.T) {
	f := newMinimalTemplateHandoffFixture(t)
	r := f.reserve(t)
	barriers := 0
	owner, err := f.binding.Start(r, f.selected, func() error { barriers++; return nil })
	if owner != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || barriers != 0 {
		t.Fatal("unarmed binding entered a provider or barrier")
	}
	if _, err := r.ClaimLaunch(r.Context()); err == nil || f.selected.Current(f.ctx) != nil {
		t.Fatal("unarmed reservation claimed or consumed original files")
	}
	foreign, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("foreign-authority", "foreign-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := foreign.IssueAuthenticatedWorkerPrincipal(f.inputs.association.scope.PrincipalID, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := f.authorizer.ResolveSelection(f.ctx, principal, f.inputs.association.scope.WorkerID, minimalTemplateHints(), f.inputs.association.template); selected != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || f.inputs.requests.Load() != 2 {
		t.Fatal("foreign same-label principal reached acquisition")
	}
	if recovered, err := f.provider.RecoverMinimalJob(f.ctx, r.Identity()); recovered != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
		t.Fatal("unavailable recovery invented an owner")
	}
}

func TestMinimalTemplateHandoffStartRetainsClaimedPartialOwner(t *testing.T) {
	f := newMinimalTemplateHandoffFixture(t)
	r := f.reserve(t)
	if err := r.ArmDispatch(f.ctx, r.Identity()); err != nil {
		t.Fatal(err)
	}
	barriers := 0
	owner, err := f.binding.Start(r, f.selected, func() error { barriers++; return nil })
	if owner != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = owner.Finalize(ctx)
		})
	}
	if barriers != 1 || r.Context().Err() != nil || f.inputs.requests.Load() != 2 {
		t.Fatal("fixture did not reach the bounded original Start boundary")
	}
	if owner == nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
		t.Fatal("actual provider Start has no retained claimed asset owner; runtime must remain unavailable", err)
	}
	// These assertions follow the missing-Start RED and are not reached evidence.
	if _, err := r.ClaimLaunch(r.Context()); err == nil || f.selected.Current(f.ctx) != nil {
		t.Fatal("Start failed to consume Claim or lost its transferred source currentness")
	}
	if again, err := f.binding.Start(r, f.selected, func() error { barriers++; return nil }); again != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) || barriers != 1 {
		t.Fatal("same reservation entered Start twice")
	}
	if original, err := r.TemplateIdentity(); err != nil || original != f.inputs.association.template {
		t.Fatal("handoff replaced original template intent", err)
	}
	for range 2 {
		if receipt, err := owner.Finalize(f.ctx); receipt != (sandboxruntime.MinimalLaunchCleanupReceipt{}) || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
			t.Fatal("asset-only partial owner fabricated runtime or terminal cleanup proof")
		}
	}
	if f.selected.Current(f.ctx) == nil {
		t.Fatal("finalized partial owner retained usable launch assets")
	}
}
