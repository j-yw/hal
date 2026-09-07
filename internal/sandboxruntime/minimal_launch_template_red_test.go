package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMinimalReservationTemplateIdentityReachesOriginalClaim(t *testing.T) {
	f := newMinimalTemplateIdentityFixture(t)
	want := minimalTemplateIdentityValue()
	args := []MinimalLaunchTemplateIdentity{want}
	f.provider.onResolve = func() { args[0].TemplateManifestSHA256 = strings.Repeat("d", 64) }
	s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, args...)
	if err != nil || s == nil || f.provider.resolves != 1 {
		t.Fatalf("actual valid selection did not reach resolver: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	args[0] = MinimalLaunchTemplateIdentity{} // Neither mutation may replace the entry copy.
	r := f.start(t, s)
	if got, err := r.TemplateIdentity(); err != nil || got != want {
		t.Fatalf("actual claimed reservation lost original template tuple: got=%+v err=%v", got, err)
	}
	// These assertions follow the missing-accessor RED, not independent RED evidence.
	copyValue, _ := r.TemplateIdentity()
	copyValue.RuntimeImage, copyValue.TemplateDocumentSHA256 = "copy", "copy"
	r.Revoke()
	f.authorizer.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := r.TemplateIdentity(); err != nil || got != want {
		t.Fatal("loss or returned-copy mutation erased original template intent")
	}
	if _, err := r.ClaimLaunch(context.Background()); err == nil || f.provider.starts != 1 {
		t.Fatal("template observation revived a consumed claim")
	}
}

func TestMinimalReservationTemplateIdentityRejectsExplicitInvalid(t *testing.T) {
	want := minimalTemplateIdentityValue()
	for _, fixture := range []struct {
		name   string
		mutate func(*MinimalLaunchTemplateIdentity)
		many   bool
	}{
		{"explicit zero", func(v *MinimalLaunchTemplateIdentity) { *v = MinimalLaunchTemplateIdentity{} }, false},
		{"missing image", func(v *MinimalLaunchTemplateIdentity) { v.RuntimeImage = "" }, false},
		{"missing document", func(v *MinimalLaunchTemplateIdentity) { v.TemplateDocumentSHA256 = "" }, false},
		{"missing manifest", func(v *MinimalLaunchTemplateIdentity) { v.TemplateManifestSHA256 = "" }, false},
		{"missing runtime digest", func(v *MinimalLaunchTemplateIdentity) { v.RuntimeImageSHA256 = "" }, false},
		{"uppercase digest", func(v *MinimalLaunchTemplateIdentity) { v.TemplateManifestSHA256 = strings.Repeat("A", 64) }, false},
		{"short digest", func(v *MinimalLaunchTemplateIdentity) { v.TemplateDocumentSHA256 = strings.Repeat("a", 63) }, false},
		{"wrong suffix", func(v *MinimalLaunchTemplateIdentity) { v.RuntimeImageSHA256 = strings.Repeat("e", 64) }, false},
		{"mutable image", func(v *MinimalLaunchTemplateIdentity) { v.RuntimeImage = "registry.test/hal/minimal:stable" }, false},
		{"multiple values", func(*MinimalLaunchTemplateIdentity) {}, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			f := newMinimalTemplateIdentityFixture(t)
			value := want
			fixture.mutate(&value)
			args := []MinimalLaunchTemplateIdentity{value}
			if fixture.many {
				args = append(args, want)
			}
			s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints, args...)
			if s != nil {
				t.Cleanup(func() { _ = s.Close() })
			}
			if !errors.Is(err, ErrMinimalLaunchUnavailable) || s != nil || f.provider.resolves != 0 {
				t.Fatal("invalid explicit template intent entered resolver or issued selection")
			}
		})
	}
}

func TestMinimalReservationTemplateIdentityIndependentControls(t *testing.T) {
	t.Run("omitted actual Start and unissued observation", func(t *testing.T) {
		f := newMinimalTemplateIdentityFixture(t)
		s, err := f.authorizer.ResolveSelection(context.Background(), f.principal, "template-worker", f.hints)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		r := f.start(t, s)
		copied := new(MinimalLaunchReservation)
		reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(r).Elem())
		for _, handle := range []*MinimalLaunchReservation{nil, new(MinimalLaunchReservation), copied, r} {
			if got, err := handle.TemplateIdentity(); got != (MinimalLaunchTemplateIdentity{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) {
				t.Fatal("unissued or omitted template became consumable")
			}
		}
		if r.Context().Err() != nil || r.OwnedContext().Err() != nil || f.provider.starts != 1 {
			t.Fatal("unavailable observation changed original launch ownership")
		}
	})
	for _, name := range []string{"foreign issuer", "wrong scope"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalTemplateIdentityFixture(t)
			principal, hints := f.principal, f.hints
			if name == "foreign issuer" {
				principal = newMinimalTemplateIdentityFixture(t).principal
			} else {
				hints.TemplatePolicyID = "foreign-template-policy"
			}
			s, err := f.authorizer.ResolveSelection(context.Background(), principal, "template-worker", hints, minimalTemplateIdentityValue())
			if s != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.resolves != 0 {
				t.Fatal("template argument bypassed original principal/scope admission")
			}
		})
	}
}

type minimalTemplateIdentityFixture struct {
	authorizer *MinimalLaunchAuthorizer
	binding    *MinimalLaunchProviderBinding
	principal  AuthenticatedWorkerPrincipal
	hints      MinimalLaunchSelectionHints
	provider   *minimalTemplateIdentityProvider
}

type minimalTemplateIdentityProvider struct {
	minimalLaunchAttemptProvider
	resolves, starts int
	onResolve        func()
}

func (p *minimalTemplateIdentityProvider) ResolveMinimalSelection(context.Context, MinimalLaunchSelectionHints) (MinimalLaunchSelection, error) {
	p.resolves++
	if p.onResolve != nil {
		p.onResolve()
	}
	return p, nil
}

func (p *minimalTemplateIdentityProvider) StartMinimalJob(ctx context.Context, r *MinimalLaunchReservation, selected MinimalLaunchSelection) (MinimalJobRuntimeOwner, error) {
	p.starts++
	if selected != p || ctx != r.Context() {
		return nil, ErrMinimalLaunchUnavailable
	}
	identity, err := r.ClaimLaunch(ctx)
	if err != nil {
		return nil, err
	}
	return &minimalLaunchOwnerRuntime{identity: identity}, nil
}

func newMinimalTemplateIdentityFixture(t *testing.T) *minimalTemplateIdentityFixture {
	t.Helper()
	authority, err := NewAuthenticatedWorkerPrincipalAuthority("template-authority", "template-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("template-principal", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f := &minimalTemplateIdentityFixture{principal: principal, provider: &minimalTemplateIdentityProvider{}, hints: MinimalLaunchSelectionHints{
		SandboxID: "template-sandbox", ExecutionID: "template-execution", SubmissionID: "template-submission", RuntimeID: "template-runtime", PlanID: "template-plan", TemplatePolicyID: "template-policy", WorkspacePolicyID: "template-workspace",
	}}
	f.provider.identity = MinimalLaunchSelectionIdentity{WorkerID: "template-worker", HostID: "template-host", RuntimeID: f.hints.RuntimeID, RuntimeGeneration: "template-runtime-generation", PlanID: f.hints.PlanID, TemplatePolicyID: f.hints.TemplatePolicyID, WorkspacePolicyID: f.hints.WorkspacePolicyID, NetworkPolicyID: "template-network"}
	f.binding, err = NewMinimalLaunchProviderBinding(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	f.authorizer, err = NewMinimalLaunchAuthorizer(authority, f.binding, []MinimalLaunchScope{{PolicyID: "template-launch-policy", Revision: 1, PrincipalID: "template-principal", WorkerID: "template-worker", HostID: "template-host", TemplatePolicyID: f.hints.TemplatePolicyID, WorkspacePolicyID: f.hints.WorkspacePolicyID, NetworkPolicyID: "template-network"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.authorizer.Close)
	return f
}

func (f *minimalTemplateIdentityFixture) start(t *testing.T, s *MinimalLaunchPreparedSelection) *MinimalLaunchReservation {
	t.Helper()
	r, err := s.Reserve(context.Background(), context.Background(), "template-job", "template-job-generation", "request-v2-"+strings.Repeat("a", 64), time.Now().Add(time.Minute), MinimalLaunchRequestCorrelation{"template-credential-grant", 7})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Revoke)
	if err := r.ArmDispatch(context.Background(), r.Identity()); err != nil {
		t.Fatal(err)
	}
	owner, err := f.binding.Start(r, s, func() error { return nil })
	if err != nil || owner == nil || f.provider.starts != 1 {
		t.Fatalf("actual armed provider Claim did not complete: %v", err)
	}
	if got, err := r.RequestCorrelation(); err != nil || got != (MinimalLaunchRequestCorrelation{"template-credential-grant", 7}) {
		t.Fatal("template fixture changed original credential intent")
	}
	return r
}

func minimalTemplateIdentityValue() MinimalLaunchTemplateIdentity {
	return MinimalLaunchTemplateIdentity{RuntimeImage: "registry.test/hal/minimal:locked@sha256:" + strings.Repeat("c", 64), TemplateDocumentSHA256: strings.Repeat("a", 64), TemplateManifestSHA256: strings.Repeat("b", 64), RuntimeImageSHA256: strings.Repeat("c", 64)}
}
