package sandboxruntime

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Pure neutral-contract fixtures; arming here models the manager's durable
// callback and is not a filesystem, runtime, or credential acceptance claim.
func TestMinimalLaunchBindingRequiresFinalBarrier(t *testing.T) {
	for _, failure := range []string{"nil", "error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			binding, selection, reservation, provider := minimalLaunchAttemptFixture(t)
			var barrier func() error
			if failure == "error" {
				barrier = func() error { return errors.New("sensitive test-only barrier cause") }
			} else if failure == "panic" {
				barrier = func() error { panic("sensitive test-only barrier panic") }
			}
			owner, err := binding.Start(reservation, selection, barrier)
			if owner != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("final barrier %s result was not a sanitized rejection: %v", failure, err)
			}
			if provider.calls.Load() != 0 {
				t.Fatalf("provider entries with %s final barrier = %d, want 0", failure, provider.calls.Load())
			}
		})
	}
}

func TestMinimalLaunchBindingAttemptsProviderOnlyOnce(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "sequential"
		if concurrent {
			name = "concurrent"
		}
		t.Run(name, func(t *testing.T) {
			binding, selection, reservation, provider := minimalLaunchAttemptFixture(t)
			barrier := func() error { return nil }
			if !concurrent {
				_, _ = binding.Start(reservation, selection, barrier)
				_, _ = binding.Start(reservation, selection, barrier)
			} else {
				provider.entered, provider.release = make(chan struct{}, 2), make(chan struct{})
				done := make(chan struct{}, 2)
				go func() { _, _ = binding.Start(reservation, selection, barrier); done <- struct{}{} }()
				select {
				case <-provider.entered:
				case <-time.After(time.Second):
					t.Fatal("first provider did not enter")
				}
				go func() { _, _ = binding.Start(reservation, selection, barrier); done <- struct{}{} }()
				secondReturned := false
				select {
				case <-provider.entered:
				case <-done:
					secondReturned = true
				case <-time.After(time.Second):
					t.Error("second attempt neither rejected nor entered")
				}
				close(provider.release)
				remaining := 2
				if secondReturned {
					remaining = 1
				}
				for range remaining {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("attempt did not quiesce")
					}
				}
			}
			if provider.calls.Load() != 1 {
				t.Fatalf("provider attempts before ClaimLaunch = %d, want exactly 1", provider.calls.Load())
			}
			reservation.mu.Lock()
			claimed := reservation.claimed
			reservation.mu.Unlock()
			if claimed {
				t.Fatal("binding preclaimed the provider's launch contract")
			}
		})
	}
}

func TestMinimalLaunchBindingRechecksCancellationAfterUnlockedBarrier(t *testing.T) {
	binding, selection, reservation, provider := minimalLaunchAttemptFixture(t)
	barrier := func() error {
		if !reservation.mu.TryLock() {
			t.Fatal("barrier ran under reservation mutex")
		}
		reservation.mu.Unlock()
		if !selection.mu.TryLock() {
			t.Fatal("barrier ran under selection mutex")
		}
		selection.mu.Unlock()
		reservation.Revoke()
		return nil
	}
	owner, err := binding.Start(reservation, selection, barrier)
	if owner != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || provider.calls.Load() != 0 {
		t.Fatal("canceled final barrier entered provider")
	}
}

func TestMinimalLaunchAttemptExpiryDoesNotExpireConfiguredScope(t *testing.T) {
	_, selection, _, _ := minimalLaunchAttemptFixture(t)
	requestKey := "request-v2-" + strings.Repeat("b", 64)
	if expired, err := selection.Reserve(context.Background(), context.Background(), "expired-job", "expired-generation", requestKey, time.Now().Add(-time.Hour)); err == nil || expired != nil {
		t.Fatal("expired per-attempt reservation was issued")
	}
	fresh, err := selection.Reserve(context.Background(), context.Background(), "fresh-job", "fresh-generation", requestKey, time.Now().Add(time.Minute))
	if err != nil || fresh == nil {
		t.Fatal("attempt expiry expired reusable constructor scope")
	}
	t.Cleanup(fresh.Revoke)
	selection.authorizer.Close()
	if fresh.Context().Err() == nil {
		select {
		case <-fresh.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("scope revocation did not cancel live grant")
		}
	}
	if revoked, err := selection.Reserve(context.Background(), context.Background(), "revoked-job", "revoked-generation", requestKey, time.Now().Add(time.Minute)); err == nil || revoked != nil {
		t.Fatal("revoked service scope issued another grant")
	}
}

type minimalLaunchAttemptProvider struct {
	identity MinimalLaunchSelectionIdentity
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
}

func (p *minimalLaunchAttemptProvider) ResolveMinimalSelection(context.Context, MinimalLaunchSelectionHints) (MinimalLaunchSelection, error) {
	return p, nil
}
func (p *minimalLaunchAttemptProvider) Current(context.Context) (MinimalLaunchSelectionIdentity, error) {
	return p.identity, nil
}
func (*minimalLaunchAttemptProvider) Close() error { return nil }
func (p *minimalLaunchAttemptProvider) StartMinimalJob(context.Context, *MinimalLaunchReservation, MinimalLaunchSelection) (MinimalJobRuntimeOwner, error) {
	p.calls.Add(1)
	if p.entered != nil {
		p.entered <- struct{}{}
		<-p.release
	}
	return nil, ErrMinimalLaunchUnavailable // No claim and no owner: uncertainty, never reusable.
}
func (*minimalLaunchAttemptProvider) RecoverMinimalJob(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
	return nil, ErrMinimalLaunchUnavailable
}

func minimalLaunchAttemptFixture(t *testing.T) (*MinimalLaunchProviderBinding, *MinimalLaunchPreparedSelection, *MinimalLaunchReservation, *minimalLaunchAttemptProvider) {
	t.Helper()
	authority, err := NewAuthenticatedWorkerPrincipalAuthority("authority-minimal", "authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("principal-minimal", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	provider := &minimalLaunchAttemptProvider{identity: MinimalLaunchSelectionIdentity{WorkerID: "worker-minimal", HostID: "host-minimal", RuntimeID: "runtime-minimal", RuntimeGeneration: "runtime-generation", PlanID: "plan-minimal", TemplatePolicyID: "template-minimal", WorkspacePolicyID: "workspace-minimal", NetworkPolicyID: "network-minimal"}}
	binding, err := NewMinimalLaunchProviderBinding(provider)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewMinimalLaunchAuthorizer(authority, binding, []MinimalLaunchScope{{PolicyID: "launch-policy", Revision: 1, PrincipalID: "principal-minimal", WorkerID: "worker-minimal", HostID: "host-minimal", TemplatePolicyID: "template-minimal", WorkspacePolicyID: "workspace-minimal", NetworkPolicyID: "network-minimal"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Close)
	selection, err := authorizer.ResolveSelection(context.Background(), principal, "worker-minimal", MinimalLaunchSelectionHints{SandboxID: "sandbox-minimal", ExecutionID: "execution-minimal", SubmissionID: "submission-minimal", RuntimeID: "runtime-minimal", PlanID: "plan-minimal", TemplatePolicyID: "template-minimal", WorkspacePolicyID: "workspace-minimal"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selection.Close() })
	reservation, err := selection.Reserve(context.Background(), context.Background(), "job-minimal", "job-generation", "request-v2-"+strings.Repeat("a", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reservation.Revoke)
	if err := reservation.ArmDispatch(context.Background(), reservation.Identity()); err != nil {
		t.Fatal(err)
	}
	return binding, selection, reservation, provider
}
