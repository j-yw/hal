package sandboxworker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchServiceRequestCorrelationReachesClaim(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	f.request.JobStartV2.AdmissionGrantID = "original-credential-grant"
	f.request.JobStartV2.AdmissionGrantRevision = 73
	p := &minimalLaunchRequestObserver{minimalLaunchDispatchProvider: f.provider}
	s := minimalLaunchRequestService(t, f, p)
	response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	if response.OK || p.startCalls != 1 || !p.checkedDispatch || p.reservation == nil || p.resolveCalls != 1 || p.recoverCalls != 0 {
		t.Fatal("fixture did not reach actual durable dispatch and Claim exactly once")
	}
	want := sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: f.request.JobStartV2.AdmissionGrantID, AdmissionGrantRevision: f.request.JobStartV2.AdmissionGrantRevision}
	if p.observationErr != nil || p.observed != want {
		t.Fatalf("actual claimed provider lost original request pair: got=%+v err=%v", p.observed, p.observationErr)
	}
	// These post-failure assertions are reached only after the missing accessor is fixed.
	if p.reservation.Context().Err() == nil || p.reservation.OwnedContext().Err() == nil {
		t.Fatal("uncertain provider return did not revoke retained ownership")
	}
	if got, err := p.reservation.RequestCorrelation(); err != nil || got != want {
		t.Fatal("failed Start erased the original request correlation")
	}
	identity := p.reservation.Identity()
	if identity.LaunchGrantID == want.AdmissionGrantID || identity.LaunchPolicyRevision == want.AdmissionGrantRevision {
		t.Fatal("fixture did not distinguish original credential and allocated launch fields")
	}
}

func TestMinimalLaunchServiceRequestCorrelationFinalBarrier(t *testing.T) {
	for _, mode := range []string{"request key", "credential grant", "credential revision"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			p := &minimalLaunchRequestReplacement{minimalLaunchDispatchProvider: f.provider, mode: mode}
			s := minimalLaunchRequestService(t, f, p)
			p.service = s
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if p.currentCalls != 3 || len(p.replacement) == 0 {
				t.Fatal("fixture did not reach final Current after both actual publications")
			}
			if response.OK || p.startCalls != 0 {
				t.Errorf("coherent memory/disk %s substitution passed original reservation barrier: entries=%d", mode, p.startCalls)
			}
			got, err := os.ReadFile(p.path)
			if err != nil || !bytes.Equal(got, p.replacement) {
				t.Fatal("rejected or uncertain dispatch rewrote replacement fixture data")
			}
			s.jobs.mu.Lock()
			poisoned, retained := s.jobs.minimalPoisoned, len(s.jobs.minimalLive)
			s.jobs.mu.Unlock()
			if !poisoned || retained != 1 {
				t.Fatal("uncertain dispatch released original retained ownership")
			}
		})
	}
}

func TestMinimalLaunchServiceRequestCorrelationIndependentControls(t *testing.T) {
	for _, mode := range []string{"valid start", "foreign issuer", "foreign principal", "missing grant", "zero revision"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			t.Cleanup(f.authorizer.Close)
			s := f.service(t)
			principal := f.principal
			switch mode {
			case "foreign issuer":
				_, principal = l8D6WorkerPrincipal(t)
			case "foreign principal":
				var err error
				principal, err = f.authority.IssueAuthenticatedWorkerPrincipal("different-principal", 1000, 1000)
				if err != nil {
					t.Fatal(err)
				}
			case "missing grant":
				f.request.JobStartV2.AdmissionGrantID = ""
			case "zero revision":
				f.request.JobStartV2.AdmissionGrantRevision = 0
			}
			response := s.HandleAuthenticatedRequest(context.Background(), principal, f.request)
			if response.OK {
				t.Fatal("incomplete fixture manufactured selected success")
			}
			if mode == "valid start" {
				if f.provider.startCalls != 1 || !f.provider.checkedDispatch {
					t.Fatal("independent unchanged actual Start/Claim control was not reached")
				}
			} else {
				f.assertNoProviderOrRecord(t)
			}
		})
	}
}

type minimalLaunchRequestObserver struct {
	*minimalLaunchDispatchProvider
	reservation    *sandboxruntime.MinimalLaunchReservation
	observed       sandboxruntime.MinimalLaunchRequestCorrelation
	observationErr error
}

func (p *minimalLaunchRequestObserver) StartMinimalJob(ctx context.Context, r *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	owner, err := p.minimalLaunchDispatchProvider.StartMinimalJob(ctx, r, selected)
	p.reservation = r
	p.observed, p.observationErr = r.RequestCorrelation() // After the actual Claim, before callback return.
	return owner, err
}

type minimalLaunchRequestReplacement struct {
	*minimalLaunchDispatchProvider
	service      *L8Service
	mode, path   string
	currentCalls int
	replacement  []byte
}

func (p *minimalLaunchRequestReplacement) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	if _, err := p.minimalLaunchDispatchProvider.ResolveMinimalSelection(ctx, hints); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *minimalLaunchRequestReplacement) Current(ctx context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	p.currentCalls++
	if p.currentCalls == 3 {
		manager := p.service.jobs
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if len(manager.states) != 1 {
			p.t.Fatal("final Current has no unique existing record")
		}
		for id, original := range manager.states {
			state := cloneStoredJobStateV2(original)
			if state.MinimalLaunch == nil || state.MinimalLaunch.Phase != "dispatching" || state.MinimalLaunch.Revision != 2 {
				p.t.Fatal("replacement occurred before actual dispatch publication")
			}
			switch p.mode {
			case "request key":
				state.RequestKey = "request-v2-" + strings.Repeat("f", 64)
			case "credential grant":
				state.JobV2.CredentialIntent.AdmissionGrantID = "replacement-credential"
			case "credential revision":
				state.JobV2.CredentialIntent.AdmissionGrantRevision++
			}
			if state.Validate() != nil {
				p.t.Fatal("replacement fixture did not preserve valid record shape")
			}
			payload, err := encodeStoredJobStateV2(state)
			p.path = filepath.Join(p.fixture.stateDir, id+".json")
			if err != nil || os.WriteFile(p.path, payload, 0o600) != nil {
				p.t.Fatal("could not install task-private coherent replacement")
			}
			manager.states[id] = state
			p.replacement = payload
		}
	}
	return p.selection.Current(ctx)
}

func (p *minimalLaunchRequestReplacement) Close() error { return p.selection.Close() }
func (p *minimalLaunchRequestReplacement) StartMinimalJob(context.Context, *sandboxruntime.MinimalLaunchReservation, sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	p.startCalls++
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable // Observation only; no host allocation.
}

func minimalLaunchRequestService(t *testing.T, f *minimalLaunchDispatchFixture, provider sandboxruntime.MinimalJobRuntimeProvider) *L8Service {
	t.Helper()
	f.authorizer.Close()
	f.binding = minimalLaunchDispatchBinding(t, provider)
	var err error
	f.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(f.authority, f.binding, []sandboxruntime.MinimalLaunchScope{{
		PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker", WorkerID: "worker-l8-neutral", HostID: "host-minimal",
		NetworkPolicyID: "network-minimal", TemplatePolicyID: f.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: f.request.JobStartV2.WorkspacePolicyID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.authorizer.Close)
	return f.service(t)
}
