package sandboxruntime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Method assertions let this RED compile against the real declared contract.
// They do not install substitutes or manufacture binding authority.
type minimalWorkerBindingAPI interface {
	BindWorker(MinimalLaunchWorkerInput, MinimalLaunchJournal) error
	RegisterWorkerOwner(context.Context, MinimalJobRuntimeOwner) (MinimalLaunchWorkerInput, error)
	RetainedWorkerOwner() *MinimalLaunchOwnerBinding
}

var errMinimalWorkerBindingMissing = errors.New("selected worker binding methods missing")

func minimalWorkerAPI(r *MinimalLaunchReservation) (minimalWorkerBindingAPI, bool) {
	var original interface{ Identity() MinimalLaunchIdentity } = r
	api, ok := original.(minimalWorkerBindingAPI)
	return api, ok
}

func requireMinimalWorkerAPI(t *testing.T, r *MinimalLaunchReservation) minimalWorkerBindingAPI {
	t.Helper()
	api, ok := minimalWorkerAPI(r)
	if !ok {
		t.Fatal("missing BindWorker/early owner registration on actual reservation")
	}
	return api
}

type minimalWorkerBindingFixture struct {
	authority *AuthenticatedWorkerPrincipalAuthority
	principal AuthenticatedWorkerPrincipal
	binding   *MinimalLaunchProviderBinding
	selection *MinimalLaunchPreparedSelection
	r         *MinimalLaunchReservation
	p         *minimalWorkerBindingProvider
	journal   *minimalWorkerAdmissionJournal
	input     MinimalLaunchWorkerInput
}

type minimalWorkerAdmissionJournal struct {
	self  *minimalWorkerAdmissionJournal
	r     *MinimalLaunchReservation
	calls atomic.Int32
	check func(*MinimalLaunchReservation) error
}

func (j *minimalWorkerAdmissionJournal) CheckMinimalLaunchReservation(ctx context.Context, r *MinimalLaunchReservation) error {
	if j == nil {
		return ErrMinimalLaunchUnavailable
	}
	j.calls.Add(1)
	if j.self != j || r != j.r || ctx != r.Context() || ctx.Err() != nil {
		return ErrMinimalLaunchUnavailable
	}
	if j.check != nil {
		return j.check(r)
	}
	return nil // Neutral observation only; the worker tests exercise real disk/lock.
}

type minimalWorkerBindingProvider struct {
	selection MinimalLaunchSelectionIdentity
	starts    atomic.Int32
	claims    atomic.Int32
	register  bool
	owner     *minimalWorkerBindingOwner
	received  MinimalLaunchWorkerInput
	before    func(*minimalWorkerBindingOwner)
	after     func() error
}

func (p *minimalWorkerBindingProvider) ResolveMinimalSelection(context.Context, MinimalLaunchSelectionHints) (MinimalLaunchSelection, error) {
	return p, nil
}
func (p *minimalWorkerBindingProvider) Current(context.Context) (MinimalLaunchSelectionIdentity, error) {
	return p.selection, nil
}
func (*minimalWorkerBindingProvider) Close() error { return nil }
func (p *minimalWorkerBindingProvider) StartMinimalJob(ctx context.Context, r *MinimalLaunchReservation, source MinimalLaunchSelection) (MinimalJobRuntimeOwner, error) {
	p.starts.Add(1)
	if source != p || ctx != r.Context() {
		return nil, ErrMinimalLaunchUnavailable
	}
	id, err := r.ClaimLaunch(ctx)
	if err != nil {
		return nil, err
	}
	p.claims.Add(1)
	p.owner = &minimalWorkerBindingOwner{identity: id}
	if p.before != nil {
		p.before(p.owner)
	}
	if p.register {
		api, ok := minimalWorkerAPI(r)
		if !ok {
			return p.owner, errMinimalWorkerBindingMissing
		}
		p.received, err = api.RegisterWorkerOwner(ctx, p.owner)
		if err != nil {
			return p.owner, err
		}
	}
	if p.after != nil {
		return p.owner, p.after()
	}
	return p.owner, nil
}
func (*minimalWorkerBindingProvider) RecoverMinimalJob(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
	return nil, ErrMinimalLaunchUnavailable
}

type minimalWorkerBindingOwner struct {
	identity MinimalLaunchIdentity
	inspect  func() MinimalLaunchIdentity
}

func (o *minimalWorkerBindingOwner) Identity() MinimalLaunchIdentity {
	if o.inspect != nil {
		return o.inspect()
	}
	return o.identity
}
func (*minimalWorkerBindingOwner) Finalize(context.Context) (MinimalLaunchCleanupReceipt, error) {
	return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
}

func newMinimalWorkerBindingFixture(t *testing.T) *minimalWorkerBindingFixture {
	t.Helper()
	f := &minimalWorkerBindingFixture{}
	var err error
	f.authority, err = NewAuthenticatedWorkerPrincipalAuthority("worker-binding-authority", "worker-binding-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	f.principal, err = f.authority.IssueAuthenticatedWorkerPrincipal("worker-binding-principal", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f.p = &minimalWorkerBindingProvider{selection: MinimalLaunchSelectionIdentity{WorkerID: "binding-worker", HostID: "binding-host", RuntimeID: "binding-runtime", RuntimeGeneration: "binding-runtime-generation", PlanID: "binding-plan", TemplatePolicyID: "binding-template", WorkspacePolicyID: "binding-workspace", NetworkPolicyID: "binding-network"}}
	f.binding, err = NewMinimalLaunchProviderBinding(f.p)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewMinimalLaunchAuthorizer(f.authority, f.binding, []MinimalLaunchScope{{PolicyID: "binding-policy", Revision: 1, PrincipalID: "worker-binding-principal", WorkerID: "binding-worker", HostID: "binding-host", TemplatePolicyID: "binding-template", WorkspacePolicyID: "binding-workspace", NetworkPolicyID: "binding-network"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Close)
	f.selection, err = authorizer.ResolveSelection(context.Background(), f.principal, "binding-worker", MinimalLaunchSelectionHints{SandboxID: "binding-sandbox", ExecutionID: "binding-execution", SubmissionID: "binding-submission", RuntimeID: "binding-runtime", PlanID: "binding-plan", TemplatePolicyID: "binding-template", WorkspacePolicyID: "binding-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.selection.Close() })
	key := "request-v2-" + strings.Repeat("b", 64)
	f.r, err = f.selection.Reserve(context.Background(), context.Background(), "binding-job", "binding-job-generation", key, time.Now().Add(time.Minute), MinimalLaunchRequestCorrelation{AdmissionGrantID: "binding-credential-grant", AdmissionGrantRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.r.Revoke)
	f.journal = &minimalWorkerAdmissionJournal{r: f.r}
	f.journal.self = f.journal
	f.input = MinimalLaunchWorkerInput{Principal: f.principal, RequestKey: key,
		Exec:        ExecRequest{Target: Target{ID: "binding-sandbox", Runtime: RuntimeState{Driver: "microvm", RuntimeID: "binding-runtime", WorkerID: "binding-worker", Metadata: &RuntimeMetadata{CapabilityLabels: []string{"original-label"}}}}, Args: []string{"test-command", "original-arg"}, Env: map[string]string{"TEST_MODE": "original-value"}, Stdin: bytes.NewReader([]byte("bounded-input")), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		Credentials: JobCredentialAdmissionRequest{GrantID: "binding-credential-grant", GrantRevision: 2, PlanID: "binding-plan", TemplatePolicyID: "binding-template", WorkspacePolicyID: "binding-workspace", SourceReferenceIDs: []string{"source-binding"}, Bindings: []JobCredentialBindingRequest{{ID: "credential-binding", Mode: JobCredentialDeliveryModeFileTmpfs, SourceReferenceID: "source-binding"}}},
	}
	return f
}

func (f *minimalWorkerBindingFixture) arm(t *testing.T) {
	t.Helper()
	if err := f.r.ArmDispatch(f.r.Context(), f.r.Identity()); err != nil {
		t.Fatal(err)
	}
}

// Copy issued authority fields with a fresh lock, not a copy of sync.Mutex.
func copyMinimalWorkerReservation(r *MinimalLaunchReservation) *MinimalLaunchReservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &MinimalLaunchReservation{self: r.self, identity: r.identity, requestCorrelation: r.requestCorrelation, templateIdentity: r.templateIdentity, selection: r.selection, ctx: r.ctx, cancel: r.cancel, ownedContext: r.ownedContext, ownedCancel: r.ownedCancel, stopAuthority: r.stopAuthority, deadline: r.deadline, armed: r.armed, attempted: r.attempted, claimed: r.claimed, revoked: r.revoked}
}
