package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// The fake provider never launches a process. Its first Start entry independently
// reads the actual manager's on-disk record, then reports an uncertain start.
// This RED stops before that entry today; its later assertions are not claimed
// as independently reproduced persistence or cleanup failures.
func TestMinimalLaunchDispatchRequiresDurableReservationBeforeProviderEntry(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	service := fixture.service(t)
	if service.jobs == nil || service.jobs.store == nil || service.jobs.stateLock == nil {
		t.Fatal("selected service did not retain the existing durable manager and state lock")
	}
	response := service.HandleAuthenticatedRequest(context.Background(), fixture.principal, fixture.request)
	if fixture.provider.startCalls != 1 {
		t.Fatalf("selected provider entries = %d, want 1 after durable minimal reservation; response OK=%t code=%v", fixture.provider.startCalls, response.OK, response.Error)
	}
	if !fixture.provider.checkedDispatch {
		t.Fatal("provider entered without independently observed durable dispatch record")
	}
	if fixture.provider.resolveCalls != 1 || fixture.provider.recoverCalls != 0 {
		t.Fatalf("provider calls = resolve:%d recover:%d, want 1/0", fixture.provider.resolveCalls, fixture.provider.recoverCalls)
	}
	if response.OK || response.JobV2 != nil {
		t.Fatal("uncertain fake start published a credential/job success")
	}
	files := minimalLaunchRecordFiles(t, fixture.stateDir)
	if len(files) != 1 {
		t.Fatalf("uncertain dispatched reservation files = %d, want retained single record", len(files))
	}
}

func TestMinimalLaunchDispatchRejectsDifferentPrincipalIssuer(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	service := fixture.service(t)
	_, foreign := l8D6WorkerPrincipal(t) // Equal visible IDs, different live issuer.
	response := service.HandleAuthenticatedRequest(context.Background(), foreign, fixture.request)
	want := l8AuthenticatedPrincipalFailureResponse(fixture.request)
	if !reflect.DeepEqual(response, want) {
		t.Fatalf("foreign issuer response = %#v, want exact principal rejection", response)
	}
	fixture.assertNoProviderOrRecord(t)
}

func TestMinimalLaunchDispatchConstructorRequiresExactDependencies(t *testing.T) {
	for _, name := range []string{"missing authorizer", "missing provider", "zero provider", "different provider", "copied provider", "same provider different binding", "different issuer", "copied authorizer", "legacy binder also selected"} {
		t.Run(name, func(t *testing.T) {
			fixture := newMinimalLaunchDispatchFixture(t)
			options := fixture.options()
			switch name {
			case "missing authorizer":
				options.MinimalLaunch.Authorizer = nil
			case "missing provider":
				options.MinimalLaunch.Provider = nil
			case "zero provider":
				options.MinimalLaunch.Provider = &sandboxruntime.MinimalLaunchProviderBinding{}
			case "different provider":
				options.MinimalLaunch.Provider = minimalLaunchDispatchBinding(t, &minimalLaunchDispatchProvider{})
			case "copied provider":
				copied := *fixture.binding
				options.MinimalLaunch.Provider = &copied
			case "same provider different binding":
				options.MinimalLaunch.Provider = minimalLaunchDispatchBinding(t, fixture.provider)
			case "different issuer":
				options.PrincipalAuthority, _ = l8D6WorkerPrincipal(t)
			case "copied authorizer":
				copied := *fixture.authorizer
				options.MinimalLaunch.Authorizer = &copied
			case "legacy binder also selected":
				var err error
				options.Binder, err = sandboxruntime.NewJobCredentialRuntimeBinder(&l8WorkerBindingProvider{})
				if err != nil {
					t.Fatal(err)
				}
			}
			service, err := NewL8DurableService(options)
			if service != nil {
				service.Close()
			}
			if !errors.Is(err, ErrL8ServiceUnavailable) || service != nil {
				t.Fatalf("constructor = %v, %v, want unavailable", service, err)
			}
			if _, err := os.Stat(fixture.stateDir); !os.IsNotExist(err) {
				t.Fatalf("invalid pairing mutated state directory: %v", err)
			}
		})
	}
}

func TestMinimalLaunchDispatchProviderBindingRejectsMissingAndTypedNil(t *testing.T) {
	for _, provider := range []sandboxruntime.MinimalJobRuntimeProvider{nil, (*minimalLaunchDispatchProvider)(nil)} {
		binding, err := sandboxruntime.NewMinimalLaunchProviderBinding(provider)
		if binding != nil || !errors.Is(err, sandboxruntime.ErrMinimalLaunchUnavailable) {
			t.Fatalf("missing provider binding = %v, %v", binding, err)
		}
	}
}

func TestMinimalLaunchDispatchCancellationPrecedesProviderEntry(t *testing.T) {
	fixture := newMinimalLaunchDispatchFixture(t)
	service := fixture.service(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := service.HandleAuthenticatedRequest(ctx, fixture.principal, fixture.request)
	want, _ := contextErrorResponse(ctx, fixture.request)
	if !reflect.DeepEqual(response, want) {
		t.Fatalf("canceled response = %#v, want exact context rejection", response)
	}
	fixture.assertNoProviderOrRecord(t)
}

type minimalLaunchDispatchFixture struct {
	request    Request
	stateDir   string
	authority  *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	principal  sandboxruntime.AuthenticatedWorkerPrincipal
	authorizer *sandboxruntime.MinimalLaunchAuthorizer
	binding    *sandboxruntime.MinimalLaunchProviderBinding
	provider   *minimalLaunchDispatchProvider
}

func newMinimalLaunchDispatchFixture(t *testing.T) *minimalLaunchDispatchFixture {
	t.Helper()
	request := l8D6WorkerStartRequest(t)
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	authority, principal := l8D6WorkerPrincipal(t)
	fixture := &minimalLaunchDispatchFixture{request: request, stateDir: filepath.Join(t.TempDir(), "jobs-v2"), authority: authority, principal: principal}
	fixture.provider = &minimalLaunchDispatchProvider{t: t, fixture: fixture}
	fixture.binding = minimalLaunchDispatchBinding(t, fixture.provider)
	var err error
	fixture.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(authority, fixture.binding, []sandboxruntime.MinimalLaunchScope{{
		PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker",
		WorkerID: "worker-l8-neutral", HostID: "host-minimal", NetworkPolicyID: "network-minimal",
		TemplatePolicyID: request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: request.JobStartV2.WorkspacePolicyID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *minimalLaunchDispatchFixture) options() L8DurableServiceOptions {
	return L8DurableServiceOptions{
		WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: fixture.stateDir, PrincipalAuthority: fixture.authority,
		MinimalLaunch: &L8MinimalLaunchOptions{Authorizer: fixture.authorizer, Provider: fixture.binding},
	}
}

func minimalLaunchDispatchBinding(t *testing.T, provider sandboxruntime.MinimalJobRuntimeProvider) *sandboxruntime.MinimalLaunchProviderBinding {
	t.Helper()
	binding, err := sandboxruntime.NewMinimalLaunchProviderBinding(provider)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func (fixture *minimalLaunchDispatchFixture) service(t *testing.T) *L8Service {
	t.Helper()
	service, err := NewL8DurableService(fixture.options())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service
}

func (fixture *minimalLaunchDispatchFixture) assertNoProviderOrRecord(t *testing.T) {
	t.Helper()
	if fixture.provider.resolveCalls != 0 || fixture.provider.startCalls != 0 || fixture.provider.recoverCalls != 0 || len(minimalLaunchRecordFiles(t, fixture.stateDir)) != 0 {
		t.Fatal("rejection entered provider or persisted a job")
	}
}

type minimalLaunchDispatchProvider struct {
	t                                      *testing.T
	fixture                                *minimalLaunchDispatchFixture
	resolveCalls, startCalls, recoverCalls int
	checkedDispatch                        bool
	selection                              *minimalLaunchDispatchSelection
}

func (provider *minimalLaunchDispatchProvider) ResolveMinimalSelection(_ context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	provider.resolveCalls++
	start := provider.fixture.request.JobStartV2
	want := sandboxruntime.MinimalLaunchSelectionHints{
		SandboxID: workerV2RequestSandboxID(start.Exec.Target), ExecutionID: start.Exec.OperationID,
		SubmissionID: start.SubmissionID, RuntimeID: start.Exec.Target.Runtime.RuntimeID, PlanID: start.PlanID,
		TemplatePolicyID: start.TemplatePolicyID, WorkspacePolicyID: start.WorkspacePolicyID,
	}
	if hints != want || len(minimalLaunchRecordFiles(provider.t, provider.fixture.stateDir)) != 0 {
		provider.t.Fatal("read-only selection did not precede allocation with exact request hints")
	}
	provider.selection = &minimalLaunchDispatchSelection{identity: sandboxruntime.MinimalLaunchSelectionIdentity{
		WorkerID: "worker-l8-neutral", HostID: "host-minimal", RuntimeID: hints.RuntimeID, RuntimeGeneration: "runtime-generation-minimal",
		PlanID: hints.PlanID, TemplatePolicyID: hints.TemplatePolicyID, WorkspacePolicyID: hints.WorkspacePolicyID, NetworkPolicyID: "network-minimal",
	}}
	return provider.selection, nil
}

func (provider *minimalLaunchDispatchProvider) StartMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, selection sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	provider.startCalls++
	if selection != provider.selection || provider.selection == nil || provider.selection.closed {
		provider.t.Fatal("provider did not receive its retained current selection")
	}
	identity, err := reservation.ClaimLaunch(ctx)
	if err != nil {
		provider.t.Fatalf("durably dispatched reservation could not be claimed: %v", err)
	}
	provider.checkDurableDispatch(identity)
	provider.checkedDispatch = true
	return nil, errors.New("test-only uncertain provider start")
}

func (provider *minimalLaunchDispatchProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	provider.recoverCalls++
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

type minimalLaunchDispatchSelection struct {
	identity sandboxruntime.MinimalLaunchSelectionIdentity
	closed   bool
}

func (selection *minimalLaunchDispatchSelection) Current(context.Context) (sandboxruntime.MinimalLaunchSelectionIdentity, error) {
	if selection.closed {
		return sandboxruntime.MinimalLaunchSelectionIdentity{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return selection.identity, nil
}

func (selection *minimalLaunchDispatchSelection) Close() error {
	selection.closed = true
	return nil
}

func minimalLaunchRecordFiles(t *testing.T, stateDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, filepath.Join(stateDir, entry.Name()))
		}
	}
	return names
}

func (provider *minimalLaunchDispatchProvider) checkDurableDispatch(identity sandboxruntime.MinimalLaunchIdentity) {
	t := provider.t
	t.Helper()
	files := minimalLaunchRecordFiles(t, provider.fixture.stateDir)
	if len(files) != 1 || filepath.Base(files[0]) != identity.WorkerJobID+".json" {
		t.Fatal("provider entered without exactly one allocated durable job")
	}
	data, err := os.ReadFile(files[0]) // Independent ordinary-file observation, not production readback proof.
	if err != nil || len(data) > int(maxStoredJobStateV2Bytes) {
		t.Fatalf("read dispatched record: %v", err)
	}
	var stored struct {
		JobV2                     JobV2
		RequestKey                string          `json:"requestKey"`
		PrincipalID               string          `json:"principalId"`
		DaemonGeneration          string          `json:"daemonGeneration"`
		CredentialState           json.RawMessage `json:"credentialState"`
		CredentialRecoveryReceipt json.RawMessage `json:"credentialRecoveryReceipt"`
		MinimalLaunch             struct {
			ContractVersion      string `json:"contractVersion"`
			Phase                string `json:"phase"`
			Revision             uint64 `json:"revision"`
			JobGeneration        string `json:"jobGeneration"`
			LaunchGrantID        string `json:"launchGrantId"`
			LaunchPolicyID       string `json:"launchPolicyId"`
			LaunchPolicyRevision uint64 `json:"launchPolicyRevision"`
		} `json:"minimalLaunch"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	request := provider.fixture.request
	key, err := jobRequestKeyV2(request.DriverID, "principal-l8-worker", l8WorkerV2DaemonGeneration, *request.JobStartV2)
	if err != nil {
		t.Fatal(err)
	}
	want := sandboxruntime.MinimalLaunchIdentity{
		WorkerJobID: stored.JobV2.ID, JobGeneration: stored.MinimalLaunch.JobGeneration,
		WorkerID: "worker-l8-neutral", HostID: "host-minimal", PrincipalID: "principal-l8-worker",
		SandboxID: workerV2RequestSandboxID(request.JobStartV2.Exec.Target), ExecutionID: request.JobStartV2.Exec.OperationID,
		SubmissionID: request.JobStartV2.SubmissionID, RuntimeID: request.JobStartV2.Exec.Target.Runtime.RuntimeID,
		RuntimeGeneration: "runtime-generation-minimal", PlanID: request.JobStartV2.PlanID, RequestKey: key,
		LaunchGrantID: stored.MinimalLaunch.LaunchGrantID, LaunchPolicyID: "minimal-launch-policy", LaunchPolicyRevision: 3,
	}
	if identity != want || !validWorkerV2JobID(identity.WorkerJobID) || !validWorkerV2SafeID(identity.JobGeneration) || identity.JobGeneration == identity.WorkerJobID ||
		!validWorkerV2SafeID(identity.LaunchGrantID) || identity.LaunchGrantID == request.JobStartV2.AdmissionGrantID {
		t.Fatal("launch identity was not independently allocated and exactly request/selection/policy bound")
	}
	if stored.RequestKey != key || stored.PrincipalID != identity.PrincipalID || stored.DaemonGeneration != l8WorkerV2DaemonGeneration ||
		stored.JobV2.WorkerID != identity.WorkerID || stored.JobV2.HostID != identity.HostID || stored.JobV2.RuntimeID != identity.RuntimeID || stored.JobV2.RuntimeDriver != RuntimeDriverMicroVM ||
		stored.JobV2.State != JobStateQueued || !reflect.DeepEqual(stored.JobV2.CredentialIntent, request.JobStartV2.credentialIntent()) ||
		stored.MinimalLaunch.ContractVersion != "sandboxjob-minimal-launch-private-v1" || stored.MinimalLaunch.Phase != "dispatching" || stored.MinimalLaunch.Revision < 2 ||
		stored.MinimalLaunch.LaunchPolicyID != identity.LaunchPolicyID || stored.MinimalLaunch.LaunchPolicyRevision != identity.LaunchPolicyRevision ||
		stored.CredentialState != nil || stored.CredentialRecoveryReceipt != nil {
		t.Fatal("provider entered before exact minimal dispatch publication, or with fabricated legacy credential ownership")
	}
}
