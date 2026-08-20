package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8ServiceDefaultPathPreservesExactEarlyUnsupportedResponse(t *testing.T) {
	service := l8NeutralWorkerService(t)
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)
	for _, request := range fixtures.v2Requests() {
		got := service.HandleRequest(context.Background(), request.req)
		want := unsupportedOperationResponse(request.req)
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("default %s response = %s, want byte-equivalent %s", request.name, gotJSON, wantJSON)
		}
	}
}

func TestL8ServiceExplicitInjectionBindsMetadataFreeTargetAndFailsClosed(t *testing.T) {
	seed := l8WorkerBindingSeed(t)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	loss := make(chan sandboxruntime.JobCredentialLoss)
	preflight := &l8WorkerBindingPreflight{identity: identity, loss: loss, cleanup: l8WorkerCleanupProof(t, identity)}
	provider := &l8WorkerBindingProvider{seed: seed, runtime: &l8WorkerBindingRuntime{preflight: preflight}}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	l8, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	request.JobStartV2.Exec.Target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{
		CapabilityLabels: []string{"untrusted-runtime-generation"},
	}

	response := l8.HandleRequest(context.Background(), request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("L8 neutral response = %#v, want fail-closed unsupported", response)
	}
	if provider.calls != 1 || preflight.abortCalls != 1 {
		t.Fatalf("neutral ownership calls = bind:%d abort:%d, want 1/1", provider.calls, preflight.abortCalls)
	}
	if provider.target.Runtime.Metadata != nil || provider.target.Connection != (sandboxruntime.ConnectionInfo{}) {
		t.Fatalf("provider target retained untrusted metadata/connection: %#v", provider.target)
	}
	close(loss)
}

func TestL8ServiceContainsBindingFailureAndDoesNotClaimCompletion(t *testing.T) {
	seed := l8WorkerBindingSeed(t)
	provider := &l8WorkerBindingProvider{seed: seed, panicValue: "token=provider-secret path=/private/runtime.sock"}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	l8, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	response := l8.HandleRequest(context.Background(), request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal {
		t.Fatalf("provider panic response = %#v, want internal failure", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"provider-secret", "/private", "token="} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("provider panic response leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestL8ServiceRetainsCleanupFailureAndNeverPublishesV2Success(t *testing.T) {
	seed := l8WorkerBindingSeed(t)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	loss := make(chan sandboxruntime.JobCredentialLoss)
	preflight := &l8WorkerBindingPreflight{
		identity: identity,
		loss:     loss,
		abortErr: errors.New("token=cleanup-secret path=/private/cleanup.sock"),
	}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8WorkerBindingProvider{
		seed:    seed,
		runtime: &l8WorkerBindingRuntime{preflight: preflight},
	})
	if err != nil {
		t.Fatal(err)
	}
	l8, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	response := l8.HandleRequest(context.Background(), request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal || preflight.abortCalls != 1 {
		t.Fatalf("cleanup failure response = %#v, abort calls %d; want retained internal failure", response, preflight.abortCalls)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"cleanup-secret", "/private", "token="} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("cleanup failure response leaked %q: %s", forbidden, encoded)
		}
	}
	close(loss)
}

func TestL8ServiceDoesNotBindNoIntentOrNonStartV2Operations(t *testing.T) {
	provider := &l8WorkerBindingProvider{panicValue: "provider must not be called"}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	l8, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)
	noIntent := fixtures.v2Requests()[0].req
	noIntent.JobStartV2.ProductionCredentialsRequested = false
	noIntent.JobStartV2.PlanID = ""
	noIntent.JobStartV2.AdmissionGrantID = ""
	noIntent.JobStartV2.AdmissionGrantRevision = 0
	noIntent.JobStartV2.TemplatePolicyID = ""
	noIntent.JobStartV2.WorkspacePolicyID = ""
	noIntent.JobStartV2.SourceReferenceIDs = nil
	noIntent.JobStartV2.Bindings = nil
	requests := append([]l8WorkerV2NamedRequest{{name: "no-intent", req: noIntent}}, fixtures.v2Requests()[1:]...)
	for _, request := range requests {
		response := l8.HandleRequest(context.Background(), request.req)
		if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
			t.Fatalf("%s response = %#v, want unsupported", request.name, response)
		}
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want zero outside production credential start", provider.calls)
	}
}

func TestL8ServiceClassifiesCanceledRequestBeforeProviderBinding(t *testing.T) {
	provider := &l8WorkerBindingProvider{panicValue: "provider must not be called"}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	l8, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	response := l8.HandleRequest(ctx, request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled response = %#v, want request_canceled", response)
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want zero after boundary cancellation", provider.calls)
	}
}

func TestNewL8ServiceRejectsMissingBinder(t *testing.T) {
	service, err := NewL8Service(nil)
	if service != nil || !errors.Is(err, ErrL8ServiceUnavailable) {
		t.Fatalf("NewL8Service(nil) = %#v, %v; want unavailable", service, err)
	}
}

func l8NeutralWorkerService(t *testing.T) *Service {
	t.Helper()
	registry, err := NewDriverRegistry()
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-l8-neutral",
		Registry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service
}

type l8WorkerBindingProvider struct {
	seed       sandboxruntime.JobCredentialIdentitySeed
	runtime    sandboxruntime.JobCredentialRuntime
	panicValue any
	target     sandboxruntime.Target
	calls      int
}

func (provider *l8WorkerBindingProvider) BindJobCredentialRuntime(_ context.Context, target sandboxruntime.Target) (sandboxruntime.JobCredentialIdentitySeed, sandboxruntime.JobCredentialRuntime, error) {
	provider.calls++
	if provider.panicValue != nil {
		panic(provider.panicValue)
	}
	provider.target = target
	return provider.seed, provider.runtime, nil
}

type l8WorkerBindingRuntime struct {
	preflight sandboxruntime.JobCredentialRuntimePreflight
}

func (runtime *l8WorkerBindingRuntime) PreflightJobCredentials(context.Context, sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimePreflight, error) {
	return runtime.preflight, nil
}

func (*l8WorkerBindingRuntime) RecoverJobCredentials(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
	return sandboxruntime.JobCredentialCleanupProof{}, nil
}

type l8WorkerBindingPreflight struct {
	identity   sandboxruntime.JobCredentialIdentity
	loss       chan sandboxruntime.JobCredentialLoss
	cleanup    sandboxruntime.JobCredentialCleanupProof
	abortErr   error
	abortCalls int
}

func (preflight *l8WorkerBindingPreflight) Identity() sandboxruntime.JobCredentialIdentity {
	return preflight.identity
}

func (*l8WorkerBindingPreflight) PrepareJobCredentials(context.Context, sandboxruntime.JobCredentialPrepareRequest) (sandboxruntime.JobCredentialSession, error) {
	panic("neutral worker seam must not resolve or prepare a credential source")
}

func (preflight *l8WorkerBindingPreflight) Abort(context.Context) (sandboxruntime.JobCredentialCleanupProof, error) {
	preflight.abortCalls++
	return preflight.cleanup, preflight.abortErr
}

func (preflight *l8WorkerBindingPreflight) Loss() <-chan sandboxruntime.JobCredentialLoss {
	return preflight.loss
}

func l8WorkerBindingSeed(t *testing.T) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	issuedAt := time.Date(2026, time.August, 21, 5, 6, 7, 0, time.UTC)
	return sandboxruntime.JobCredentialIdentitySeed{
		SandboxID:                    "sandbox-l8-worker",
		ExecutionID:                  "execution-l8-worker",
		WorkerID:                     "worker-l8-neutral",
		HostID:                       "host-l8-worker",
		RuntimeDriver:                sandboxruntime.DriverMicroVM,
		RuntimeID:                    "runtime-l8-worker",
		RuntimeGeneration:            "runtime-generation-worker",
		FirecrackerProcessGeneration: "firecracker-generation-worker",
		VsockGeneration:              "vsock-generation-worker",
		WorkerJobID:                  "job-l8-worker",
		SubmissionID:                 "submission-v2-primary",
		PlanID:                       "plan-primary",
		ActivationGeneration:         "activation-generation-worker",
		CredentialGeneration:         "credential-generation-worker",
		NetworkPlanID:                "network-plan-worker",
		PolicySnapshotID:             "policy-snapshot-worker",
		ProxySessionID:               "proxy-session-worker",
		ProxyGenerationID:            "proxy-generation-worker",
		TopologyGenerationID:         "topology-generation-worker",
		RuleGenerationID:             "rule-generation-worker",
		AdmissionGrantID:             "grant-primary",
		PrincipalID:                  "principal-l8-worker",
		TemplatePolicyID:             "template-policy-primary",
		WorkspacePolicyID:            "workspace-policy-primary",
		ControllerKeyGeneration:      "controller-generation-worker",
		GuestBootGeneration:          "guest-boot-generation-worker",
		GuestImageGeneration:         "guest-image-generation-worker",
		GuestImageDigest:             "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AdmissionGrantRevision:       7,
		BindingIDs:                   []string{"binding-http"},
		DeliveryModes:                []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy},
		IssuedAt:                     issuedAt,
	}
}

func l8WorkerGuestSessionGeneration() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

func l8WorkerCleanupProof(t *testing.T, identity sandboxruntime.JobCredentialIdentity) sandboxruntime.JobCredentialCleanupProof {
	t.Helper()
	proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID:            "cleanup-l8-worker",
		Identity:           identity,
		Revision:           1,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
