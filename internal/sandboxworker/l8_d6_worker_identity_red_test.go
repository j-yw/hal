package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8D6WorkerCredentialPrivateSchemasAreExact(t *testing.T) {
	seedFields := []string{
		`SandboxID|string|json:"sandboxId"`, `ExecutionID|string|json:"executionId"`, `WorkerID|string|json:"workerId"`, `HostID|string|json:"hostId"`,
		`RuntimeDriver|string|json:"runtimeDriver"`, `RuntimeID|string|json:"runtimeId"`, `RuntimeGeneration|string|json:"runtimeGeneration"`,
		`FirecrackerProcessGeneration|string|json:"firecrackerProcessGeneration"`, `VsockGeneration|string|json:"vsockGeneration"`,
		`WorkerJobID|string|json:"workerJobId"`, `SubmissionID|string|json:"submissionId"`, `PlanID|string|json:"planId"`,
		`ActivationGeneration|string|json:"activationGeneration"`, `CredentialGeneration|string|json:"credentialGeneration"`,
		`NetworkPlanID|string|json:"networkPlanId"`, `PolicySnapshotID|string|json:"policySnapshotId"`, `ProxySessionID|string|json:"proxySessionId"`,
		`ProxyGenerationID|string|json:"proxyGenerationId"`, `TopologyGenerationID|string|json:"topologyGenerationId"`, `RuleGenerationID|string|json:"ruleGenerationId"`,
		`AdmissionGrantID|string|json:"admissionGrantId"`, `PrincipalID|string|json:"principalId"`, `TemplatePolicyID|string|json:"templatePolicyId"`,
		`WorkspacePolicyID|string|json:"workspacePolicyId"`, `ControllerKeyGeneration|string|json:"controllerKeyGeneration"`,
		`GuestBootGeneration|string|json:"guestBootGeneration"`, `GuestImageGeneration|string|json:"guestImageGeneration"`, `GuestImageDigest|string|json:"guestImageDigest"`,
		`AdmissionGrantRevision|uint64|json:"admissionGrantRevision"`, `BindingIDs|[]string|json:"bindingIds"`, `DeliveryModes|[]string|json:"deliveryModes"`, `IssuedAt|time.Time|json:"issuedAt"`,
	}
	identityFields := append([]string(nil), seedFields[:28]...)
	identityFields = append(identityFields,
		`GuestSessionGeneration|string|json:"guestSessionGeneration"`,
		`GuestHelperGeneration|string|json:"guestHelperGeneration"`,
	)
	identityFields = append(identityFields, seedFields[28:]...)
	l8D6AssertPrivateSchema(t, reflect.TypeOf(storedJobCredentialIdentitySeedV1{}), seedFields)
	l8D6AssertPrivateSchema(t, reflect.TypeOf(storedJobCredentialIdentityV1{}), identityFields)
	l8D6AssertPrivateSchema(t, reflect.TypeOf(storedJobCredentialStateV2{}), []string{
		`ContractVersion|string|json:"contractVersion"`,
		`Seed|sandboxworker.storedJobCredentialIdentitySeedV1|json:"seed"`,
		`Identity|*sandboxworker.storedJobCredentialIdentityV1|json:"identity,omitempty"`,
		`Revision|uint64|json:"revision"`,
	})

	stored := reflect.TypeOf(storedJobStateV2{})
	field, ok := stored.FieldByName("CredentialState")
	if !ok || field.Type != reflect.TypeOf((*storedJobCredentialStateV2)(nil)) || string(field.Tag) != `json:"credentialState,omitempty"` {
		t.Fatalf("storedJobStateV2 credential field = %#v, %t", field, ok)
	}
	if _, public := reflect.TypeOf(JobV2{}).FieldByName("CredentialState"); public {
		t.Fatal("private credential state escaped onto public JobV2")
	}
	for _, root := range []reflect.Type{reflect.TypeOf(sandboxruntime.JobCredentialIdentitySeed{}), reflect.TypeOf(sandboxruntime.JobCredentialIdentity{})} {
		for index := 0; index < root.NumField(); index++ {
			if root.Field(index).Tag.Get("json") != "" {
				t.Fatalf("root %s gained durable JSON tag on %s", root.Name(), root.Field(index).Name)
			}
		}
	}
}

func TestL8D6WorkerPersistsSeedBeforePreflightAndIdentityBeforeBoundedAbort(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	request := l8D6WorkerStartRequest(t)
	seed := l8D6WorkerSeed(t, request)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}

	order := &l8D6OrderRecorder{}
	preflight := &l8D6WorkerPreflight{
		identity: identity,
		loss:     make(chan sandboxruntime.JobCredentialLoss),
		cleanup:  l8WorkerCleanupProof(t, identity),
		stateDir: stateDir,
		jobID:    seed.WorkerJobID,
		order:    order,
	}
	runtime := &l8D6WorkerRuntime{preflight: preflight, stateDir: stateDir, jobID: seed.WorkerJobID, order: order}
	provider := &l8D6WorkerProvider{seed: seed, runtime: runtime}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	authority, principal := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID:           seed.WorkerID,
		DaemonGeneration:   l8WorkerV2DaemonGeneration,
		StateDir:           stateDir,
		Binder:             binder,
		PrincipalAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)

	ctx, cancel := context.WithCancel(context.Background())
	preflight.cancelRequest = cancel
	response := service.HandleAuthenticatedRequest(ctx, principal, request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("durable boundary response = %#v, want stable unsupported dependency", response)
	}
	if got, want := order.snapshot(), []string{"preflight-after-seed", "identity-after-seed", "abort-after-identity"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("durable ordering = %v, want %v", got, want)
	}
	if !preflight.abortContextIndependent || preflight.abortCalls != 1 || runtime.preflightCalls != 1 || provider.calls != 1 {
		t.Fatalf("ownership calls = bind:%d preflight:%d abort:%d independent:%t", provider.calls, runtime.preflightCalls, preflight.abortCalls, preflight.abortContextIndependent)
	}
	if provider.target.Runtime.Metadata != nil || provider.target.Connection != (sandboxruntime.ConnectionInfo{}) {
		t.Fatalf("binding retained untrusted metadata/connection: %#v", provider.target)
	}

	stored, err := service.jobs.store.load(seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil || stored.CredentialState.Identity == nil || stored.CredentialState.Revision != 0 {
		t.Fatalf("private durable credential state = %#v", stored.CredentialState)
	}
	runtimeSeed, err := stored.CredentialState.Seed.runtimeSeed()
	if err != nil {
		t.Fatal(err)
	}
	runtimeIdentity, err := stored.CredentialState.Identity.runtimeIdentity()
	if err != nil || sandboxruntime.ValidateJobCredentialIdentityCompletion(runtimeSeed, runtimeIdentity) != nil {
		t.Fatalf("durable identity completion = %v", err)
	}
	publicJSON, err := json.Marshal(stored.JobV2)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"credentialState", "guestSessionGeneration", "guestHelperGeneration", "runtimeGeneration", "firecrackerProcessGeneration", "vsockGeneration"} {
		if strings.Contains(string(publicJSON), forbidden) {
			t.Fatalf("public job leaked private field %q: %s", forbidden, publicJSON)
		}
	}
}

func TestL8D6WorkerConcurrentReplayPreflightsExactlyOnce(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	request := l8D6WorkerStartRequest(t)
	seed := l8D6WorkerSeed(t, request)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	preflight := &l8D6WorkerPreflight{identity: identity, loss: make(chan sandboxruntime.JobCredentialLoss), cleanup: l8WorkerCleanupProof(t, identity)}
	runtime := &l8D6WorkerRuntime{preflight: preflight}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{seed: seed, runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	authority, principal := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: stateDir, Binder: binder, PrincipalAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)

	const callers = 24
	responses := make(chan Response, callers)
	var start sync.WaitGroup
	start.Add(1)
	var callersWG sync.WaitGroup
	for index := 0; index < callers; index++ {
		callersWG.Add(1)
		go func() {
			defer callersWG.Done()
			start.Wait()
			responses <- service.HandleAuthenticatedRequest(context.Background(), principal, request)
		}()
	}
	start.Done()
	callersWG.Wait()
	close(responses)
	for response := range responses {
		if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
			t.Fatalf("concurrent response = %#v", response)
		}
	}
	if runtime.preflightCallCount() != 1 || preflight.abortCallCount() != 1 {
		t.Fatalf("concurrent ownership = preflight:%d abort:%d, want 1/1", runtime.preflightCallCount(), preflight.abortCallCount())
	}
}

func TestL8D6WorkerRestartRetainsOwnershipAndRequiresRecoveryDependency(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8D6WorkerStartRequest(t).JobStartV2
	seed := l8D6WorkerSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
	job, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed)
	if err != nil || existing {
		t.Fatalf("accept seed = %#v, %t, %v", job, existing, err)
	}
	manager.close()
	path := stateDir + "/" + job.ID + ".json"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if restarted != nil || !errors.Is(err, ErrL8RecoveryDependency) {
		t.Fatalf("restart = %#v, %v, want recovery dependency", restarted, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed-closed restart mutated retained credential ownership")
	}
	store, err := newJobStoreV2(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.JobV2.State != JobStateQueued || retained.JobV2.FinishedAt != nil || retained.CredentialState == nil {
		t.Fatalf("restart fabricated terminal cleanup: %#v", retained)
	}
}

func TestL8D6WorkerRestartRetainsCompleteIdentityWithoutCleanupFabrication(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8D6WorkerStartRequest(t).JobStartV2
	seed := l8D6WorkerSeed(t, Request{DriverID: RuntimeDriverMicroVM, JobStartV2: request})
	job, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-l8-worker", *request, seed)
	if err != nil || existing {
		t.Fatalf("accept seed = %#v, %t, %v", job, existing, err)
	}
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.persistCredentialIdentity(job.ID, "principal-l8-worker", identity); err != nil {
		t.Fatal(err)
	}
	manager.close()

	path := stateDir + "/" + job.ID + ".json"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-l8-neutral", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if restarted != nil || !errors.Is(err, ErrL8RecoveryDependency) {
		t.Fatalf("restart = %#v, %v, want recovery dependency", restarted, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed-closed restart mutated complete retained credential identity")
	}
	store, err := newJobStoreV2(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.JobV2.State != JobStateQueued || retained.JobV2.FinishedAt != nil || retained.CredentialState == nil || retained.CredentialState.Identity == nil {
		t.Fatalf("restart fabricated terminal cleanup: %#v", retained)
	}
}

func TestL8D6WorkerRejectsInvalidPrincipalAndSeedBeforePreflight(t *testing.T) {
	request := l8D6WorkerStartRequest(t)
	seed := l8D6WorkerSeed(t, request)
	runtime := &l8D6WorkerRuntime{}
	provider := &l8D6WorkerProvider{seed: seed, runtime: runtime}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	authority, principal := l8D6WorkerPrincipal(t)
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: t.TempDir() + "/jobs-v2", Binder: binder, PrincipalAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)

	otherAuthority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("other-authority", "other-generation")
	if err != nil {
		t.Fatal(err)
	}
	forged, err := otherAuthority.IssueAuthenticatedWorkerPrincipal("principal-l8-worker", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	response := service.HandleAuthenticatedRequest(context.Background(), forged, request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal || provider.calls != 0 {
		t.Fatalf("foreign principal response = %#v, bind calls %d", response, provider.calls)
	}

	provider.seed.WorkerID = "worker-neighbor"
	response = service.HandleAuthenticatedRequest(context.Background(), principal, request)
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeInternal || runtime.preflightCallCount() != 0 {
		t.Fatalf("mismatched seed response = %#v, preflight calls %d", response, runtime.preflightCallCount())
	}
}

func TestL8D6WorkerCredentialBindingBoundIsSixteen(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = make([]string, 17)
	request.Bindings = make([]JobCredentialBindingV2, 17)
	seed := l8WorkerBindingSeed(t)
	seed.BindingIDs = make([]string, 17)
	seed.DeliveryModes = make([]sandboxruntime.JobCredentialDeliveryMode, 17)
	seed.NetworkPlanID, seed.PolicySnapshotID, seed.ProxySessionID = "", "", ""
	seed.ProxyGenerationID, seed.TopologyGenerationID, seed.RuleGenerationID = "", "", ""
	for index := 0; index < 17; index++ {
		bindingID := "binding-" + string(rune('a'+index))
		sourceID := "source-" + string(rune('a'+index))
		request.SourceReferenceIDs[index] = sourceID
		request.Bindings[index] = JobCredentialBindingV2{BindingID: bindingID, SourceReferenceID: sourceID, Mode: CredentialModeFileTmpfs}
		seed.BindingIDs[index] = bindingID
		seed.DeliveryModes[index] = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
	}
	if request.Validate() == nil || sandboxruntime.ValidateJobCredentialIdentitySeed(seed) == nil {
		t.Fatal("worker request or durable seed accepted seventeen credential bindings")
	}
}

func TestL8D6WorkerCredentialBindingBoundAcceptsExactlySixteen(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = make([]string, 16)
	request.Bindings = make([]JobCredentialBindingV2, 16)
	seed := l8WorkerBindingSeed(t)
	seed.BindingIDs = make([]string, 16)
	seed.DeliveryModes = make([]sandboxruntime.JobCredentialDeliveryMode, 16)
	seed.NetworkPlanID, seed.PolicySnapshotID, seed.ProxySessionID = "", "", ""
	seed.ProxyGenerationID, seed.TopologyGenerationID, seed.RuleGenerationID = "", "", ""
	for index := 0; index < 16; index++ {
		bindingID := "binding-" + string(rune('a'+index))
		sourceID := "source-" + string(rune('a'+index))
		request.SourceReferenceIDs[index] = sourceID
		request.Bindings[index] = JobCredentialBindingV2{BindingID: bindingID, SourceReferenceID: sourceID, Mode: CredentialModeFileTmpfs}
		seed.BindingIDs[index] = bindingID
		seed.DeliveryModes[index] = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("worker request rejected exactly sixteen credential bindings: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err != nil {
		t.Fatalf("durable seed rejected exactly sixteen credential bindings: %v", err)
	}
}

func l8D6AssertPrivateSchema(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	if typ.NumField() != len(want) {
		t.Fatalf("%s fields = %d, want %d", typ.Name(), typ.NumField(), len(want))
	}
	for index, expected := range want {
		field := typ.Field(index)
		got := field.Name + "|" + field.Type.String() + "|" + string(field.Tag)
		if got != expected {
			t.Fatalf("%s field %d = %q, want %q", typ.Name(), index, got, expected)
		}
	}
}

func l8D6WorkerStartRequest(t *testing.T) Request {
	t.Helper()
	request := l8WorkerV2RequestPayloadFixturesForTest(t).v2Requests()[0].req
	request.DriverID = RuntimeDriverMicroVM
	return request
}

func l8D6WorkerSeed(t *testing.T, request Request) sandboxruntime.JobCredentialIdentitySeed {
	t.Helper()
	seed := l8WorkerBindingSeed(t)
	start := request.JobStartV2
	seed.WorkerID = "worker-l8-neutral"
	seed.SandboxID = workerV2RequestSandboxID(start.Exec.Target)
	seed.ExecutionID = strings.TrimSpace(start.Exec.OperationID)
	seed.RuntimeDriver = strings.TrimSpace(request.DriverID)
	seed.RuntimeID = strings.TrimSpace(start.Exec.Target.Runtime.RuntimeID)
	seed.SubmissionID = strings.TrimSpace(start.SubmissionID)
	seed.PlanID = strings.TrimSpace(start.PlanID)
	seed.AdmissionGrantID = strings.TrimSpace(start.AdmissionGrantID)
	seed.AdmissionGrantRevision = start.AdmissionGrantRevision
	seed.PrincipalID = "principal-l8-worker"
	seed.TemplatePolicyID = strings.TrimSpace(start.TemplatePolicyID)
	seed.WorkspacePolicyID = strings.TrimSpace(start.WorkspacePolicyID)
	seed.BindingIDs = make([]string, len(start.Bindings))
	seed.DeliveryModes = make([]sandboxruntime.JobCredentialDeliveryMode, len(start.Bindings))
	for index := range start.Bindings {
		seed.BindingIDs[index] = strings.TrimSpace(start.Bindings[index].BindingID)
		seed.DeliveryModes[index] = sandboxruntime.JobCredentialDeliveryMode(strings.TrimSpace(start.Bindings[index].Mode))
	}
	return seed
}

func l8D6WorkerPrincipal(t *testing.T) (*sandboxruntime.AuthenticatedWorkerPrincipalAuthority, sandboxruntime.AuthenticatedWorkerPrincipal) {
	t.Helper()
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", l8WorkerV2DaemonGeneration)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("principal-l8-worker", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return authority, principal
}

func l8D6StoredCredentialStateForJob(t *testing.T, job JobV2, principalID string) *storedJobCredentialStateV2 {
	t.Helper()
	seed := l8WorkerBindingSeed(t)
	seed.WorkerID = job.WorkerID
	seed.HostID = job.HostID
	seed.RuntimeDriver = job.RuntimeDriver
	seed.RuntimeID = job.RuntimeID
	seed.WorkerJobID = job.ID
	seed.PlanID = job.CredentialIntent.PlanID
	seed.AdmissionGrantID = job.CredentialIntent.AdmissionGrantID
	seed.AdmissionGrantRevision = job.CredentialIntent.AdmissionGrantRevision
	seed.PrincipalID = principalID
	seed.TemplatePolicyID = job.CredentialIntent.TemplatePolicyID
	seed.WorkspacePolicyID = job.CredentialIntent.WorkspacePolicyID
	seed.BindingIDs = make([]string, len(job.CredentialIntent.Bindings))
	seed.DeliveryModes = make([]sandboxruntime.JobCredentialDeliveryMode, len(job.CredentialIntent.Bindings))
	hasHTTP := false
	for index, binding := range job.CredentialIntent.Bindings {
		seed.BindingIDs[index] = binding.BindingID
		seed.DeliveryModes[index] = sandboxruntime.JobCredentialDeliveryMode(binding.Mode)
		hasHTTP = hasHTTP || seed.DeliveryModes[index] == sandboxruntime.JobCredentialDeliveryModeHTTPProxy
	}
	if !hasHTTP {
		seed.NetworkPlanID, seed.PolicySnapshotID, seed.ProxySessionID = "", "", ""
		seed.ProxyGenerationID, seed.TopologyGenerationID, seed.RuleGenerationID = "", "", ""
	}
	state, err := newStoredJobCredentialStateV2(seed)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

type l8D6OrderRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (recorder *l8D6OrderRecorder) add(step string) {
	if recorder == nil {
		return
	}
	recorder.mu.Lock()
	recorder.steps = append(recorder.steps, step)
	recorder.mu.Unlock()
}

func (recorder *l8D6OrderRecorder) snapshot() []string {
	if recorder == nil {
		return nil
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]string(nil), recorder.steps...)
}

type l8D6WorkerProvider struct {
	mu      sync.Mutex
	seed    sandboxruntime.JobCredentialIdentitySeed
	runtime sandboxruntime.JobCredentialRuntime
	target  sandboxruntime.Target
	calls   int
}

func (provider *l8D6WorkerProvider) BindJobCredentialRuntime(_ context.Context, target sandboxruntime.Target) (sandboxruntime.JobCredentialIdentitySeed, sandboxruntime.JobCredentialRuntime, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls++
	provider.target = target
	return provider.seed, provider.runtime, nil
}

type l8D6WorkerRuntime struct {
	mu             sync.Mutex
	preflight      sandboxruntime.JobCredentialRuntimePreflight
	preflightCalls int
	stateDir       string
	jobID          string
	order          *l8D6OrderRecorder
}

func (runtime *l8D6WorkerRuntime) PreflightJobCredentials(context.Context, sandboxruntime.JobCredentialIdentitySeed) (sandboxruntime.JobCredentialRuntimePreflight, error) {
	runtime.mu.Lock()
	runtime.preflightCalls++
	runtime.mu.Unlock()
	if runtime.stateDir != "" {
		state := l8D6LoadStoredStateForExternalCall(runtime.stateDir, runtime.jobID)
		if state.CredentialState == nil || state.CredentialState.Identity != nil {
			panic("preflight did not observe durable seed-only ownership")
		}
		runtime.order.add("preflight-after-seed")
	}
	return runtime.preflight, nil
}

func (*l8D6WorkerRuntime) RecoverJobCredentials(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
	panic("recovery dependency is not part of this bounded slice")
}

func (runtime *l8D6WorkerRuntime) preflightCallCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.preflightCalls
}

type l8D6WorkerPreflight struct {
	mu                      sync.Mutex
	identity                sandboxruntime.JobCredentialIdentity
	loss                    chan sandboxruntime.JobCredentialLoss
	cleanup                 sandboxruntime.JobCredentialCleanupProof
	stateDir                string
	jobID                   string
	order                   *l8D6OrderRecorder
	cancelRequest           context.CancelFunc
	abortCalls              int
	abortContextIndependent bool
}

func (preflight *l8D6WorkerPreflight) Identity() sandboxruntime.JobCredentialIdentity {
	if preflight.stateDir != "" {
		state := l8D6LoadStoredStateForExternalCall(preflight.stateDir, preflight.jobID)
		if state.CredentialState == nil || state.CredentialState.Identity != nil {
			panic("identity did not observe durable seed-only ownership")
		}
		preflight.order.add("identity-after-seed")
	}
	return preflight.identity
}

func (*l8D6WorkerPreflight) PrepareJobCredentials(context.Context, sandboxruntime.JobCredentialPrepareRequest) (sandboxruntime.JobCredentialSession, error) {
	panic("worker identity slice must not prepare credential sources")
}

func (preflight *l8D6WorkerPreflight) Abort(ctx context.Context) (sandboxruntime.JobCredentialCleanupProof, error) {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	preflight.abortCalls++
	if preflight.cancelRequest != nil {
		preflight.cancelRequest()
	}
	preflight.abortContextIndependent = ctx != nil && ctx.Err() == nil
	if _, deadline := ctx.Deadline(); !deadline {
		preflight.abortContextIndependent = false
	}
	if preflight.stateDir != "" {
		state := l8D6LoadStoredStateForExternalCall(preflight.stateDir, preflight.jobID)
		if state.CredentialState == nil || state.CredentialState.Identity == nil {
			panic("abort did not observe complete durable identity")
		}
		preflight.order.add("abort-after-identity")
	}
	return preflight.cleanup, nil
}

func (preflight *l8D6WorkerPreflight) Loss() <-chan sandboxruntime.JobCredentialLoss {
	return preflight.loss
}

func (preflight *l8D6WorkerPreflight) abortCallCount() int {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return preflight.abortCalls
}

func l8D6LoadStoredStateForExternalCall(stateDir, jobID string) storedJobStateV2 {
	store, err := newJobStoreV2(stateDir)
	if err != nil {
		panic(err)
	}
	state, err := store.load(jobID)
	if err != nil {
		panic(err)
	}
	return state
}
