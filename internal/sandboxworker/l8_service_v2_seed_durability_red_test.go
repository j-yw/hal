package sandboxworker

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8WorkerV2AcceptsAndPersistsExactSeedBeforeAnyPreflightOwnerExists(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir:         stateDir,
		WorkerID:         "worker-primary",
		DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2StartRequest()
	seed := l8WorkerRuntimeCredentialSeed()
	job, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", request, seed)
	if err != nil || existing {
		t.Fatalf("acceptCredentialSeed() = %#v, %v, %v", job, existing, err)
	}
	seed.BindingIDs[0] = "caller-mutated"
	stored, err := manager.store.load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialState == nil || stored.CredentialState.Identity != nil || stored.CredentialState.Revision != 0 || stored.CredentialState.Seed.BindingIDs[0] != "binding-primary" {
		t.Fatalf("seed was not durably and privately accepted before preflight: %#v", stored.CredentialState)
	}
	completionSeed := l8WorkerRuntimeCredentialSeed()
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(completionSeed, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "guest-helper-primary")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.persistCredentialIdentity(job.ID, "principal-primary", identity); err != nil {
		t.Fatalf("persistCredentialIdentity() error: %v", err)
	}
	identity.BindingIDs[0] = "caller-mutated"
	stored, err = manager.store.load(job.ID)
	if err != nil || stored.CredentialState == nil || stored.CredentialState.Identity == nil || stored.CredentialState.Identity.BindingIDs[0] != "binding-primary" {
		t.Fatalf("completed identity was not durably and privately persisted: %#v, %v", stored.CredentialState, err)
	}

	replaySeed := l8WorkerRuntimeCredentialSeed()
	replayed, existing, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", request, replaySeed)
	if err != nil || !existing || replayed.ID != job.ID {
		t.Fatalf("exact replay = %#v, %v, %v, want existing %s", replayed, existing, err, job.ID)
	}
	conflict := request
	conflict.Exec.Args = []string{"pi", "--neighbor"}
	if _, _, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", conflict, replaySeed); !errors.Is(err, errJobV2SubmissionConflict) {
		t.Fatalf("conflicting submission error = %v, want %v", err, errJobV2SubmissionConflict)
	}
}

func TestL8WorkerV2CredentialIntentAndDurableSeedRejectBindingCountAboveSixteen(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = make([]string, 17)
	request.Bindings = make([]JobCredentialBindingV2, 17)
	seed := l8WorkerRuntimeCredentialSeed()
	seed.BindingIDs = make([]string, 17)
	seed.DeliveryModes = make([]sandboxruntime.JobCredentialDeliveryMode, 17)
	for index := 0; index < 17; index++ {
		id := "binding-" + string(rune('a'+index))
		source := "source-" + string(rune('a'+index))
		request.SourceReferenceIDs[index] = source
		request.Bindings[index] = JobCredentialBindingV2{BindingID: id, SourceReferenceID: source, Mode: CredentialModeFileTmpfs}
		seed.BindingIDs[index] = id
		seed.DeliveryModes[index] = sandboxruntime.JobCredentialDeliveryModeFileTmpfs
	}
	seed.NetworkPlanID = ""
	seed.PolicySnapshotID = ""
	seed.ProxySessionID = ""
	seed.ProxyGenerationID = ""
	seed.TopologyGenerationID = ""
	seed.RuleGenerationID = ""
	if err := request.Validate(); err == nil {
		t.Fatal("worker v2 request accepted seventeen credential bindings")
	}
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err == nil {
		t.Fatal("durable seed accepted seventeen credential bindings")
	}
}

func TestL8WorkerV2RestartFailsClosedWithoutSeedRecoveryAuthority(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	manager, err := newJobManagerV2(jobManagerV2Options{StateDir: stateDir, WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration})
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2StartRequest()
	job, _, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", request, l8WorkerRuntimeCredentialSeed())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newJobManagerV2(jobManagerV2Options{StateDir: stateDir, WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration}); err == nil {
		t.Fatal("worker v2 restart accepted a durable credential owner without recovery authority")
	}
	stored, err := manager.store.load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.JobV2.State != JobStateQueued || stored.JobV2.FinishedAt != nil || stored.CredentialState == nil {
		t.Fatalf("failed-closed restart falsely terminalized or discarded credential ownership: %#v", stored)
	}
}

func TestL8WorkerV2DurableStateHasOneProcessOwner(t *testing.T) {
	stateDir := t.TempDir() + "/jobs-v2"
	first, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatalf("first newJobManagerV2() error: %v", err)
	}
	if _, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration,
	}); err == nil {
		t.Fatal("second newJobManagerV2() succeeded while first process owner was live")
	}
	first.close()
	first.close()
	second, err := newJobManagerV2(jobManagerV2Options{
		StateDir: stateDir, WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatalf("newJobManagerV2() after release error: %v", err)
	}
	second.close()
	if _, err := first.status("job-missing", "principal-primary"); err == nil {
		t.Fatal("released worker v2 process owner remained usable after a successor acquired the store")
	}
	if _, _, err := first.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", l8WorkerV2StartRequest(), l8WorkerRuntimeCredentialSeed()); err == nil {
		t.Fatal("released worker v2 process owner mutated the store after a successor acquired it")
	}
}

func TestL8WorkerV2ClosedManagerRejectsEveryStateAccess(t *testing.T) {
	manager, err := newJobManagerV2(jobManagerV2Options{
		StateDir: t.TempDir() + "/jobs-v2", WorkerID: "worker-primary", DaemonGeneration: l8WorkerV2DaemonGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8WorkerV2StartRequest()
	seed := l8WorkerRuntimeCredentialSeed()
	job, _, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", request, seed)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "guest-helper-primary")
	if err != nil {
		t.Fatal(err)
	}
	manager.close()
	if _, err := manager.status(job.ID, "principal-primary"); err == nil {
		t.Fatal("closed worker v2 manager returned durable state")
	}
	if err := manager.persistCredentialIdentity(job.ID, "principal-primary", identity); err == nil {
		t.Fatal("closed worker v2 manager persisted a completed identity")
	}
	if _, _, err := manager.acceptCredentialSeed(RuntimeDriverMicroVM, "principal-primary", request, seed); err == nil {
		t.Fatal("closed worker v2 manager accepted a credential seed")
	}
}

func TestL8WorkerV2PrivateStateDurablyOwnsSeedBeforePreflightAndIdentityBeforeSources(t *testing.T) {
	seed := l8WorkerRuntimeCredentialSeed()
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "guest-helper-primary")
	if err != nil {
		t.Fatalf("CompleteJobCredentialIdentity() error: %v", err)
	}
	request := l8WorkerV2StartRequest()
	principalID := "principal-primary"
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, request)
	if err != nil {
		t.Fatal(err)
	}
	job := l8WorkerV2QueuedJob()
	job.SubmissionKey = jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, request)
	credentialState, err := newStoredJobCredentialStateV2(seed)
	if err != nil {
		t.Fatal(err)
	}
	credentialState, err = credentialState.withIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	state := storedJobStateV2{
		JobV2:            job,
		RequestKey:       requestKey,
		PrincipalID:      principalID,
		DaemonGeneration: l8WorkerV2DaemonGeneration,
		CredentialState:  credentialState,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("credential-bearing private state Validate() error: %v", err)
	}

	store, err := newJobStoreV2(t.TempDir() + "/jobs-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.save(state); err != nil {
		t.Fatalf("save credential-bearing private state: %v", err)
	}
	seed.BindingIDs[0] = "caller-mutated"
	identity.BindingIDs[0] = "caller-mutated"
	loaded, err := store.load(job.ID)
	if err != nil {
		t.Fatalf("load credential-bearing private state: %v", err)
	}
	if loaded.CredentialState == nil || loaded.CredentialState.Identity == nil {
		t.Fatalf("loaded state omitted durable credential authority: %#v", loaded)
	}
	loadedSeed, err := loaded.CredentialState.Seed.runtimeSeed()
	if err != nil {
		t.Fatal(err)
	}
	loadedIdentity, err := loaded.CredentialState.Identity.runtimeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialIdentityCompletion(loadedSeed, loadedIdentity); err != nil {
		t.Fatalf("loaded identity is not exact durable seed completion: %v", err)
	}
	if loaded.CredentialState.Seed.BindingIDs[0] != "binding-primary" || loaded.CredentialState.Identity.BindingIDs[0] != "binding-primary" {
		t.Fatal("private state retained caller-owned seed or identity slices")
	}

	invalid := state
	invalid.CredentialState = cloneStoredJobCredentialStateV2(state.CredentialState)
	invalid.CredentialState.Seed = storedJobCredentialIdentitySeedV1{}
	if err := invalid.Validate(); err == nil {
		t.Fatal("private state accepted a completed identity without its exact durable seed")
	}
	invalid = state
	invalid.CredentialState = cloneStoredJobCredentialStateV2(state.CredentialState)
	neighbor := *invalid.CredentialState.Identity
	neighbor.GuestImageGeneration = "guest-image-neighbor"
	invalid.CredentialState.Identity = &neighbor
	if err := invalid.Validate(); err == nil {
		t.Fatal("private state accepted an identity that does not complete its durable seed")
	}

	wantTail := []string{`CredentialState|*sandboxworker.storedJobCredentialStateV2|json:"credentialState,omitempty"`}
	typeOf := reflect.TypeOf(storedJobStateV2{})
	if typeOf.NumField() < len(wantTail) {
		t.Fatalf("stored state has %d fields, want credential authority tail", typeOf.NumField())
	}
	for index, want := range wantTail {
		field := typeOf.Field(typeOf.NumField() - len(wantTail) + index)
		got := field.Name + "|" + field.Type.String() + "|" + string(field.Tag)
		if got != want {
			t.Fatalf("stored credential field %d = %q, want %q", index, got, want)
		}
	}
	l8AssertStoredJobCredentialSchemasExact(t)
}

func l8AssertStoredJobCredentialSchemasExact(t *testing.T) {
	t.Helper()
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
	identityFields = append(identityFields, `GuestSessionGeneration|string|json:"guestSessionGeneration"`, `GuestHelperGeneration|string|json:"guestHelperGeneration"`)
	identityFields = append(identityFields, seedFields[28:]...)
	l8AssertStoredJobCredentialStructFields(t, reflect.TypeOf(storedJobCredentialIdentitySeedV1{}), seedFields)
	l8AssertStoredJobCredentialStructFields(t, reflect.TypeOf(storedJobCredentialIdentityV1{}), identityFields)
	l8AssertStoredJobCredentialStructFields(t, reflect.TypeOf(storedJobCredentialStateV2{}), []string{
		`ContractVersion|string|json:"contractVersion"`, `Seed|sandboxworker.storedJobCredentialIdentitySeedV1|json:"seed"`,
		`Identity|*sandboxworker.storedJobCredentialIdentityV1|json:"identity,omitempty"`, `Revision|uint64|json:"revision"`,
	})
	for _, typ := range []reflect.Type{reflect.TypeOf(sandboxruntime.JobCredentialIdentitySeed{}), reflect.TypeOf(sandboxruntime.JobCredentialIdentity{})} {
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).Tag.Get("json") != "" {
				t.Fatalf("root %s gained direct durable JSON field %s", typ.Name(), typ.Field(index).Name)
			}
		}
	}
}

func l8AssertStoredJobCredentialStructFields(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	if typ.NumField() != len(want) {
		t.Fatalf("%s field count = %d, want %d", typ.Name(), typ.NumField(), len(want))
	}
	for index, expected := range want {
		field := typ.Field(index)
		got := field.Name + "|" + field.Type.String() + "|" + string(field.Tag)
		if got != expected {
			t.Fatalf("%s field %d = %q, want %q", typ.Name(), index, got, expected)
		}
	}
}

func l8WorkerRuntimeCredentialSeed() sandboxruntime.JobCredentialIdentitySeed {
	return sandboxruntime.JobCredentialIdentitySeed{
		SandboxID:                    "sandbox-primary",
		ExecutionID:                  "exec-primary",
		WorkerID:                     "worker-primary",
		HostID:                       "host-primary",
		RuntimeDriver:                sandboxruntime.DriverMicroVM,
		RuntimeID:                    "runtime-primary",
		RuntimeGeneration:            "runtime-generation-primary",
		FirecrackerProcessGeneration: "firecracker-process-primary",
		VsockGeneration:              "vsock-primary",
		WorkerJobID:                  "job-primary",
		SubmissionID:                 "submission-primary",
		PlanID:                       "plan-primary",
		ActivationGeneration:         "activation-primary",
		CredentialGeneration:         "credential-primary",
		NetworkPlanID:                "network-plan-primary",
		PolicySnapshotID:             "policy-primary",
		ProxySessionID:               "proxy-session-primary",
		ProxyGenerationID:            "proxy-generation-primary",
		TopologyGenerationID:         "topology-primary",
		RuleGenerationID:             "rule-primary",
		AdmissionGrantID:             "grant-primary",
		PrincipalID:                  "principal-primary",
		TemplatePolicyID:             "template-primary",
		WorkspacePolicyID:            "workspace-primary",
		ControllerKeyGeneration:      "controller-key-primary",
		GuestBootGeneration:          "guest-boot-primary",
		GuestImageGeneration:         "guest-image-primary",
		GuestImageDigest:             "sha256-" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AdmissionGrantRevision:       9,
		BindingIDs:                   []string{"binding-primary"},
		DeliveryModes:                []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy},
		IssuedAt:                     time.Date(2026, time.August, 20, 1, 2, 3, 0, time.UTC),
	}
}

func l8StoredJobCredentialStateForTest(t *testing.T, job JobV2, principalID string) *storedJobCredentialStateV2 {
	t.Helper()
	seed := l8WorkerRuntimeCredentialSeed()
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
		seed.NetworkPlanID = ""
		seed.PolicySnapshotID = ""
		seed.ProxySessionID = ""
		seed.ProxyGenerationID = ""
		seed.TopologyGenerationID = ""
		seed.RuleGenerationID = ""
	}
	state, err := newStoredJobCredentialStateV2(seed)
	if err != nil {
		t.Fatalf("newStoredJobCredentialStateV2() error: %v", err)
	}
	return state
}
