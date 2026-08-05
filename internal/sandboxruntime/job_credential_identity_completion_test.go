package sandboxruntime

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestJobCredentialIdentityD2ExactFieldOrder(t *testing.T) {
	wantSeed := []string{
		"SandboxID", "ExecutionID", "WorkerID", "HostID",
		"RuntimeDriver", "RuntimeID", "RuntimeGeneration",
		"FirecrackerProcessGeneration", "VsockGeneration",
		"WorkerJobID", "SubmissionID", "PlanID",
		"ActivationGeneration", "CredentialGeneration",
		"NetworkPlanID", "PolicySnapshotID",
		"ProxySessionID", "ProxyGenerationID",
		"TopologyGenerationID", "RuleGenerationID",
		"AdmissionGrantID", "PrincipalID",
		"TemplatePolicyID", "WorkspacePolicyID",
		"ControllerKeyGeneration", "GuestBootGeneration",
		"GuestImageGeneration", "GuestImageDigest",
		"AdmissionGrantRevision", "BindingIDs", "DeliveryModes", "IssuedAt",
	}
	wantIdentity := append([]string(nil), wantSeed[:28]...)
	wantIdentity = append(wantIdentity, "GuestSessionGeneration", "GuestHelperGeneration")
	wantIdentity = append(wantIdentity, wantSeed[28:]...)

	assertFieldOrder(t, reflect.TypeOf(JobCredentialIdentitySeed{}), wantSeed)
	assertFieldOrder(t, reflect.TypeOf(JobCredentialIdentity{}), wantIdentity)

	functions := []struct {
		name string
		got  any
		want any
	}{
		{name: "ValidateJobCredentialIdentitySeed", got: ValidateJobCredentialIdentitySeed, want: (func(JobCredentialIdentitySeed) error)(nil)},
		{name: "CloneJobCredentialIdentitySeed", got: CloneJobCredentialIdentitySeed, want: (func(JobCredentialIdentitySeed) (JobCredentialIdentitySeed, error))(nil)},
		{name: "CompleteJobCredentialIdentity", got: CompleteJobCredentialIdentity, want: (func(JobCredentialIdentitySeed, string, string) (JobCredentialIdentity, error))(nil)},
		{name: "ValidateJobCredentialIdentityCompletion", got: ValidateJobCredentialIdentityCompletion, want: (func(JobCredentialIdentitySeed, JobCredentialIdentity) error)(nil)},
		{name: "ValidateJobCredentialIdentity", got: ValidateJobCredentialIdentity, want: (func(JobCredentialIdentity) error)(nil)},
		{name: "JobCredentialIdentityDigest", got: JobCredentialIdentityDigest, want: (func(JobCredentialIdentity) ([32]byte, error))(nil)},
	}
	for _, function := range functions {
		if reflect.TypeOf(function.got) != reflect.TypeOf(function.want) {
			t.Fatalf("%s type = %s, want %s", function.name, reflect.TypeOf(function.got), reflect.TypeOf(function.want))
		}
	}
}

func TestJobCredentialIdentityD2ValidationAndNetworkTuple(t *testing.T) {
	now := time.Date(2026, time.August, 5, 1, 2, 3, 0, time.UTC)
	mixedSeed := d2JobCredentialIdentitySeed(now)
	httpSeed := mixedSeed
	httpSeed.BindingIDs = []string{"binding-http"}
	httpSeed.DeliveryModes = []JobCredentialDeliveryMode{JobCredentialDeliveryModeHTTPProxy}
	fileSeed := mixedSeed
	fileSeed.BindingIDs = []string{"binding-file"}
	fileSeed.DeliveryModes = []JobCredentialDeliveryMode{JobCredentialDeliveryModeFileTmpfs}
	clearD2NetworkTuple(&fileSeed)
	sshSeed := mixedSeed
	sshSeed.BindingIDs = []string{"binding-ssh"}
	sshSeed.DeliveryModes = []JobCredentialDeliveryMode{JobCredentialDeliveryModeSSHAgent}
	clearD2NetworkTuple(&sshSeed)

	for _, seed := range []JobCredentialIdentitySeed{httpSeed, mixedSeed, fileSeed, sshSeed} {
		if err := ValidateJobCredentialIdentitySeed(seed); err != nil {
			t.Fatalf("valid seed rejected: %v", err)
		}
		identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(1), "helper-generation-1")
		if err != nil {
			t.Fatalf("complete valid identity: %v", err)
		}
		if err := ValidateJobCredentialIdentity(identity); err != nil {
			t.Fatalf("valid identity rejected: %v", err)
		}
	}

	invalid := []struct {
		name string
		seed JobCredentialIdentitySeed
	}{
		{name: "http without tuple", seed: func() JobCredentialIdentitySeed {
			seed := httpSeed
			clearD2NetworkTuple(&seed)
			return seed
		}()},
		{name: "http partial tuple", seed: func() JobCredentialIdentitySeed {
			seed := httpSeed
			seed.ProxySessionID = ""
			return seed
		}()},
		{name: "non-http with tuple", seed: func() JobCredentialIdentitySeed {
			seed := mixedSeed
			seed.DeliveryModes = []JobCredentialDeliveryMode{JobCredentialDeliveryModeFileTmpfs, JobCredentialDeliveryModeSSHAgent}
			return seed
		}()},
		{name: "uppercase image digest", seed: func() JobCredentialIdentitySeed {
			seed := mixedSeed
			seed.GuestImageDigest = "sha256-" + strings.Repeat("A", 64)
			return seed
		}()},
		{name: "colon image digest", seed: func() JobCredentialIdentitySeed {
			seed := mixedSeed
			seed.GuestImageDigest = "sha256:" + strings.Repeat("0", 64)
			return seed
		}()},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateJobCredentialIdentitySeed(tt.seed); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
				t.Fatalf("seed validation error = %v, want identity mismatch", err)
			}
		})
	}

	for _, sessionGeneration := range []string{"", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("+", 43), strings.Repeat("B", 43)} {
		if _, err := CompleteJobCredentialIdentity(mixedSeed, sessionGeneration, "helper-generation-1"); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
			t.Fatalf("guest session generation %q error = %v, want identity mismatch", sessionGeneration, err)
		}
	}
}

func TestJobCredentialIdentityD2CloneCompletionAndDigestOwnEveryField(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 5, 2, 3, 4, 0, time.UTC))
	cloned, err := CloneJobCredentialIdentitySeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	seed.BindingIDs[0] = "caller-mutated"
	seed.DeliveryModes[0] = JobCredentialDeliveryModeSSHAgent
	if cloned.BindingIDs[0] != "binding-http" || cloned.DeliveryModes[0] != JobCredentialDeliveryModeHTTPProxy {
		t.Fatal("seed clone retained caller-owned ordered slices")
	}

	identity, err := CompleteJobCredentialIdentity(cloned, d2GuestSessionGeneration(1), "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	cloned.BindingIDs[0] = "clone-mutated"
	cloned.DeliveryModes[0] = JobCredentialDeliveryModeSSHAgent
	if identity.BindingIDs[0] != "binding-http" || identity.DeliveryModes[0] != JobCredentialDeliveryModeHTTPProxy {
		t.Fatal("completed identity retained seed-owned ordered slices")
	}

	baseSeed := d2JobCredentialIdentitySeed(identity.IssuedAt)
	for fieldIndex := 0; fieldIndex < reflect.TypeOf(baseSeed).NumField(); fieldIndex++ {
		fieldName := reflect.TypeOf(baseSeed).Field(fieldIndex).Name
		t.Run("completion_"+fieldName, func(t *testing.T) {
			mutated := mutateD2IdentitySeedField(t, baseSeed, fieldName)
			if err := ValidateJobCredentialIdentitySeed(mutated); err != nil {
				t.Fatalf("test mutation is invalid: %v", err)
			}
			if err := ValidateJobCredentialIdentityCompletion(mutated, identity); !errors.Is(err, ErrJobCredentialIdentityMismatch) {
				t.Fatalf("completion mismatch error = %v, want identity mismatch", err)
			}
		})
	}

	baseDigest, err := JobCredentialIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	for fieldIndex := 0; fieldIndex < reflect.TypeOf(identity).NumField(); fieldIndex++ {
		fieldName := reflect.TypeOf(identity).Field(fieldIndex).Name
		t.Run("digest_"+fieldName, func(t *testing.T) {
			mutated := mutateD2IdentityField(t, identity, fieldName)
			if err := ValidateJobCredentialIdentity(mutated); err != nil {
				t.Fatalf("test mutation is invalid: %v", err)
			}
			got, err := JobCredentialIdentityDigest(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if got == baseDigest {
				t.Fatal("identity digest omitted field or ordered slice")
			}
		})
	}
	invalid := identity
	invalid.GuestHelperGeneration = ""
	if digest, err := JobCredentialIdentityDigest(invalid); !errors.Is(err, ErrJobCredentialIdentityMismatch) || digest != ([32]byte{}) {
		t.Fatalf("invalid identity digest = %x, %v; want zero and identity mismatch", digest, err)
	}
}

func assertFieldOrder(t *testing.T, typ reflect.Type, want []string) {
	t.Helper()
	if typ.NumField() != len(want) {
		t.Fatalf("%s has %d fields, want %d", typ, typ.NumField(), len(want))
	}
	for index, name := range want {
		if got := typ.Field(index).Name; got != name {
			t.Fatalf("%s field %d = %s, want %s", typ, index, got, name)
		}
	}
}

func d2JobCredentialIdentitySeed(now time.Time) JobCredentialIdentitySeed {
	return JobCredentialIdentitySeed{
		SandboxID: "sandbox-1", ExecutionID: "execution-1", WorkerID: "worker-1", HostID: "host-1",
		RuntimeDriver: "microvm", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		WorkerJobID: "job-1", SubmissionID: "submission-1", PlanID: "plan-1",
		ActivationGeneration: "activation-generation-1", CredentialGeneration: "credential-generation-1",
		NetworkPlanID: "network-plan-1", PolicySnapshotID: "policy-snapshot-1",
		ProxySessionID: "proxy-session-1", ProxyGenerationID: "proxy-generation-1",
		TopologyGenerationID: "topology-generation-1", RuleGenerationID: "rule-generation-1",
		AdmissionGrantID: "grant-1", PrincipalID: "principal-1",
		TemplatePolicyID: "template-policy-1", WorkspacePolicyID: "workspace-policy-1",
		ControllerKeyGeneration: "controller-key-generation-1", GuestBootGeneration: "guest-boot-generation-1",
		GuestImageGeneration: "guest-image-generation-1", GuestImageDigest: "sha256-" + strings.Repeat("0", 64),
		AdmissionGrantRevision: 4,
		BindingIDs:             []string{"binding-http", "binding-file"},
		DeliveryModes:          []JobCredentialDeliveryMode{JobCredentialDeliveryModeHTTPProxy, JobCredentialDeliveryModeFileTmpfs},
		IssuedAt:               now,
	}
}

func d2GuestSessionGeneration(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func clearD2NetworkTuple(seed *JobCredentialIdentitySeed) {
	seed.NetworkPlanID = ""
	seed.PolicySnapshotID = ""
	seed.ProxySessionID = ""
	seed.ProxyGenerationID = ""
	seed.TopologyGenerationID = ""
	seed.RuleGenerationID = ""
}

func mutateD2IdentitySeedField(t *testing.T, seed JobCredentialIdentitySeed, fieldName string) JobCredentialIdentitySeed {
	t.Helper()
	value := reflect.ValueOf(&seed).Elem().FieldByName(fieldName)
	mutateD2Field(t, value, fieldName)
	return seed
}

func mutateD2IdentityField(t *testing.T, identity JobCredentialIdentity, fieldName string) JobCredentialIdentity {
	t.Helper()
	value := reflect.ValueOf(&identity).Elem().FieldByName(fieldName)
	mutateD2Field(t, value, fieldName)
	return identity
}

func mutateD2Field(t *testing.T, value reflect.Value, fieldName string) {
	t.Helper()
	switch fieldName {
	case "GuestImageDigest":
		value.SetString("sha256-" + strings.Repeat("1", 64))
	case "GuestSessionGeneration":
		value.SetString(d2GuestSessionGeneration(2))
	case "BindingIDs":
		value.Set(reflect.ValueOf([]string{"binding-file", "binding-http"}))
	case "DeliveryModes":
		value.Set(reflect.ValueOf([]JobCredentialDeliveryMode{JobCredentialDeliveryModeFileTmpfs, JobCredentialDeliveryModeHTTPProxy}))
	case "IssuedAt":
		value.Set(reflect.ValueOf(value.Interface().(time.Time).Add(time.Second)))
	default:
		switch value.Kind() {
		case reflect.String:
			value.SetString(value.String() + "-neighbor")
		case reflect.Uint64:
			value.SetUint(value.Uint() + 1)
		default:
			t.Fatalf("unsupported D2 field mutation %s (%s)", fieldName, value.Kind())
		}
	}
}
