package v2control

import (
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestJobIdentityFieldOrderAndJSONTags(t *testing.T) {
	want := []struct {
		name string
		tag  string
	}{
		{"SandboxID", "sandboxId"}, {"ExecutionID", "executionId"},
		{"WorkerID", "workerId"}, {"HostID", "hostId"},
		{"RuntimeDriver", "runtimeDriver"}, {"RuntimeID", "runtimeId"},
		{"RuntimeGeneration", "runtimeGeneration"},
		{"FirecrackerProcessGeneration", "firecrackerProcessGeneration"},
		{"VsockGeneration", "vsockGeneration"}, {"WorkerJobID", "workerJobId"},
		{"SubmissionID", "submissionId"}, {"PlanID", "planId"},
		{"ActivationGeneration", "activationGeneration"},
		{"CredentialGeneration", "credentialGeneration"},
		{"NetworkPlanID", "networkPlanId"}, {"PolicySnapshotID", "policySnapshotId"},
		{"ProxySessionID", "proxySessionId"}, {"ProxyGenerationID", "proxyGenerationId"},
		{"TopologyGenerationID", "topologyGenerationId"}, {"RuleGenerationID", "ruleGenerationId"},
		{"AdmissionGrantID", "admissionGrantId"}, {"PrincipalID", "principalId"},
		{"TemplatePolicyID", "templatePolicyId"}, {"WorkspacePolicyID", "workspacePolicyId"},
		{"ControllerKeyGeneration", "controllerKeyGeneration"},
		{"GuestBootGeneration", "guestBootGeneration"},
		{"GuestImageGeneration", "guestImageGeneration"}, {"GuestImageDigest", "guestImageDigest"},
		{"GuestSessionGeneration", "guestSessionGeneration"},
		{"GuestHelperGeneration", "guestHelperGeneration"},
		{"AdmissionGrantRevision", "admissionGrantRevision"},
		{"IssuedAtUnixNano", "issuedAtUnixNano"}, {"Bindings", "bindings"},
	}
	typ := reflect.TypeOf(JobIdentity{})
	if typ.NumField() != len(want) {
		t.Fatalf("JobIdentity field count = %d, want %d", typ.NumField(), len(want))
	}
	for index, expected := range want {
		field := typ.Field(index)
		if field.Name != expected.name || field.Tag.Get("json") != expected.tag || strings.Contains(string(field.Tag), "omitempty") {
			t.Errorf("field %d = %s %q, want %s %q without omitempty", index, field.Name, field.Tag.Get("json"), expected.name, expected.tag)
		}
	}
	bindingType := reflect.TypeOf(JobBinding{})
	if bindingType.NumField() != 2 || bindingType.Field(0).Name != "BindingID" || bindingType.Field(0).Tag.Get("json") != "bindingId" ||
		bindingType.Field(1).Name != "Mode" || bindingType.Field(1).Tag.Get("json") != "mode" {
		t.Fatalf("JobBinding fields do not match frozen bindingId,mode order: %#v", bindingType)
	}
	if reflect.TypeOf(JobBinding{}.Mode) != reflect.TypeOf(sandboxruntime.JobCredentialDeliveryMode("")) {
		t.Fatal("JobBinding.Mode must use the root delivery-mode authority")
	}
}

func TestJobIdentityCanonicalJSONVector(t *testing.T) {
	identity := validChildIdentity(t)
	got, err := MarshalJobIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"sandboxId":"sandbox-1","executionId":"execution-1","workerId":"worker-1","hostId":"host-1","runtimeDriver":"microvm","runtimeId":"runtime-1","runtimeGeneration":"runtime-generation-1","firecrackerProcessGeneration":"process-generation-1","vsockGeneration":"vsock-generation-1","workerJobId":"worker-job-1","submissionId":"submission-1","planId":"plan-1","activationGeneration":"activation-generation-1","credentialGeneration":"credential-generation-1","networkPlanId":"network-plan-1","policySnapshotId":"policy-snapshot-1","proxySessionId":"proxy-session-1","proxyGenerationId":"proxy-generation-1","topologyGenerationId":"topology-generation-1","ruleGenerationId":"rule-generation-1","admissionGrantId":"grant-1","principalId":"principal-1","templatePolicyId":"template-policy-1","workspacePolicyId":"workspace-policy-1","controllerKeyGeneration":"controller-key-generation-1","guestBootGeneration":"guest-boot-generation-1","guestImageGeneration":"guest-image-generation-1","guestImageDigest":"sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","guestSessionGeneration":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","guestHelperGeneration":"helper-generation-1","admissionGrantRevision":7,"issuedAtUnixNano":1700000000123456789,"bindings":[{"bindingId":"binding-http","mode":"http_proxy"},{"bindingId":"binding-file","mode":"file_tmpfs"}]}`
	if string(got) != want {
		t.Fatalf("canonical JSON:\n got %s\nwant %s", got, want)
	}
	decoded, err := DecodeJobIdentity(got)
	if err != nil {
		t.Fatal(err)
	}
	assertJobIdentityEqual(t, decoded, identity)
}

func TestJobIdentityRootConversionAndDigestConformance(t *testing.T) {
	root := validRootIdentity()
	child, err := JobIdentityFromRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootDigest, err := sandboxruntime.JobCredentialIdentityDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	childDigest, err := JobIdentityDigest(child)
	if err != nil {
		t.Fatal(err)
	}
	if childDigest != rootDigest {
		t.Fatalf("child digest = %x, root digest = %x", childDigest, rootDigest)
	}

	root.BindingIDs[0] = "mutated-root"
	root.DeliveryModes[0] = sandboxruntime.JobCredentialDeliveryModeSSHAgent
	if child.Bindings[0].BindingID != "binding-http" || child.Bindings[0].Mode != sandboxruntime.JobCredentialDeliveryModeHTTPProxy {
		t.Fatal("root conversion retained caller slices")
	}
}

func TestJobIdentityDigestChangesForEveryFieldAndBindingOrder(t *testing.T) {
	identity := validChildIdentity(t)
	baseline, err := JobIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(identity)
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			mutated := cloneJobIdentity(identity)
			value := reflect.ValueOf(&mutated).Elem().Field(index)
			switch field.Name {
			case "GuestSessionGeneration":
				value.SetString(sessionGeneration(filledSessionID(33)))
			case "GuestImageDigest":
				value.SetString("sha256-1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			case "AdmissionGrantRevision":
				value.SetUint(value.Uint() + 1)
			case "IssuedAtUnixNano":
				value.SetInt(value.Int() + 1)
			case "Bindings":
				mutated.Bindings[0].BindingID = "binding-http-mutated"
			default:
				value.SetString(value.String() + "-mutated")
			}
			got, digestErr := JobIdentityDigest(mutated)
			if digestErr != nil {
				t.Fatalf("valid mutation rejected: %v", digestErr)
			}
			if got == baseline {
				t.Fatal("digest did not bind field")
			}
		})
	}

	reordered := cloneJobIdentity(identity)
	reordered.Bindings[0], reordered.Bindings[1] = reordered.Bindings[1], reordered.Bindings[0]
	got, err := JobIdentityDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if got == baseline {
		t.Fatal("digest did not bind binding order")
	}

	modeCorrelation := cloneJobIdentity(identity)
	modeCorrelation.Bindings[0].Mode, modeCorrelation.Bindings[1].Mode = modeCorrelation.Bindings[1].Mode, modeCorrelation.Bindings[0].Mode
	got, err = JobIdentityDigest(modeCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	if got == baseline {
		t.Fatal("digest did not bind mode order to binding IDs")
	}
}

func TestJobIdentityValidationMatchesRootNetworkAndBindingRules(t *testing.T) {
	httpIdentity := validChildIdentity(t)
	fileOnly := cloneJobIdentity(httpIdentity)
	fileOnly.NetworkPlanID, fileOnly.PolicySnapshotID, fileOnly.ProxySessionID = "", "", ""
	fileOnly.ProxyGenerationID, fileOnly.TopologyGenerationID, fileOnly.RuleGenerationID = "", "", ""
	fileOnly.Bindings = []JobBinding{{BindingID: "binding-file", Mode: sandboxruntime.JobCredentialDeliveryModeFileTmpfs}}

	tests := []struct {
		name    string
		mutate  func(*JobIdentity)
		wantErr bool
	}{
		{name: "one HTTP complete tuple"},
		{name: "one HTTP missing tuple field", mutate: func(value *JobIdentity) { value.RuleGenerationID = "" }, wantErr: true},
		{name: "two HTTP", mutate: func(value *JobIdentity) { value.Bindings[1].Mode = sandboxruntime.JobCredentialDeliveryModeHTTPProxy }, wantErr: true},
		{name: "unknown mode", mutate: func(value *JobIdentity) { value.Bindings[0].Mode = sandboxruntime.JobCredentialDeliveryMode("unknown") }, wantErr: true},
		{name: "duplicate binding", mutate: func(value *JobIdentity) { value.Bindings[1].BindingID = value.Bindings[0].BindingID }, wantErr: true},
		{name: "nil bindings", mutate: func(value *JobIdentity) { value.Bindings = nil }, wantErr: true},
		{name: "empty bindings", mutate: func(value *JobIdentity) { value.Bindings = []JobBinding{} }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneJobIdentity(httpIdentity)
			if test.mutate != nil {
				test.mutate(&value)
			}
			err := ValidateJobIdentity(value)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateJobIdentity() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
	if err := ValidateJobIdentity(fileOnly); err != nil {
		t.Fatalf("file-only identity rejected: %v", err)
	}
	partial := cloneJobIdentity(fileOnly)
	partial.NetworkPlanID = "invented-network-plan"
	if err := ValidateJobIdentity(partial); !errors.Is(err, ErrInvalidJobIdentity) {
		t.Fatalf("partial non-HTTP tuple error = %v", err)
	}
	full := cloneJobIdentity(fileOnly)
	full.NetworkPlanID, full.PolicySnapshotID, full.ProxySessionID = "network", "policy", "proxy"
	full.ProxyGenerationID, full.TopologyGenerationID, full.RuleGenerationID = "proxy-gen", "topology", "rule"
	if err := ValidateJobIdentity(full); !errors.Is(err, ErrInvalidJobIdentity) {
		t.Fatalf("full non-HTTP tuple error = %v", err)
	}
}

func TestJobIdentityRejectsEveryMissingRequiredField(t *testing.T) {
	identity := validChildIdentity(t)
	typ := reflect.TypeOf(identity)
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.Name == "IssuedAtUnixNano" {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			mutated := cloneJobIdentity(identity)
			reflect.ValueOf(&mutated).Elem().Field(index).Set(reflect.Zero(field.Type))
			if err := ValidateJobIdentity(mutated); !errors.Is(err, ErrInvalidJobIdentity) {
				t.Fatalf("error = %v, want ErrInvalidJobIdentity", err)
			}
		})
	}
}

func TestDecodeJobIdentityStrictCanonicalJSON(t *testing.T) {
	canonical, err := MarshalJobIdentity(validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	text := string(canonical)
	tests := map[string]string{
		"unknown":           strings.Replace(text, `"executionId"`, `"unknown":"value","executionId"`, 1),
		"duplicate root":    strings.Replace(text, `"executionId"`, `"sandboxId":"sandbox-1","executionId"`, 1),
		"duplicate binding": strings.Replace(text, `"mode":"http_proxy"`, `"bindingId":"binding-http","mode":"http_proxy"`, 1),
		"null scalar":       strings.Replace(text, `"sandboxId":"sandbox-1"`, `"sandboxId":null`, 1),
		"null bindings":     text[:strings.Index(text, `"bindings":`)] + `"bindings":null}`,
		"null binding":      strings.Replace(text, `[{"bindingId"`, `[null,{"bindingId"`, 1),
		"omitted":           strings.Replace(text, `"sandboxId":"sandbox-1",`, "", 1),
		"wrong type":        strings.Replace(text, `"admissionGrantRevision":7`, `"admissionGrantRevision":"7"`, 1),
		"whitespace":        " " + text,
		"trailing bytes":    text + " ",
		"trailing value":    text + `{}`,
		"reordered":         strings.Replace(text, `{"sandboxId":"sandbox-1","executionId":"execution-1"`, `{"executionId":"execution-1","sandboxId":"sandbox-1"`, 1),
		"invalid utf8":      text[:10] + string([]byte{0xff}) + text[10:],
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeJobIdentity([]byte(input)); !errors.Is(err, ErrInvalidJobIdentityJSON) {
				t.Fatalf("error = %v, want ErrInvalidJobIdentityJSON", err)
			}
		})
	}
}

func TestMarshalAndDecodeJobIdentityReturnDefensiveBindings(t *testing.T) {
	identity := validChildIdentity(t)
	wire, err := MarshalJobIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.Bindings[0].BindingID = "caller-mutated"
	decoded, err := DecodeJobIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bindings[0].BindingID != "binding-http" {
		t.Fatal("marshal output retained caller binding slice")
	}
	decoded.Bindings[0].BindingID = "decoded-mutated"
	decodedAgain, err := DecodeJobIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedAgain.Bindings[0].BindingID != "binding-http" {
		t.Fatal("decode returned shared binding slice")
	}
}

func TestGuestCredentialSessionIdentityValidationDigestAndAccessors(t *testing.T) {
	sessionID := sequentialSessionID()
	job := validChildIdentity(t)
	identity, err := NewGuestCredentialSessionIdentity(sessionID, job)
	if err != nil {
		t.Fatal(err)
	}
	job.Bindings[0].BindingID = "caller-mutated"
	if got := identity.JobIdentity(); got.Bindings[0].BindingID != "binding-http" {
		t.Fatal("constructor retained caller binding slice")
	}
	accessed := identity.JobIdentity()
	accessed.Bindings[0].BindingID = "accessor-mutated"
	if got := identity.JobIdentity(); got.Bindings[0].BindingID != "binding-http" {
		t.Fatal("JobIdentity accessor returned shared binding slice")
	}
	if identity.SessionID() != sessionID {
		t.Fatal("SessionID accessor changed value")
	}
	if err := ValidateGuestCredentialSessionIdentity(identity); err != nil {
		t.Fatal(err)
	}

	jobDigest, err := JobIdentityDigest(identity.JobIdentity())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	label := []byte("hal/l8/guest-credential-identity/v1")
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(label)))
	h.Write(length[:])
	h.Write(label)
	h.Write(sessionID[:])
	h.Write(jobDigest[:])
	var want [32]byte
	copy(want[:], h.Sum(nil))
	got, err := GuestCredentialSessionIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("session identity digest = %x, want %x", got, want)
	}
}

func TestGuestCredentialSessionIdentityFromRootAndMismatch(t *testing.T) {
	sessionID := sequentialSessionID()
	root := validRootIdentity()
	identity, err := GuestCredentialSessionIdentityFromRoot(sessionID, root)
	if err != nil {
		t.Fatal(err)
	}
	root.BindingIDs[0] = "caller-mutated"
	if identity.JobIdentity().Bindings[0].BindingID != "binding-http" {
		t.Fatal("root conversion retained caller bindings")
	}

	wrong := filledSessionID(44)
	if _, err := NewGuestCredentialSessionIdentity(wrong, identity.JobIdentity()); !errors.Is(err, ErrSessionIdentityMismatch) {
		t.Fatalf("session mismatch error = %v", err)
	}
	invalidJob := identity.JobIdentity()
	invalidJob.GuestHelperGeneration = "https://secret.invalid/path"
	if _, err := NewGuestCredentialSessionIdentity(sessionID, invalidJob); !errors.Is(err, ErrInvalidJobIdentity) {
		t.Fatalf("invalid job error = %v", err)
	}
}

func TestGuestCredentialSessionIdentityDeniesSerializationAndFormatting(t *testing.T) {
	identity, err := NewGuestCredentialSessionIdentity(sequentialSessionID(), validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	jsonMarshaler, ok := any(identity).(json.Marshaler)
	if !ok {
		t.Fatal("session identity does not explicitly deny JSON")
	}
	if wire, marshalErr := jsonMarshaler.MarshalJSON(); wire != nil || !errors.Is(marshalErr, ErrGuestCredentialSessionIdentitySerialization) {
		t.Fatalf("MarshalJSON() = %q, %v", wire, marshalErr)
	}
	if wire, marshalErr := json.Marshal(identity); wire != nil || !errors.Is(marshalErr, ErrGuestCredentialSessionIdentitySerialization) {
		t.Fatalf("json.Marshal() = %q, %v", wire, marshalErr)
	}
	textMarshaler, ok := any(identity).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("session identity does not explicitly deny text")
	}
	if wire, marshalErr := textMarshaler.MarshalText(); wire != nil || !errors.Is(marshalErr, ErrGuestCredentialSessionIdentitySerialization) {
		t.Fatalf("MarshalText() = %q, %v", wire, marshalErr)
	}
	want := "<v2control.GuestCredentialSessionIdentity>"
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%t"} {
		if got := fmt.Sprintf(format, identity); got != want {
			t.Errorf("Sprintf(%q) = %q, want %q", format, got, want)
		}
	}
	if identity.String() != want || identity.GoString() != want {
		t.Fatal("String or GoString did not return the fixed placeholder")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%t", "%p", "%T"} {
		rendered := fmt.Sprintf(format, identity)
		for _, forbidden := range []string{"sandbox-1", "runtime-1", "binding-http", identity.JobIdentity().GuestSessionGeneration} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("formatting %q leaked %q in %q", format, forbidden, rendered)
			}
		}
	}
}

func TestGuestCredentialSessionIdentityOpaqueShapeAndMethodSet(t *testing.T) {
	typ := reflect.TypeOf(GuestCredentialSessionIdentity{})
	if typ.NumField() != 1 || typ.Field(0).Name != "state" || typ.Field(0).Type != reflect.TypeOf((*guestCredentialSessionIdentityState)(nil)) {
		t.Fatalf("opaque session identity shape changed: %v", typ)
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.IsExported() || field.Tag != "" {
			t.Errorf("field %s must remain private and untagged", field.Name)
		}
	}
	wantMethods := []string{
		"Format", "GoString", "JobIdentity", "MarshalJSON", "MarshalText", "SessionID", "String",
	}
	var gotMethods []string
	for index := 0; index < typ.NumMethod(); index++ {
		gotMethods = append(gotMethods, typ.Method(index).Name)
	}
	if !reflect.DeepEqual(gotMethods, wantMethods) {
		t.Fatalf("session identity methods = %#v, want %#v; no binary/gob/Bytes/Value surface is allowed", gotMethods, wantMethods)
	}
}

func TestIdentityErrorsAreStableAndSanitized(t *testing.T) {
	unsafe := "https://user:secret@example.invalid/private/path"
	root := validRootIdentity()
	root.SandboxID = unsafe
	_, err := JobIdentityFromRoot(root)
	if !errors.Is(err, ErrInvalidJobIdentity) {
		t.Fatalf("error = %v", err)
	}
	for _, denied := range []string{"secret", "example.invalid", "/private/path", unsafe} {
		if strings.Contains(err.Error(), denied) {
			t.Fatalf("error leaked %q: %v", denied, err)
		}
	}
	if ErrInvalidJobIdentity.Error() != "guest credential job identity is invalid" ||
		ErrInvalidJobIdentityJSON.Error() != "guest credential job identity JSON is invalid" ||
		ErrSessionIdentityMismatch.Error() != "guest credential session identity does not match" ||
		ErrGuestCredentialSessionIdentitySerialization.Error() != "guest credential session identity serialization is denied" {
		t.Fatal("identity errors changed")
	}
}

func validChildIdentity(t *testing.T) JobIdentity {
	t.Helper()
	identity, err := JobIdentityFromRoot(validRootIdentity())
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func validRootIdentity() sandboxruntime.JobCredentialIdentity {
	return sandboxruntime.JobCredentialIdentity{
		SandboxID: "sandbox-1", ExecutionID: "execution-1", WorkerID: "worker-1", HostID: "host-1",
		RuntimeDriver: "microvm", RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		WorkerJobID: "worker-job-1", SubmissionID: "submission-1", PlanID: "plan-1",
		ActivationGeneration: "activation-generation-1", CredentialGeneration: "credential-generation-1",
		NetworkPlanID: "network-plan-1", PolicySnapshotID: "policy-snapshot-1", ProxySessionID: "proxy-session-1",
		ProxyGenerationID: "proxy-generation-1", TopologyGenerationID: "topology-generation-1", RuleGenerationID: "rule-generation-1",
		AdmissionGrantID: "grant-1", PrincipalID: "principal-1", TemplatePolicyID: "template-policy-1", WorkspacePolicyID: "workspace-policy-1",
		ControllerKeyGeneration: "controller-key-generation-1", GuestBootGeneration: "guest-boot-generation-1",
		GuestImageGeneration:   "guest-image-generation-1",
		GuestImageDigest:       "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		GuestSessionGeneration: sessionGeneration(sequentialSessionID()), GuestHelperGeneration: "helper-generation-1",
		AdmissionGrantRevision: 7, IssuedAt: time.Unix(0, 1700000000123456789).UTC(),
		BindingIDs: []string{"binding-http", "binding-file"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{
			sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
			sandboxruntime.JobCredentialDeliveryModeFileTmpfs,
		},
	}
}

func sequentialSessionID() [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = byte(index)
	}
	return result
}

func filledSessionID(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func sessionGeneration(sessionID [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(sessionID[:])
}

func assertJobIdentityEqual(t *testing.T, got, want JobIdentity) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("identity mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestSessionIdentityDigestFixedVector(t *testing.T) {
	identity, err := NewGuestCredentialSessionIdentity(sequentialSessionID(), validChildIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GuestCredentialSessionIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	// This value is independently locked once against the frozen root digest and
	// opaque16 session-domain formula.
	want, err := hex.DecodeString("89a41b7f1a60e74c31fd577e28d5b7d6fb32d783e7722a77ae55fda4d6f84f3c")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(digest[:], want) {
		t.Fatalf("digest = %x, want %x", digest, want)
	}
}
