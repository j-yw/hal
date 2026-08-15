package v2control

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const canonicalCredentialPrepareIdentityJSON = `{"sandboxId":"sandbox-1","executionId":"execution-1","workerId":"worker-1","hostId":"host-1","runtimeDriver":"microvm","runtimeId":"runtime-1","runtimeGeneration":"runtime-generation-1","firecrackerProcessGeneration":"process-generation-1","vsockGeneration":"vsock-generation-1","workerJobId":"worker-job-1","submissionId":"submission-1","planId":"plan-1","activationGeneration":"activation-generation-1","credentialGeneration":"credential-generation-1","networkPlanId":"network-plan-1","policySnapshotId":"policy-snapshot-1","proxySessionId":"proxy-session-1","proxyGenerationId":"proxy-generation-1","topologyGenerationId":"topology-generation-1","ruleGenerationId":"rule-generation-1","admissionGrantId":"grant-1","principalId":"principal-1","templatePolicyId":"template-policy-1","workspacePolicyId":"workspace-policy-1","controllerKeyGeneration":"controller-key-generation-1","guestBootGeneration":"guest-boot-generation-1","guestImageGeneration":"guest-image-generation-1","guestImageDigest":"sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","guestSessionGeneration":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","guestHelperGeneration":"helper-generation-1","admissionGrantRevision":7,"issuedAtUnixNano":1700000000123456789,"bindings":[{"bindingId":"binding-http","mode":"http_proxy"},{"bindingId":"binding-file","mode":"file_tmpfs"}]}`

func TestCredentialPrepareRequiresAuthenticatedSessionIdentity(t *testing.T) {
	t.Run("API requires authenticated context", func(t *testing.T) {
		constructor := reflect.TypeOf(NewCredentialPrepareRequest)
		if got := constructor.In(1); got != reflect.TypeOf(GuestCredentialSessionIdentity{}) {
			t.Errorf("constructor identity parameter = %v, want authenticated GuestCredentialSessionIdentity", got)
		}
		decoder := reflect.TypeOf(DecodeCredentialPrepareRequest)
		if decoder.NumIn() != 2 || decoder.In(0) != reflect.TypeOf(GuestCredentialSessionIdentity{}) {
			t.Errorf("decoder inputs = %v, want expected authenticated session identity plus wire", decoder)
		}
	})

	sessionIdentity := testSessionIdentity(t)
	request, err := NewCredentialPrepareRequest(
		testRequestID(t), sessionIdentity, 1, 1700000001123456789,
		[]BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}, 1, 7,
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := GuestCredentialSessionIdentityDigest(sessionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	jobDigest, err := JobIdentityDigest(sessionIdentity.JobIdentity())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("digest binds authenticated session", func(t *testing.T) {
		if request.IdentityDigest().Bytes() != sessionDigest || sessionDigest == jobDigest {
			t.Fatal("prepare envelope digest must be the session-bound identity digest, not the bare job digest")
		}
	})

	otherSession := otherLifecycleSessionIdentity(t)
	firstJob := sessionIdentity.JobIdentity()
	otherJob := otherSession.JobIdentity()
	otherJob.GuestSessionGeneration = firstJob.GuestSessionGeneration
	if !sameCredentialLifecycleIdentity(firstJob, otherJob) {
		t.Fatal("cross-session fixture differs outside its valid session generation")
	}
	otherRequest, err := NewCredentialPrepareRequest(
		testRequestID(t), otherSession, 1, 1700000001123456789,
		[]BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}, 1, 7,
	)
	if err != nil {
		t.Fatal(err)
	}
	otherWire, err := EncodeCredentialPrepareRequest(otherRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("exact expected session and cross-session rejection", func(t *testing.T) {
		if _, err := DecodeCredentialPrepareRequest(otherSession, otherWire); err != nil {
			t.Fatalf("exact expected session decode error = %v", err)
		}
		if _, err := DecodeCredentialPrepareRequest(sessionIdentity, otherWire); !errors.Is(err, ErrInvalidCredentialPrepareRequestJSON) {
			t.Fatalf("cross-session decode error = %v", err)
		}
	})
}

func TestCredentialPrepareCanonicalRequestAndCorrelatedSuccess(t *testing.T) {
	httpBinding, err := NewHTTPBindingManifest("binding-http", "azure-openai-responses-v1")
	if err != nil {
		t.Fatal(err)
	}
	fileBinding, err := NewFileBindingManifest("binding-file", "credentials/config", 7, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	sessionIdentity := testSessionIdentity(t)
	request, err := NewCredentialPrepareRequest(
		testRequestID(t), sessionIdentity, 1, 1700000001123456789,
		[]BindingManifest{httpBinding, fileBinding}, 1, 7,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeCredentialPrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	identityWire, err := MarshalJobIdentity(sessionIdentity.JobIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if string(identityWire) != canonicalCredentialPrepareIdentityJSON {
		t.Fatalf("prepare identity wire:\n got %s\nwant %s", identityWire, canonicalCredentialPrepareIdentityJSON)
	}
	wantRequest := `{"protocolVersion":"guest-agent-v2","operation":"credential_prepare","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","body":{"identity":` + canonicalCredentialPrepareIdentityJSON + `,"revision":1,"expiresAtUnixNano":1700000001123456789,"bindings":[{"bindingId":"binding-http","mode":"http_proxy","serviceId":"azure-openai-responses-v1"},{"bindingId":"binding-file","mode":"file_tmpfs","targetPath":"credentials/config","declaredFileBytes":7,"fileSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"privateRecordCount":1,"privateAggregateBytes":7}}`
	if string(wire) != wantRequest {
		t.Fatalf("request wire:\n got %s\nwant %s", wire, wantRequest)
	}
	sessionDigest, err := GuestCredentialSessionIdentityDigest(sessionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	jobDigest, err := JobIdentityDigest(sessionIdentity.JobIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if request.IdentityDigest().Bytes() != sessionDigest || sessionDigest == jobDigest {
		t.Fatal("canonical prepare request is not bound to the authenticated session")
	}
	decodedRequest, err := DecodeCredentialPrepareRequest(sessionIdentity, wire)
	if err != nil {
		t.Fatal(err)
	}

	proofs := []BindingProof{
		mustBindingProof(t, "binding-http", DeliveryMode("http_proxy"), "proof-http"),
		mustBindingProof(t, "binding-file", DeliveryMode("file_tmpfs"), "proof-file"),
	}
	response, err := NewCredentialPrepareSuccessResponse(decodedRequest, 1, 1700000001123456789, "active-proof", "exec-binding", proofs)
	if err != nil {
		t.Fatal(err)
	}
	responseWire, err := EncodeCredentialPrepareSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	wantResponse := `{"protocolVersion":"guest-agent-v2","operation":"credential_prepare","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"iaQbfxpg50wx_Vd-KNW31vsy14Pncip3rlX9pNb4Tzw","ok":true,"body":{"revision":1,"expiresAtUnixNano":1700000001123456789,"activeProofId":"active-proof","execBindingId":"exec-binding","bindingProofs":[{"bindingId":"binding-http","mode":"http_proxy","proofId":"proof-http"},{"bindingId":"binding-file","mode":"file_tmpfs","proofId":"proof-file"}]}}`
	if string(responseWire) != wantResponse {
		t.Fatalf("response wire:\n got %s\nwant %s", responseWire, wantResponse)
	}
	if _, err := DecodeCredentialPrepareSuccessResponse(decodedRequest, responseWire); err != nil {
		t.Fatal(err)
	}
	otherSession := otherLifecycleSessionIdentity(t)
	otherSessionRequest, err := NewCredentialPrepareRequest(testRequestID(t), otherSession, 1, 1700000001123456789, []BindingManifest{httpBinding, fileBinding}, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialPrepareSuccessResponse(otherSessionRequest, responseWire); !errors.Is(err, ErrCredentialPrepareCorrelationMismatch) {
		t.Fatalf("cross-session response correlation error = %v", err)
	}

	other, err := NewCredentialPrepareRequest(testRequestIDWithByte(0x7f), sessionIdentity, 1, 1700000001123456789, []BindingManifest{httpBinding, fileBinding}, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialPrepareSuccessResponse(other, responseWire); !errors.Is(err, ErrCredentialPrepareCorrelationMismatch) {
		t.Fatalf("correlation error = %v", err)
	}
	otherIdentity := validChildIdentity(t)
	otherIdentity.SandboxID = "sandbox-2"
	other, err = NewCredentialPrepareRequest(testRequestID(t), prepareSessionIdentity(t, otherIdentity), 1, 1700000001123456789, []BindingManifest{httpBinding, fileBinding}, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialPrepareSuccessResponse(other, responseWire); !errors.Is(err, ErrCredentialPrepareCorrelationMismatch) {
		t.Fatalf("identity correlation error = %v", err)
	}
}

func TestCredentialPrepareSSHManifestCanonicalVector(t *testing.T) {
	identity := prepareIdentity(t, []JobBinding{{BindingID: "binding-ssh", Mode: DeliveryMode("ssh_agent")}})
	sessionIdentity := prepareSessionIdentity(t, identity)
	manifest := mustSSHManifest(t, "binding-ssh")
	request, err := NewCredentialPrepareRequest(testRequestID(t), sessionIdentity, 1, 1700000001123456789,
		[]BindingManifest{manifest}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	identityWire, err := MarshalJobIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GuestCredentialSessionIdentityDigest(sessionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"guest-agent-v2","operation":"credential_prepare","requestId":"AQIDBAUGBwgJCgsMDQ4PEA","identityDigest":"` + EncodeIdentityDigest(NewIdentityDigest(digest)) + `","body":{"identity":` + string(identityWire) + `,"revision":1,"expiresAtUnixNano":1700000001123456789,"bindings":[{"bindingId":"binding-ssh","mode":"ssh_agent","sshPolicyId":"ssh-policy-1","sshPolicyRevision":1}],"privateRecordCount":0,"privateAggregateBytes":0}}`
	wire, err := EncodeCredentialPrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(wire) != want {
		t.Fatalf("SSH request wire:\n got %s\nwant %s", wire, want)
	}
	if _, err := DecodeCredentialPrepareRequest(sessionIdentity, wire); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialPrepareManifestModesAndPrivateAccounting(t *testing.T) {
	tests := []struct {
		name      string
		identity  func(*testing.T) JobIdentity
		bindings  func(*testing.T) []BindingManifest
		count     uint32
		aggregate uint64
		execID    string
	}{
		{name: "HTTP only", identity: func(t *testing.T) JobIdentity {
			return prepareIdentity(t, []JobBinding{{BindingID: "http", Mode: DeliveryMode("http_proxy")}})
		}, bindings: func(t *testing.T) []BindingManifest { return []BindingManifest{mustHTTPManifest(t, "http")} }, execID: "exec-1"},
		{name: "file only", identity: func(t *testing.T) JobIdentity {
			return prepareIdentity(t, []JobBinding{{BindingID: "file", Mode: DeliveryMode("file_tmpfs")}})
		}, bindings: func(t *testing.T) []BindingManifest { return []BindingManifest{mustFileManifest(t, "file", 9)} }, count: 1, aggregate: 9, execID: "exec-1"},
		{name: "SSH only", identity: func(t *testing.T) JobIdentity {
			return prepareIdentity(t, []JobBinding{{BindingID: "ssh", Mode: DeliveryMode("ssh_agent")}})
		}, bindings: func(t *testing.T) []BindingManifest { return []BindingManifest{mustSSHManifest(t, "ssh")} }, execID: "exec-1"},
		{name: "mixed", identity: func(t *testing.T) JobIdentity {
			return prepareIdentity(t, []JobBinding{{BindingID: "file", Mode: DeliveryMode("file_tmpfs")}, {BindingID: "http", Mode: DeliveryMode("http_proxy")}, {BindingID: "ssh", Mode: DeliveryMode("ssh_agent")}})
		}, bindings: func(t *testing.T) []BindingManifest {
			return []BindingManifest{mustFileManifest(t, "file", 11), mustHTTPManifest(t, "http"), mustSSHManifest(t, "ssh")}
		}, count: 1, aggregate: 11, execID: "exec-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bindings := tt.bindings(t)
			identity := tt.identity(t)
			request, err := NewCredentialPrepareRequest(testRequestID(t), prepareSessionIdentity(t, identity), 1, 1700000001123456789, bindings, tt.count, tt.aggregate)
			if err != nil {
				t.Fatal(err)
			}
			proofs := make([]BindingProof, len(bindings))
			for index, binding := range bindings {
				proofs[index] = mustBindingProof(t, binding.BindingID(), binding.Mode(), fmt.Sprintf("proof-%d", index))
			}
			response, err := NewCredentialPrepareSuccessResponse(request, 1, request.ExpiresAtUnixNano(), "active", tt.execID, proofs)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := EncodeCredentialPrepareSuccessResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), "privateRecordCount") || strings.Contains(string(wire), "privateAggregateBytes") {
				t.Fatalf("success leaked private fields: %s", wire)
			}
		})
	}
}

func TestCredentialPrepareManifestIdentityAndLimitRejections(t *testing.T) {
	baseIdentity := validChildIdentity(t)
	baseBindings := []BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}
	tests := []struct {
		name      string
		identity  JobIdentity
		bindings  []BindingManifest
		count     uint32
		aggregate uint64
		revision  uint64
		expiry    int64
	}{
		{name: "zero bindings", identity: baseIdentity, bindings: nil, revision: 1, expiry: 1700000001123456789},
		{name: "count mismatch", identity: baseIdentity, bindings: baseBindings, count: 2, aggregate: 7, revision: 1, expiry: 1700000001123456789},
		{name: "aggregate mismatch", identity: baseIdentity, bindings: baseBindings, count: 1, aggregate: 8, revision: 1, expiry: 1700000001123456789},
		{name: "wrong revision", identity: baseIdentity, bindings: baseBindings, count: 1, aggregate: 7, revision: 2, expiry: 1700000001123456789},
		{name: "zero expiry", identity: baseIdentity, bindings: baseBindings, count: 1, aggregate: 7, revision: 1},
		{name: "manifest order", identity: baseIdentity, bindings: []BindingManifest{baseBindings[1], baseBindings[0]}, count: 1, aggregate: 7, revision: 1, expiry: 1700000001123456789},
		{name: "manifest mode", identity: baseIdentity, bindings: []BindingManifest{baseBindings[0], mustSSHManifest(t, "binding-file")}, revision: 1, expiry: 1700000001123456789},
		{name: "duplicate HTTP", identity: baseIdentity, bindings: []BindingManifest{baseBindings[0], mustHTTPManifest(t, "binding-file")}, revision: 1, expiry: 1700000001123456789},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCredentialPrepareRequest(testRequestID(t), prepareSessionIdentity(t, tt.identity), tt.revision, tt.expiry, tt.bindings, tt.count, tt.aggregate); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	maxBindings := make([]BindingManifest, maxCredentialPrepareBindings)
	maxJobBindings := make([]JobBinding, maxCredentialPrepareBindings)
	for index := range maxBindings {
		id := fmt.Sprintf("file-%02d", index)
		maxBindings[index] = mustFileManifest(t, id, maxCredentialPrepareFileBytes)
		maxJobBindings[index] = JobBinding{BindingID: id, Mode: DeliveryMode("file_tmpfs")}
	}
	maxIdentity := prepareIdentity(t, maxJobBindings)
	maxSessionIdentity := prepareSessionIdentity(t, maxIdentity)
	if _, err := NewCredentialPrepareRequest(testRequestID(t), maxSessionIdentity, 1, 1700000001123456789, maxBindings, 16, maxCredentialPrepareAggregateBytes); err != nil {
		t.Fatalf("maximum request: %v", err)
	}
	maximumRequest, err := NewCredentialPrepareRequest(testRequestID(t), maxSessionIdentity, 1, 1700000001123456789, maxBindings, 16, maxCredentialPrepareAggregateBytes)
	if err != nil {
		t.Fatal(err)
	}
	maximumWire, err := EncodeCredentialPrepareRequest(maximumRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCredentialPrepareRequest(maxSessionIdentity, maximumWire); err != nil {
		t.Fatalf("decode maximum request: %v", err)
	}
	plusOneBindings := append(append([]BindingManifest(nil), maxBindings...), mustSSHManifest(t, "ssh-extra"))
	if _, err := NewCredentialPrepareRequest(testRequestID(t), maxSessionIdentity, 1, 1700000001123456789, plusOneBindings, 16, maxCredentialPrepareAggregateBytes); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("17 bindings error = %v", err)
	}
	if _, err := NewCredentialPrepareRequest(testRequestID(t), maxSessionIdentity, 1, 1700000001123456789, maxBindings, 17, maxCredentialPrepareAggregateBytes); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("private count plus one error = %v", err)
	}
	if _, err := NewCredentialPrepareRequest(testRequestID(t), maxSessionIdentity, 1, 1700000001123456789, maxBindings, 16, maxCredentialPrepareAggregateBytes+1); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("private aggregate plus one error = %v", err)
	}
}

func TestCredentialPrepareManifestConstructorBounds(t *testing.T) {
	invalid := []func() error{
		func() error { _, err := NewHTTPBindingManifest("", "service"); return err },
		func() error { _, err := NewHTTPBindingManifest("binding", "https://secret.invalid"); return err },
		func() error {
			_, err := NewFileBindingManifest("binding", "../secret", 1, strings.Repeat("a", 64))
			return err
		},
		func() error {
			_, err := NewFileBindingManifest("binding", "credential", 0, strings.Repeat("a", 64))
			return err
		},
		func() error {
			_, err := NewFileBindingManifest("binding", "credential", maxCredentialPrepareFileBytes+1, strings.Repeat("a", 64))
			return err
		},
		func() error {
			_, err := NewFileBindingManifest("binding", "credential", 1, strings.Repeat("A", 64))
			return err
		},
		func() error {
			_, err := NewFileBindingManifest("binding", "credential", 1, strings.Repeat("0", 64))
			return err
		},
		func() error { _, err := NewSSHBindingManifest("binding", "", 1); return err },
		func() error { _, err := NewSSHBindingManifest("binding", "policy", 0); return err },
		func() error { _, err := NewBindingProof("binding", DeliveryMode("unknown"), "proof"); return err },
		func() error { _, err := NewBindingProof("binding", DeliveryMode("ssh_agent"), ""); return err },
	}
	for index, run := range invalid {
		if err := run(); err == nil {
			t.Errorf("invalid constructor %d succeeded", index)
		}
	}
}

func TestCredentialPrepareExpiryRootAndSessionHandoff(t *testing.T) {
	identity := validChildIdentity(t)
	sessionIdentity := prepareSessionIdentity(t, identity)
	bindings := []BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}
	if _, err := NewCredentialPrepareRequest(testRequestID(t), sessionIdentity, 1, identity.IssuedAtUnixNano, bindings, 1, 7); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("expiry at issue error = %v", err)
	}
	rootMaximum := identity.IssuedAtUnixNano + int64(60*60*1e9)
	request, err := NewCredentialPrepareRequest(testRequestID(t), sessionIdentity, 1, rootMaximum, bindings, 1, 7)
	if err != nil {
		t.Fatalf("root maximum: %v", err)
	}
	if _, err := NewCredentialPrepareRequest(testRequestID(t), sessionIdentity, 1, rootMaximum+1, bindings, 1, 7); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("over root maximum error = %v", err)
	}
	if err := ValidateCredentialPrepareRequestExpiry(request, rootMaximum); err != nil {
		t.Fatalf("exact session hard expiry: %v", err)
	}
	if err := ValidateCredentialPrepareRequestExpiry(request, rootMaximum-1); !errors.Is(err, ErrInvalidCredentialPrepareRequest) {
		t.Fatalf("over session hard expiry error = %v", err)
	}
}

func TestCredentialPrepareSuccessRequiresExactRequestProofs(t *testing.T) {
	request := testCredentialPrepareRequest(t)
	valid := []BindingProof{
		mustBindingProof(t, "binding-http", DeliveryMode("http_proxy"), "proof-http"),
		mustBindingProof(t, "binding-file", DeliveryMode("file_tmpfs"), "proof-file"),
	}
	tests := []struct {
		name   string
		rev    uint64
		expiry int64
		execID string
		proofs []BindingProof
	}{
		{name: "revision", rev: 2, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: valid},
		{name: "expiry", rev: 1, expiry: request.ExpiresAtUnixNano() + 1, execID: "exec", proofs: valid},
		{name: "missing active", rev: 1, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: valid},
		{name: "missing exec", rev: 1, expiry: request.ExpiresAtUnixNano(), proofs: valid},
		{name: "proof count", rev: 1, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: valid[:1]},
		{name: "proof order", rev: 1, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: []BindingProof{valid[1], valid[0]}},
		{name: "proof ID", rev: 1, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: []BindingProof{mustBindingProof(t, "other", DeliveryMode("http_proxy"), "proof-http"), valid[1]}},
		{name: "proof mode", rev: 1, expiry: request.ExpiresAtUnixNano(), execID: "exec", proofs: []BindingProof{mustBindingProof(t, "binding-http", DeliveryMode("file_tmpfs"), "proof-http"), valid[1]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activeID := "active"
			if tt.name == "missing active" {
				activeID = ""
			}
			if _, err := NewCredentialPrepareSuccessResponse(request, tt.rev, tt.expiry, activeID, tt.execID, tt.proofs); !errors.Is(err, ErrInvalidCredentialPrepareSuccess) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCredentialPrepareStrictCanonicalDecodeMatrices(t *testing.T) {
	sessionIdentity := testSessionIdentity(t)
	request := testCredentialPrepareRequestForIdentity(t, sessionIdentity)
	requestWireBytes, err := EncodeCredentialPrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestWire := string(requestWireBytes)
	if _, err := DecodeCredentialPrepareRequest(GuestCredentialSessionIdentity{}, requestWireBytes); !errors.Is(err, ErrInvalidCredentialPrepareRequestJSON) {
		t.Fatalf("missing authenticated session identity error = %v", err)
	}
	requestCases := []string{
		" " + requestWire,
		requestWire + `{}`,
		replacePrepareOnce(t, requestWire, `"protocolVersion":`, `"ProtocolVersion":`),
		replacePrepareOnce(t, requestWire, `"operation":"credential_prepare",`, `"operation":"credential_prepare","operation":"credential_prepare",`),
		replacePrepareOnce(t, requestWire, `"requestId":`, `"unknown":1,"requestId":`),
		replacePrepareOnce(t, requestWire, `"revision":1`, `"revision":1e0`),
		replacePrepareOnce(t, requestWire, `"revision":1`, `"revision":"1"`),
		replacePrepareOnce(t, requestWire, `"body":{`, `"body":null,"ignored":{`),
		replacePrepareOnce(t, requestWire, `,"privateAggregateBytes":7`, ``),
		replacePrepareOnce(t, requestWire, `"serviceId":"azure-openai-responses-v1"`, `"targetPath":"x","declaredFileBytes":1,"fileSha256":"`+strings.Repeat("a", 64)+`"`),
	}
	requestCases = append(requestCases, strings.Repeat(" ", maxCredentialPrepareJSONBytes+1), string([]byte{0xff}))
	for index, input := range requestCases {
		if _, err := DecodeCredentialPrepareRequest(sessionIdentity, []byte(input)); !errors.Is(err, ErrInvalidCredentialPrepareRequestJSON) {
			t.Errorf("request case %d error = %v", index, err)
		}
	}
	tooDeep := []byte(`{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}`)
	tooManyTokens := []byte(`[` + strings.TrimSuffix(strings.Repeat(`0,`, maxCredentialPrepareJSONTokens), ",") + `]`)
	tooLongString := []byte(`"` + strings.Repeat("a", maxCredentialPrepareJSONStringBytes+1) + `"`)
	for _, tt := range []struct {
		name  string
		input []byte
	}{{"depth", tooDeep}, {"tokens", tooManyTokens}, {"string", tooLongString}} {
		if validCredentialPrepareJSONInput(tt.input) {
			t.Errorf("%s bound accepted", tt.name)
		}
	}

	proofs := []BindingProof{mustBindingProof(t, "binding-http", DeliveryMode("http_proxy"), "proof-http"), mustBindingProof(t, "binding-file", DeliveryMode("file_tmpfs"), "proof-file")}
	response, err := NewCredentialPrepareSuccessResponse(request, 1, request.ExpiresAtUnixNano(), "active", "exec", proofs)
	if err != nil {
		t.Fatal(err)
	}
	responseWireBytes, err := EncodeCredentialPrepareSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	responseWire := string(responseWireBytes)
	responseCases := []string{
		"\n" + responseWire,
		responseWire + `false`,
		replacePrepareOnce(t, responseWire, `"ok":true`, `"OK":true`),
		replacePrepareOnce(t, responseWire, `"activeProofId":`, `"privateRecordCount":0,"activeProofId":`),
		replacePrepareOnce(t, responseWire, `"revision":1`, `"revision":1.0`),
		replacePrepareOnce(t, responseWire, `"bindingProofs":[`, `"bindingProofs":null,"ignored":[`),
		replacePrepareOnce(t, responseWire, `,"execBindingId":"exec"`, ``),
	}
	for index, input := range responseCases {
		if _, err := DecodeCredentialPrepareSuccessResponse(request, []byte(input)); !errors.Is(err, ErrInvalidCredentialPrepareSuccessJSON) {
			t.Errorf("response case %d error = %v", index, err)
		}
	}
}

func TestCredentialPrepareDefensiveCopiesAndOpaqueSerialization(t *testing.T) {
	identity := validChildIdentity(t)
	sessionIdentity := prepareSessionIdentity(t, identity)
	bindings := []BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}
	request, err := NewCredentialPrepareRequest(testRequestID(t), sessionIdentity, 1, 1700000001123456789, bindings, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	identity.Bindings[0].BindingID = "changed"
	bindings[0] = BindingManifest{}
	gotIdentity := request.Identity()
	gotBindings := request.Bindings()
	gotIdentity.Bindings[0].BindingID = "changed-again"
	gotBindings[0] = BindingManifest{}
	if request.Identity().Bindings[0].BindingID != "binding-http" || request.Bindings()[0].BindingID() != "binding-http" {
		t.Fatal("constructor or accessor alias escaped")
	}
	proofs := []BindingProof{mustBindingProof(t, "binding-http", DeliveryMode("http_proxy"), "proof-http"), mustBindingProof(t, "binding-file", DeliveryMode("file_tmpfs"), "proof-file")}
	response, err := NewCredentialPrepareSuccessResponse(request, 1, request.ExpiresAtUnixNano(), "active", "exec", proofs)
	if err != nil {
		t.Fatal(err)
	}
	proofs[0] = BindingProof{}
	gotProofs := response.BindingProofs()
	gotProofs[0] = BindingProof{}
	if response.BindingProofs()[0].ProofID() != "proof-http" {
		t.Fatal("proof alias escaped")
	}
	for _, value := range []interface{}{request, response, request.Bindings()[0], response.BindingProofs()[0]} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrCredentialPrepareSerialization) {
			t.Fatalf("marshal %T error = %v", value, err)
		}
		formatted := fmt.Sprintf("%v %#v %s %q %x", value, value, value, value, value)
		if strings.Contains(formatted, "binding-http") || strings.Contains(formatted, "proof-http") || strings.Contains(formatted, "active") {
			t.Fatalf("format %T leaked state: %s", value, formatted)
		}
	}
	seededManifest := request.Bindings()[0]
	if _, err := seededManifest.MarshalBinary(); !errors.Is(err, ErrCredentialPrepareSerialization) {
		t.Fatalf("manifest binary marshal error = %v", err)
	}
	if err := seededManifest.UnmarshalJSON([]byte(`{}`)); !errors.Is(err, ErrCredentialPrepareSerialization) || seededManifest.BindingID() != "binding-http" {
		t.Fatalf("denied manifest unmarshal mutated receiver: %v", err)
	}
	seededProof := response.BindingProofs()[0]
	if _, err := seededProof.MarshalBinary(); !errors.Is(err, ErrCredentialPrepareSerialization) {
		t.Fatalf("proof binary marshal error = %v", err)
	}
	if err := seededProof.UnmarshalText([]byte("private")); !errors.Is(err, ErrCredentialPrepareSerialization) || seededProof.ProofID() != "proof-http" {
		t.Fatalf("denied proof unmarshal mutated receiver: %v", err)
	}
	requestBefore, err := EncodeCredentialPrepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		unmarshal func(*CredentialPrepareRequest) error
	}{
		{"JSON", func(target *CredentialPrepareRequest) error { return target.UnmarshalJSON([]byte(`{}`)) }},
		{"text", func(target *CredentialPrepareRequest) error { return target.UnmarshalText([]byte("private")) }},
		{"binary", func(target *CredentialPrepareRequest) error { return target.UnmarshalBinary([]byte("private")) }},
	} {
		seededRequest := request
		if err := tt.unmarshal(&seededRequest); !errors.Is(err, ErrCredentialPrepareSerialization) {
			t.Fatalf("request %s unmarshal error = %v", tt.name, err)
		}
		requestAfter, err := EncodeCredentialPrepareRequest(seededRequest)
		if err != nil || string(requestAfter) != string(requestBefore) {
			t.Fatalf("denied request %s unmarshal mutated receiver", tt.name)
		}
	}
	responseBefore, err := EncodeCredentialPrepareSuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		unmarshal func(*CredentialPrepareSuccessResponse) error
	}{
		{"JSON", func(target *CredentialPrepareSuccessResponse) error { return target.UnmarshalJSON([]byte(`{}`)) }},
		{"text", func(target *CredentialPrepareSuccessResponse) error { return target.UnmarshalText([]byte("private")) }},
		{"binary", func(target *CredentialPrepareSuccessResponse) error { return target.UnmarshalBinary([]byte("private")) }},
	} {
		seededResponse := response
		if err := tt.unmarshal(&seededResponse); !errors.Is(err, ErrCredentialPrepareSerialization) {
			t.Fatalf("response %s unmarshal error = %v", tt.name, err)
		}
		responseAfter, err := EncodeCredentialPrepareSuccessResponse(seededResponse)
		if err != nil || string(responseAfter) != string(responseBefore) {
			t.Fatalf("denied response %s unmarshal mutated receiver", tt.name)
		}
	}
}

func TestCredentialPrepareErrorsAreStaticAndSanitized(t *testing.T) {
	want := []string{
		"guest agent v2 credential prepare binding manifest is invalid",
		"guest agent v2 credential prepare binding proof is invalid",
		"guest agent v2 credential prepare request is invalid",
		"guest agent v2 credential prepare request JSON is invalid",
		"guest agent v2 credential prepare success response is invalid",
		"guest agent v2 credential prepare success response JSON is invalid",
		"guest agent v2 credential prepare response correlation does not match",
		"guest agent v2 credential prepare serialization is denied",
	}
	got := []error{
		ErrInvalidBindingManifest, ErrInvalidBindingProof, ErrInvalidCredentialPrepareRequest,
		ErrInvalidCredentialPrepareRequestJSON, ErrInvalidCredentialPrepareSuccess,
		ErrInvalidCredentialPrepareSuccessJSON, ErrCredentialPrepareCorrelationMismatch,
		ErrCredentialPrepareSerialization,
	}
	for index := range want {
		if got[index].Error() != want[index] {
			t.Errorf("error %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func mustBindingProof(t *testing.T, bindingID string, mode DeliveryMode, proofID string) BindingProof {
	t.Helper()
	proof, err := NewBindingProof(bindingID, mode, proofID)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func mustHTTPManifest(t *testing.T, bindingID string) BindingManifest {
	t.Helper()
	manifest, err := NewHTTPBindingManifest(bindingID, "azure-openai-responses-v1")
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func mustFileManifest(t *testing.T, bindingID string, size uint32) BindingManifest {
	t.Helper()
	manifest, err := NewFileBindingManifest(bindingID, "credentials/"+bindingID, size, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func mustSSHManifest(t *testing.T, bindingID string) BindingManifest {
	t.Helper()
	manifest, err := NewSSHBindingManifest(bindingID, "ssh-policy-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func prepareIdentity(t *testing.T, bindings []JobBinding) JobIdentity {
	t.Helper()
	identity := validChildIdentity(t)
	identity.Bindings = append([]JobBinding(nil), bindings...)
	hasHTTP := false
	for _, binding := range bindings {
		if binding.Mode == DeliveryMode("http_proxy") {
			hasHTTP = true
		}
	}
	if !hasHTTP {
		identity.NetworkPlanID = ""
		identity.PolicySnapshotID = ""
		identity.ProxySessionID = ""
		identity.ProxyGenerationID = ""
		identity.TopologyGenerationID = ""
		identity.RuleGenerationID = ""
	}
	if ValidateJobIdentity(identity) != nil {
		t.Fatal("test identity is invalid")
	}
	return identity
}

func testCredentialPrepareRequest(t *testing.T) CredentialPrepareRequest {
	t.Helper()
	return testCredentialPrepareRequestForIdentity(t, testSessionIdentity(t))
}

func testCredentialPrepareRequestForIdentity(t *testing.T, identity GuestCredentialSessionIdentity) CredentialPrepareRequest {
	t.Helper()
	request, err := NewCredentialPrepareRequest(testRequestID(t), identity, 1, 1700000001123456789,
		[]BindingManifest{mustHTTPManifest(t, "binding-http"), mustFileManifest(t, "binding-file", 7)}, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func prepareSessionIdentity(t *testing.T, identity JobIdentity) GuestCredentialSessionIdentity {
	t.Helper()
	sessionIdentity, err := NewGuestCredentialSessionIdentity(sequentialSessionID(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return sessionIdentity
}

func replacePrepareOnce(t *testing.T, value, old, replacement string) string {
	t.Helper()
	if strings.Count(value, old) != 1 {
		t.Fatalf("replacement target %q count = %d", old, strings.Count(value, old))
	}
	return strings.Replace(value, old, replacement, 1)
}

func testRequestIDWithByte(value byte) RequestID {
	var raw [16]byte
	for index := range raw {
		raw[index] = value
	}
	requestID, err := NewRequestID(raw)
	if err != nil {
		panic(err)
	}
	return requestID
}
