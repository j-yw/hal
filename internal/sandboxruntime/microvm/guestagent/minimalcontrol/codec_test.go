package minimalcontrol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func testIdentity() session.Identity {
	return session.Identity{
		Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		GuestBootNonce: [32]byte{1}, ControllerKeyGeneration: "controller-key-1",
		RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		BootGeneration: "boot-generation-1", ImageGeneration: "image-generation-1", ImageSHA256: [32]byte{2},
	}
}

func testBindingFields() map[string]string {
	fields := map[string]string{
		"sandboxId": "sandbox-1", "executionId": "execution-1", "workerId": "worker-1", "hostId": "host-1",
		"runtimeDriver": "microvm", "runtimeId": "runtime-1", "runtimeGeneration": "runtime-generation-1",
		"processGeneration": "process-generation-1", "vsockGeneration": "vsock-generation-1", "bootGeneration": "boot-generation-1",
		"imageGeneration": "image-generation-1", "workerJobId": "job-1", "submissionId": "submission-1", "planId": "plan-1",
		"jobGeneration": "job-generation-1", "admissionGrantId": "admission-1", "admissionRevision": "1", "principalId": "principal-1",
		"templatePolicyId": "template-policy-1", "workspacePolicyId": "workspace-policy-1", "networkPlanId": "network-plan-1",
		"policySnapshotId": "policy-snapshot-1", "proxySessionId": "proxy-session-1", "proxyGenerationId": "proxy-generation-1",
		"topologyGenerationId": "topology-generation-1", "ruleGenerationId": "rule-generation-1",
	}
	identity := testIdentity()
	fields["imageDigest"] = "sha256-" + hex.EncodeToString(identity.ImageSHA256[:])
	return fields
}

func testRequest(t *testing.T, binding Binding, id [32]byte) []byte {
	t.Helper()
	digest, err := binding.Digest(id)
	if err != nil {
		t.Fatal(err)
	}
	request := readinessRequest{Operation: "readiness", ProtocolVersion: ProtocolVersion, RequestID: "0102030405060708090a0b0c0d0e0f10"}
	request.Body.Binding = maps.Clone(binding.fields)
	request.Body.BindingDigest = digest
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestBindingRequiresAndPinsAll27Fields(t *testing.T) {
	fields := testBindingFields()
	if len(fields) != 27 {
		t.Fatal("fixture does not cover the complete contract")
	}
	binding, err := NewBinding(testIdentity(), fields)
	if err != nil {
		t.Fatal(err)
	}
	id := [32]byte{3}
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			missing := maps.Clone(fields)
			delete(missing, key)
			if _, err := NewBinding(testIdentity(), missing); !errors.Is(err, ErrInvalid) {
				t.Fatalf("missing field error = %v", err)
			}
			payload := testRequest(t, binding, id)
			var request readinessRequest
			if err := json.Unmarshal(payload, &request); err != nil {
				t.Fatal(err)
			}
			request.Body.Binding[key] += "-other"
			mutated, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := binding.decodeReadiness(mutated, id); !errors.Is(err, ErrInvalid) {
				t.Fatalf("changed field error = %v", err)
			}
		})
	}
}

func TestBindingCanonicalBoundsAndImmutableCopy(t *testing.T) {
	for _, value := range []string{"", "-first", "has:colon", "space here", "nonascii-\u00e9", strings.Repeat("a", 65), strings.Repeat("b", 128)} {
		t.Run(value, func(t *testing.T) {
			fields := testBindingFields()
			fields["workerId"] = value
			if _, err := NewBinding(testIdentity(), fields); !errors.Is(err, ErrInvalid) || fields["workerId"] != value {
				t.Fatalf("invalid input accepted or truncated: error=%v", err)
			}
		})
	}
	fields := testBindingFields()
	fields["workerId"] = strings.Repeat("A", 64)
	binding, err := NewBinding(testIdentity(), fields)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := binding.Digest([32]byte{3})
	fields["workerId"] = "mutated"
	second, _ := binding.Digest([32]byte{3})
	otherSession, _ := binding.Digest([32]byte{4})
	if first != second || first == otherSession {
		t.Fatal("binding copy or cross-session digest isolation failed")
	}
	if _, err := binding.Digest([32]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero session digest error=%v", err)
	}
	if _, err := (Binding{}).Digest([32]byte{3}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero binding digest error=%v", err)
	}
	encoded, err := json.Marshal(binding)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("opaque binding became a durable authority object")
	}
}

func TestBindingRejectsIdentityAndRevisionDrift(t *testing.T) {
	for _, change := range []func(*session.Identity){
		func(id *session.Identity) { id.Channel = session.ChannelSSHRelay },
		func(id *session.Identity) { id.GuestCID++ },
		func(id *session.Identity) { id.GuestPort++ },
		func(id *session.Identity) { id.GuestBootNonce = [32]byte{} },
		func(id *session.Identity) { id.ImageSHA256 = [32]byte{} },
		func(id *session.Identity) { id.ControllerKeyGeneration = "" },
		func(id *session.Identity) { id.JobGeneration = "must-stay-empty" },
		func(id *session.Identity) { id.RuntimeID += "-other" },
		func(id *session.Identity) { id.FirecrackerProcessGeneration += "-other" },
		func(id *session.Identity) { id.VsockGeneration += "-other" },
		func(id *session.Identity) { id.BootGeneration += "-other" },
		func(id *session.Identity) { id.ImageGeneration += "-other" },
	} {
		identity := testIdentity()
		change(&identity)
		if _, err := NewBinding(identity, testBindingFields()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("identity drift accepted: %v", err)
		}
	}
	for _, revision := range []string{"0", "01", "+1", "-1", "1.0", "18446744073709551616"} {
		fields := testBindingFields()
		fields["admissionRevision"] = revision
		if _, err := NewBinding(testIdentity(), fields); !errors.Is(err, ErrInvalid) {
			t.Fatalf("revision %q accepted: %v", revision, err)
		}
	}
}

func TestReadinessCanonicalJSONNegatives(t *testing.T) {
	binding, err := NewBinding(testIdentity(), testBindingFields())
	if err != nil {
		t.Fatal(err)
	}
	id := [32]byte{3}
	payload := testRequest(t, binding, id)
	if _, err := binding.decodeReadiness(payload, id); err != nil {
		t.Fatalf("valid canonical request rejected: %v", err)
	}
	replace := func(old, new string) []byte {
		t.Helper()
		if !bytes.Contains(payload, []byte(old)) {
			t.Fatalf("missing mutation target %q", old)
		}
		return bytes.Replace(payload, []byte(old), []byte(new), 1)
	}
	for name, invalid := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "truncated": payload[:len(payload)-1],
		"trailing":               append(bytes.Clone(payload), []byte("{}")...),
		"two objects":            append(bytes.Clone(payload), payload...),
		"whitespace":             append([]byte(" "), payload...),
		"oversized":              bytes.Repeat([]byte(" "), MaxMessageBytes+1),
		"depth":                  []byte(`{"a":{"b":{"c":{}}}}`),
		"root duplicate":         replace(`"operation":"readiness"`, `"operation":"exec","operation":"readiness"`),
		"root alias":             replace(`"operation"`, `"Operation"`),
		"root unknown":           replace(`"operation"`, `"extra":0,"operation"`),
		"body duplicate":         replace(`"binding":`, `"binding":null,"binding":`),
		"body alias":             replace(`"binding":`, `"Binding":`),
		"body unknown":           replace(`"binding":`, `"extra":0,"binding":`),
		"binding duplicate":      replace(`"workerId":"worker-1"`, `"workerId":"other","workerId":"worker-1"`),
		"binding same duplicate": replace(`"workerId":"worker-1"`, `"workerId":"worker-1","workerId":"worker-1"`),
		"binding alias":          replace(`"workerId"`, `"WorkerId"`),
		"binding escaped alias":  replace(`"workerId"`, `"\u0077orkerId"`),
		"binding unknown":        replace(`"workerId"`, `"extra":"ignored","workerId"`),
		"binding null field":     replace(`"workerId":"worker-1"`, `"workerId":null`),
		"binding wrong type":     replace(`"workerId":"worker-1"`, `"workerId":true`),
		"value escape":           replace(`"worker-1"`, `"\u0077orker-1"`),
		"wrong protocol":         replace(ProtocolVersion, "guest-agent-v2"),
		"wrong operation":        replace(`"operation":"readiness"`, `"operation":"exec"`),
		"short request id":       replace("0102030405060708090a0b0c0d0e0f10", "01"),
		"uppercase request id":   replace("0102030405060708090a0b0c0d0e0f10", "0102030405060708090A0B0C0D0E0F10"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := binding.decodeReadiness(invalid, id); !errors.Is(err, ErrInvalid) {
				t.Fatalf("noncanonical request accepted: %v", err)
			}
		})
	}
}
