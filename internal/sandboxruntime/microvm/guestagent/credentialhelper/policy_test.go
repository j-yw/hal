package credentialhelper

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestHelperPolicyContractShapeAndCatalogsAreExact(t *testing.T) {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	policyType := reflect.TypeOf((*Policy)(nil)).Elem()
	if policyType.NumMethod() != 2 {
		t.Fatalf("Policy method count = %d, want 2", policyType.NumMethod())
	}
	authorize, ok := policyType.MethodByName("Authorize")
	if !ok {
		t.Fatal("Policy is missing Authorize")
	}
	assertMethodSignature(t, authorize.Type, methodSignature{
		in:  []reflect.Type{reflect.TypeOf(PolicyRequest{})},
		out: []reflect.Type{reflect.TypeOf(PolicyDecision{}), errorType},
	})
	descriptor, ok := policyType.MethodByName("Descriptor")
	if !ok {
		t.Fatal("Policy is missing Descriptor")
	}
	assertMethodSignature(t, descriptor.Type, methodSignature{out: []reflect.Type{reflect.TypeOf(PolicyDescriptor{})}})

	fields := []struct {
		value any
		names []string
	}{
		{PolicyRequest{}, []string{"liveValue", "operation", "correlation", "generations", "expiresUnixNano", "fixedLimitSetID", "manifest", "manifestSHA256", "execBodyBytes", "execBodySHA256", "privateBytes", "privateSHA256"}},
		{PolicyDecision{}, []string{"liveValue", "allow", "rejectionCode"}},
		{PolicyDescriptor{}, []string{"liveValue", "id", "digest"}},
	}
	for _, contract := range fields {
		typeOf := reflect.TypeOf(contract.value)
		if typeOf.NumField() != len(contract.names) {
			t.Fatalf("%s field count = %d, want %d", typeOf.Name(), typeOf.NumField(), len(contract.names))
		}
		for index, name := range contract.names {
			field := typeOf.Field(index)
			if field.Name != name {
				t.Errorf("%s field %d = %s, want %s", typeOf.Name(), index, field.Name, name)
			}
			if field.IsExported() || field.Tag != "" {
				t.Errorf("%s.%s must be private and untagged", typeOf.Name(), field.Name)
			}
			if field.Type.Kind() == reflect.Map || field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Slice {
				t.Errorf("%s.%s has forbidden kind %s", typeOf.Name(), field.Name, field.Type.Kind())
			}
		}
	}

	if PolicyOperationPrepare != 1 || PolicyOperationExec != 2 || PolicyOperationRenew != 3 || PolicyOperationRevoke != 4 || PolicyOperationInspect != 5 {
		t.Fatal("policy operation catalog changed")
	}
	if PolicyRejectionMalformed != 1 || PolicyRejectionIdentityMismatch != 2 || PolicyRejectionRevisionStale != 3 || PolicyRejectionExpired != 4 || PolicyRejectionResourceLimit != 5 || PolicyRejectionManifestMismatch != 6 || PolicyRejectionGenerationMismatch != 7 || PolicyRejectionOperationDenied != 8 {
		t.Fatal("policy rejection catalog changed")
	}

	valueMethods := []struct {
		typeOf reflect.Type
		names  []string
	}{
		{typeOf: reflect.TypeOf(PolicyRequest{}), names: []string{
			"ExecBodyBytes", "ExecBodySHA256", "ExpiresUnixNano", "FixedLimitSetID", "Format", "Generations", "GoString", "IdentityDigest", "Manifest", "ManifestSHA256", "MarshalBinary", "MarshalJSON", "MarshalText", "Operation", "PrivateBytes", "PrivateSHA256", "RequestID", "Revision", "String",
		}},
		{typeOf: reflect.TypeOf(PolicyDecision{}), names: []string{
			"Allowed", "Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "RejectionCode", "String",
		}},
		{typeOf: reflect.TypeOf(PolicyDescriptor{}), names: []string{
			"Format", "GoString", "ID", "MarshalBinary", "MarshalJSON", "MarshalText", "SHA256", "String",
		}},
	}
	for _, methods := range valueMethods {
		typeOf, names := methods.typeOf, methods.names
		if typeOf.NumMethod() != len(names) {
			t.Fatalf("%s value method count = %d, want %d", typeOf.Name(), typeOf.NumMethod(), len(names))
		}
		for _, name := range names {
			if _, ok := typeOf.MethodByName(name); !ok {
				t.Errorf("%s is missing value method %s", typeOf.Name(), name)
			}
		}
		pointer := reflect.PointerTo(typeOf)
		if pointer.NumMethod() != len(names)+3 {
			t.Fatalf("*%s method count = %d, want %d", typeOf.Name(), pointer.NumMethod(), len(names)+3)
		}
		for _, name := range []string{"UnmarshalBinary", "UnmarshalJSON", "UnmarshalText"} {
			if _, ok := pointer.MethodByName(name); !ok {
				t.Errorf("*%s is missing pointer method %s", typeOf.Name(), name)
			}
		}
	}
}

func TestNewPolicyRequestAcceptsExactOperationMatrixAndCopiesValues(t *testing.T) {
	partial, complete, manifest := policyFixtures(t)
	manifestDigest := manifest.SHA256()
	execDigest := sha256.Sum256([]byte("canonical-exec"))
	privateDigest := sha256.Sum256([]byte("private-binding"))

	tests := []struct {
		name           string
		operation      PolicyOperation
		requestID      [16]byte
		generations    CoreGenerations
		expiry         int64
		manifest       ManifestCapability
		manifestDigest [32]byte
		execBytes      uint32
		execDigest     [32]byte
		privateBytes   uint32
		privateDigest  [32]byte
	}{
		{name: "prepare", operation: PolicyOperationPrepare, requestID: [16]byte{1}, generations: partial, expiry: 1, manifest: manifest, manifestDigest: manifestDigest},
		{name: "exec without private", operation: PolicyOperationExec, requestID: [16]byte{2}, generations: complete, manifest: manifest, manifestDigest: manifestDigest, execBytes: 1, execDigest: execDigest},
		{name: "exec exact maxima", operation: PolicyOperationExec, requestID: [16]byte{3}, generations: complete, manifest: manifest, manifestDigest: manifestDigest, execBytes: credentialprotocol.MaxHelperPacketBodyBytes, execDigest: execDigest, privateBytes: credentialprotocol.MaxHelperExecPrivateBytes, privateDigest: privateDigest},
		{name: "renew", operation: PolicyOperationRenew, requestID: [16]byte{4}, generations: complete, expiry: 1},
		{name: "revoke", operation: PolicyOperationRevoke, requestID: [16]byte{5}, generations: complete},
		{name: "inspect", operation: PolicyOperationInspect, generations: complete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewPolicyRequest(test.operation, test.requestID, [32]byte{9}, 7, test.generations, test.expiry, "helper-limits-v1", test.manifest, test.manifestDigest, test.execBytes, test.execDigest, test.privateBytes, test.privateDigest)
			if err != nil {
				t.Fatalf("NewPolicyRequest() error = %v", err)
			}
			if request.Operation() != test.operation || request.RequestID() != test.requestID || request.IdentityDigest() != ([32]byte{9}) || request.Revision() != 7 || request.Generations() != test.generations || request.ExpiresUnixNano() != test.expiry || request.FixedLimitSetID() != "helper-limits-v1" || request.ManifestSHA256() != test.manifestDigest || request.ExecBodyBytes() != test.execBytes || request.ExecBodySHA256() != test.execDigest || request.PrivateBytes() != test.privateBytes || request.PrivateSHA256() != test.privateDigest {
				t.Fatal("policy request accessors did not preserve the exact values")
			}
			if request.Manifest().Count() != test.manifest.Count() || request.Manifest().SHA256() != test.manifest.SHA256() {
				t.Fatal("Manifest() did not return the snapshotted value")
			}
		})
	}
}

func TestNewPolicyRequestRejectsEveryNoncanonicalShapeAndLimitBoundary(t *testing.T) {
	partial, complete, manifest := policyFixtures(t)
	manifestDigest := manifest.SHA256()
	execDigest := sha256.Sum256([]byte("canonical-exec"))
	privateDigest := sha256.Sum256([]byte("private-binding"))

	validPrepare := policyRequestArguments{operation: PolicyOperationPrepare, requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1, generations: partial, expiry: 1, fixedLimitSetID: "helper-limits-v1", manifest: manifest, manifestDigest: manifestDigest}
	validExec := policyRequestArguments{operation: PolicyOperationExec, requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1, generations: complete, fixedLimitSetID: "helper-limits-v1", manifest: manifest, manifestDigest: manifestDigest, execBytes: 1, execDigest: execDigest}
	validRenew := policyRequestArguments{operation: PolicyOperationRenew, requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1, generations: complete, expiry: 1, fixedLimitSetID: "helper-limits-v1"}
	validRevoke := policyRequestArguments{operation: PolicyOperationRevoke, requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1, generations: complete, fixedLimitSetID: "helper-limits-v1"}
	validInspect := policyRequestArguments{operation: PolicyOperationInspect, identityDigest: [32]byte{2}, revision: 1, generations: complete, fixedLimitSetID: "helper-limits-v1"}

	tests := []struct {
		name string
		base policyRequestArguments
		edit func(*policyRequestArguments)
	}{
		{name: "unknown operation", base: validPrepare, edit: func(v *policyRequestArguments) { v.operation = 0 }},
		{name: "packet request ID absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.requestID = [16]byte{} }},
		{name: "inspect request ID present", base: validInspect, edit: func(v *policyRequestArguments) { v.requestID = [16]byte{1} }},
		{name: "identity absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.identityDigest = [32]byte{} }},
		{name: "revision absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.revision = 0 }},
		{name: "unsafe fixed limit ID", base: validPrepare, edit: func(v *policyRequestArguments) { v.fixedLimitSetID = "helper/limits" }},
		{name: "wrong fixed limit ID", base: validPrepare, edit: func(v *policyRequestArguments) { v.fixedLimitSetID = "helper-limits-v2" }},
		{name: "unsafe boot generation", base: validPrepare, edit: func(v *policyRequestArguments) { v.generations.boot = "boot/unsafe" }},
		{name: "prepare complete generations", base: validPrepare, edit: func(v *policyRequestArguments) { v.generations = complete }},
		{name: "exec partial generations", base: validExec, edit: func(v *policyRequestArguments) { v.generations = partial }},
		{name: "prepare expiry absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.expiry = 0 }},
		{name: "exec expiry present", base: validExec, edit: func(v *policyRequestArguments) { v.expiry = 1 }},
		{name: "renew expiry absent", base: validRenew, edit: func(v *policyRequestArguments) { v.expiry = 0 }},
		{name: "revoke expiry present", base: validRevoke, edit: func(v *policyRequestArguments) { v.expiry = 1 }},
		{name: "prepare manifest absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.manifest = ManifestCapability{}; v.manifestDigest = [32]byte{} }},
		{name: "prepare manifest digest absent", base: validPrepare, edit: func(v *policyRequestArguments) { v.manifestDigest = [32]byte{} }},
		{name: "prepare manifest digest wrong", base: validPrepare, edit: func(v *policyRequestArguments) { v.manifestDigest = [32]byte{7} }},
		{name: "prepare exec bytes present", base: validPrepare, edit: func(v *policyRequestArguments) { v.execBytes = 1; v.execDigest = execDigest }},
		{name: "prepare private bytes present", base: validPrepare, edit: func(v *policyRequestArguments) { v.privateBytes = 1; v.privateDigest = privateDigest }},
		{name: "exec manifest absent", base: validExec, edit: func(v *policyRequestArguments) { v.manifest = ManifestCapability{}; v.manifestDigest = [32]byte{} }},
		{name: "exec bytes absent", base: validExec, edit: func(v *policyRequestArguments) { v.execBytes = 0; v.execDigest = [32]byte{} }},
		{name: "exec bytes plus one", base: validExec, edit: func(v *policyRequestArguments) { v.execBytes = credentialprotocol.MaxHelperPacketBodyBytes + 1 }},
		{name: "exec digest absent", base: validExec, edit: func(v *policyRequestArguments) { v.execDigest = [32]byte{} }},
		{name: "private zero with digest", base: validExec, edit: func(v *policyRequestArguments) { v.privateDigest = privateDigest }},
		{name: "private positive without digest", base: validExec, edit: func(v *policyRequestArguments) { v.privateBytes = 1 }},
		{name: "private plus one", base: validExec, edit: func(v *policyRequestArguments) {
			v.privateBytes = credentialprotocol.MaxHelperExecPrivateBytes + 1
			v.privateDigest = privateDigest
		}},
		{name: "renew manifest present", base: validRenew, edit: func(v *policyRequestArguments) { v.manifest = manifest; v.manifestDigest = manifestDigest }},
		{name: "renew body present", base: validRenew, edit: func(v *policyRequestArguments) { v.execBytes = 1; v.execDigest = execDigest }},
		{name: "revoke manifest digest present", base: validRevoke, edit: func(v *policyRequestArguments) { v.manifestDigest = manifestDigest }},
		{name: "inspect private present", base: validInspect, edit: func(v *policyRequestArguments) { v.privateBytes = 1; v.privateDigest = privateDigest }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := test.base
			test.edit(&arguments)
			request, err := arguments.new()
			if !errors.Is(err, ErrContractInvalidArgument) || request != (PolicyRequest{}) {
				t.Fatalf("NewPolicyRequest() = (%v, %v), want zero/invalid argument", request, err)
			}
		})
	}
}

func TestHelperPolicyDecisionOrderAndClosedRejectionAuthority(t *testing.T) {
	partial, _, manifest := policyFixtures(t)
	valid := PolicyRequest{
		operation:       PolicyOperationPrepare,
		correlation:     requestCorrelation{requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1},
		generations:     partial,
		expiresUnixNano: 1,
		fixedLimitSetID: "helper-limits-v1",
		manifest:        manifest,
		manifestSHA256:  manifest.SHA256(),
	}
	policy := NewHelperPolicy()
	if policy == nil || reflect.ValueOf(policy).Kind() == reflect.Pointer {
		t.Fatal("NewHelperPolicy must return a non-nil, non-pointer production policy value")
	}

	tests := []struct {
		name    string
		edit    func(*PolicyRequest)
		allowed bool
		code    PolicyRejectionCode
	}{
		{name: "allow", allowed: true},
		{name: "closed operation first", edit: func(v *PolicyRequest) {
			v.operation = 0
			v.correlation.requestID = [16]byte{}
			v.fixedLimitSetID = "wrong"
			v.manifestSHA256 = [32]byte{}
		}, code: PolicyRejectionOperationDenied},
		{name: "shape before limits", edit: func(v *PolicyRequest) {
			v.correlation.requestID = [16]byte{}
			v.fixedLimitSetID = "wrong"
			v.manifestSHA256 = [32]byte{}
		}, code: PolicyRejectionMalformed},
		{name: "limits before manifest", edit: func(v *PolicyRequest) { v.fixedLimitSetID = "wrong"; v.manifestSHA256 = [32]byte{} }, code: PolicyRejectionResourceLimit},
		{name: "manifest mismatch", edit: func(v *PolicyRequest) { v.manifestSHA256 = [32]byte{3} }, code: PolicyRejectionManifestMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			if test.edit != nil {
				test.edit(&request)
			}
			decision, err := policy.Authorize(request)
			if err != nil || decision.Allowed() != test.allowed || decision.RejectionCode() != test.code {
				t.Fatalf("Authorize() = allowed %t code %d error %v", decision.Allowed(), decision.RejectionCode(), err)
			}
			if test.allowed && test.code != 0 || !test.allowed && test.code == 0 {
				t.Fatal("test case specifies invalid decision matrix")
			}
		})
	}

	for _, serviceOwned := range []PolicyRejectionCode{PolicyRejectionIdentityMismatch, PolicyRejectionRevisionStale, PolicyRejectionExpired, PolicyRejectionGenerationMismatch} {
		request := valid
		request.correlation.identityDigest = [32]byte{}
		decision, err := policy.Authorize(request)
		if err != nil || decision.Allowed() || decision.RejectionCode() == serviceOwned {
			t.Fatalf("helper policy minted service-owned rejection %d", serviceOwned)
		}
	}
}

func TestPolicyDecisionConstructorsEnforceExactMatrix(t *testing.T) {
	allowed := newPolicyAllowDecision()
	if !allowed.Allowed() || allowed.RejectionCode() != 0 || !allowed.allow || allowed.rejectionCode != 0 {
		t.Fatal("allow constructor did not produce exact allow=true/code=0")
	}
	for code := PolicyRejectionMalformed; code <= PolicyRejectionOperationDenied; code++ {
		decision := newPolicyRejectionDecision(code)
		if decision.Allowed() || decision.RejectionCode() != code || decision.allow || decision.rejectionCode != code {
			t.Errorf("rejection %d did not produce exact allow=false/nonzero-code matrix", code)
		}
	}
	for _, code := range []PolicyRejectionCode{0, PolicyRejectionOperationDenied + 1, 255} {
		if decision := newPolicyRejectionDecision(code); decision != (PolicyDecision{}) {
			t.Errorf("unknown rejection %d produced a nonzero decision", code)
		}
	}
	for _, invalid := range []PolicyDecision{
		{allow: true, rejectionCode: PolicyRejectionMalformed},
		{rejectionCode: PolicyRejectionOperationDenied + 1},
	} {
		if invalid.Allowed() || invalid.RejectionCode() != 0 {
			t.Errorf("invalid decision matrix was exposed as valid: %+v", invalid)
		}
	}
}

func TestHelperPolicyResourceBoundsAndManifestAuthorization(t *testing.T) {
	_, complete, manifest := policyFixtures(t)
	execDigest := sha256.Sum256([]byte("exec"))
	privateDigest := sha256.Sum256([]byte("private"))
	base := PolicyRequest{
		operation:       PolicyOperationExec,
		correlation:     requestCorrelation{requestID: [16]byte{1}, identityDigest: [32]byte{2}, revision: 1},
		generations:     complete,
		fixedLimitSetID: "helper-limits-v1",
		manifest:        manifest,
		manifestSHA256:  manifest.SHA256(),
		execBodyBytes:   credentialprotocol.MaxHelperPacketBodyBytes,
		execBodySHA256:  execDigest,
		privateBytes:    credentialprotocol.MaxHelperExecPrivateBytes,
		privateSHA256:   privateDigest,
	}
	policy := NewHelperPolicy()
	if decision, err := policy.Authorize(base); err != nil || !decision.Allowed() {
		t.Fatalf("Authorize(exact maxima) = (%v, %v)", decision, err)
	}

	tests := []struct {
		name string
		edit func(*PolicyRequest)
		code PolicyRejectionCode
	}{
		{name: "exec plus one", edit: func(v *PolicyRequest) { v.execBodyBytes++ }, code: PolicyRejectionResourceLimit},
		{name: "private plus one", edit: func(v *PolicyRequest) { v.privateBytes++ }, code: PolicyRejectionResourceLimit},
		{name: "zero exec with digest", edit: func(v *PolicyRequest) { v.execBodyBytes = 0 }, code: PolicyRejectionMalformed},
		{name: "zero private with digest", edit: func(v *PolicyRequest) { v.privateBytes = 0 }, code: PolicyRejectionMalformed},
		{name: "manifest digest changed", edit: func(v *PolicyRequest) { v.manifestSHA256 = [32]byte{8} }, code: PolicyRejectionManifestMismatch},
		{name: "manifest storage noncanonical", edit: func(v *PolicyRequest) {
			v.manifest.records[credentialprotocol.MaxHelperBindings-1].bindingID = "hidden"
		}, code: PolicyRejectionManifestMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.edit(&request)
			decision, err := policy.Authorize(request)
			if err != nil || decision.Allowed() || decision.RejectionCode() != test.code {
				t.Fatalf("Authorize() = allowed %t code %d error %v", decision.Allowed(), decision.RejectionCode(), err)
			}
		})
	}

	twoSSH := manifest
	twoSSH.count = 2
	twoSSH.records[0] = manifestRecord{bindingID: "ssh-1", mode: credentialprotocol.DeliveryModeSSHAgent}
	twoSSH.records[1] = manifestRecord{bindingID: "ssh-2", mode: credentialprotocol.DeliveryModeSSHAgent}
	twoHTTP := manifest
	twoHTTP.count = 2
	twoHTTP.records[1] = manifestRecord{bindingID: "http-2", mode: credentialprotocol.DeliveryModeHTTPProxy}
	for _, manifestTest := range []struct {
		name      string
		candidate ManifestCapability
	}{{name: "two SSH bindings", candidate: twoSSH}, {name: "two HTTP bindings", candidate: twoHTTP}} {
		t.Run(manifestTest.name, func(t *testing.T) {
			request := base
			request.manifest = manifestTest.candidate
			request.manifestSHA256 = manifestTest.candidate.SHA256()
			decision, err := policy.Authorize(request)
			if err != nil || decision.Allowed() || decision.RejectionCode() != PolicyRejectionResourceLimit {
				t.Fatalf("Authorize() = allowed %t code %d error %v", decision.Allowed(), decision.RejectionCode(), err)
			}
		})
	}
}

func TestHelperPolicyDescriptorDigestAndAllPolicyValuesFailClosed(t *testing.T) {
	policy := NewHelperPolicy()
	descriptor := policy.Descriptor()
	if descriptor.ID() != "helper-policy-v1" {
		t.Fatalf("descriptor ID = %q", descriptor.ID())
	}
	want := sha256.Sum256(append(policyOpaque16("hal/l8/process-policy/v1"), policyOpaque16("helper-policy-v1")...))
	if descriptor.SHA256() != want {
		t.Fatalf("descriptor digest = %x, want %x", descriptor.SHA256(), want)
	}
	if policy.Descriptor() != descriptor {
		t.Fatal("Descriptor changed across reads")
	}

	partial, _, manifest := policyFixtures(t)
	request, err := NewPolicyRequest(PolicyOperationPrepare, [16]byte{1}, [32]byte{2}, 1, partial, 1, "helper-limits-v1", manifest, manifest.SHA256(), 0, [32]byte{}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{policy, request, decision, descriptor, PolicyRequest{}, PolicyDecision{}, PolicyDescriptor{}}
	for _, value := range values {
		assertPolicyValueFailsClosed(t, value)
	}
}

type policyRequestArguments struct {
	operation       PolicyOperation
	requestID       [16]byte
	identityDigest  [32]byte
	revision        uint64
	generations     CoreGenerations
	expiry          int64
	fixedLimitSetID credentialprotocol.SafeID
	manifest        ManifestCapability
	manifestDigest  [32]byte
	execBytes       uint32
	execDigest      [32]byte
	privateBytes    uint32
	privateDigest   [32]byte
}

func (v policyRequestArguments) new() (PolicyRequest, error) {
	return NewPolicyRequest(v.operation, v.requestID, v.identityDigest, v.revision, v.generations, v.expiry, v.fixedLimitSetID, v.manifest, v.manifestDigest, v.execBytes, v.execDigest, v.privateBytes, v.privateDigest)
}

func policyFixtures(t *testing.T) (CoreGenerations, CoreGenerations, ManifestCapability) {
	t.Helper()
	partial, err := NewCoreGenerations("boot-1", "helper-1", "job-1", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	complete, err := NewCoreGenerations("boot-1", "helper-1", "job-1", "monitor-1", "mount-1", "cgroup-1")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord{{BindingID: "http-1", Mode: credentialprotocol.DeliveryModeHTTPProxy}})
	if err != nil {
		t.Fatal(err)
	}
	return partial, complete, manifest
}

func assertPolicyValueFailsClosed(t *testing.T, value any) {
	t.Helper()
	pointer := reflect.New(reflect.TypeOf(value))
	pointer.Elem().Set(reflect.ValueOf(value))
	for _, candidate := range []any{value, pointer.Interface()} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O", "%b", "%U"} {
			if got := fmt.Sprintf(format, candidate); got != "credentialhelper.live[redacted]" {
				t.Fatalf("format %s for %T = %q", format, candidate, got)
			}
		}
		if encoded, err := json.Marshal(candidate); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
			t.Fatalf("json.Marshal(%T) = (%q, %v)", candidate, encoded, err)
		}
	}
	if encoded, err := value.(encoding.TextMarshaler).MarshalText(); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("MarshalText(%T) = (%q, %v)", value, encoded, err)
	}
	if encoded, err := value.(encoding.BinaryMarshaler).MarshalBinary(); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("MarshalBinary(%T) = (%q, %v)", value, encoded, err)
	}
	before := pointer.Elem().Interface()
	if err := json.Unmarshal([]byte(`{"private":"canary"}`), pointer.Interface()); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("UnmarshalJSON(%T) error = %v", value, err)
	}
	if err := pointer.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte("private")); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("UnmarshalText(%T) error = %v", value, err)
	}
	if err := pointer.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private")); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("UnmarshalBinary(%T) error = %v", value, err)
	}
	if after := pointer.Elem().Interface(); !reflect.DeepEqual(after, before) {
		t.Fatalf("%T changed after denied unmarshal", value)
	}
}

func policyOpaque16(value string) []byte {
	result := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(result[:2], uint16(len(value)))
	copy(result[2:], value)
	return result
}
