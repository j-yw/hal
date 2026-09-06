package credentialhelper

import (
	"context"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestExtensionContractMethodSetsAreExact(t *testing.T) {
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	tests := []struct {
		name    string
		typeOf  reflect.Type
		methods map[string]methodSignature
	}{
		{
			name:   "ExtensionFactory",
			typeOf: reflect.TypeOf((*ExtensionFactory)(nil)).Elem(),
			methods: map[string]methodSignature{
				"Open": {in: []reflect.Type{contextType, reflect.TypeOf(ExtensionOpenRequest{})}, out: []reflect.Type{reflect.TypeOf((*ExtensionSession)(nil)).Elem(), errorType}},
			},
		},
		{
			name:   "ExtensionSession",
			typeOf: reflect.TypeOf((*ExtensionSession)(nil)).Elem(),
			methods: map[string]methodSignature{
				"Prepare":  {in: []reflect.Type{contextType, reflect.TypeOf(ExtensionPrepareRequest{})}, out: []reflect.Type{reflect.TypeOf(ExtensionPrepareResult{}), errorType}},
				"BindExec": {in: []reflect.Type{contextType, reflect.TypeOf(ExtensionExecRequest{})}, out: []reflect.Type{reflect.TypeOf(ExtensionExecResult{}), errorType}},
				"Renew":    {in: []reflect.Type{contextType, reflect.TypeOf(ExtensionRenewRequest{})}, out: []reflect.Type{errorType}},
				"Revoke":   {in: []reflect.Type{contextType, reflect.TypeOf(ExtensionRevokeRequest{})}, out: []reflect.Type{reflect.TypeOf(ExtensionCleanupResult{}), errorType}},
				"Close":    {in: []reflect.Type{contextType}, out: []reflect.Type{errorType}},
			},
		},
		{
			name:   "ExtensionHost",
			typeOf: reflect.TypeOf((*ExtensionHost)(nil)).Elem(),
			methods: map[string]methodSignature{
				"CreateSSHAgentEndpoint":       {in: []reflect.Type{contextType, reflect.TypeOf(SSHAgentEndpointRequest{})}, out: []reflect.Type{reflect.TypeOf((*SSHAgentEndpoint)(nil)).Elem(), errorType}},
				"PublishSSHAcceptedConnection": {in: []reflect.Type{contextType, reflect.TypeOf(SSHAcceptedPublication{}), reflect.TypeOf((*SSHAgentConnection)(nil)).Elem()}, out: []reflect.Type{errorType}},
			},
		},
		{
			name:   "SSHAgentEndpoint",
			typeOf: reflect.TypeOf((*SSHAgentEndpoint)(nil)).Elem(),
			methods: map[string]methodSignature{
				"ExecBinding": {out: []reflect.Type{reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}},
				"Accept":      {in: []reflect.Type{contextType}, out: []reflect.Type{reflect.TypeOf((*SSHAgentConnection)(nil)).Elem(), errorType}},
				"Close":       {in: []reflect.Type{contextType}, out: []reflect.Type{reflect.TypeOf(ExtensionCleanupResult{}), errorType}},
			},
		},
		{
			name:   "SSHAgentConnection",
			typeOf: reflect.TypeOf((*SSHAgentConnection)(nil)).Elem(),
			methods: map[string]methodSignature{
				"Read":     {in: []reflect.Type{contextType, reflect.TypeOf((*credentialmemory.CredentialSink)(nil)).Elem()}, out: []reflect.Type{reflect.TypeOf(SSHIOResult{}), errorType}},
				"Write":    {in: []reflect.Type{contextType, reflect.TypeOf((*credentialmemory.BorrowedView)(nil)).Elem()}, out: []reflect.Type{reflect.TypeOf(SSHIOResult{}), errorType}},
				"Shutdown": {in: []reflect.Type{contextType, reflect.TypeOf(SSHShutdownDirection(0))}, out: []reflect.Type{errorType}},
				"Close":    {in: []reflect.Type{contextType}, out: []reflect.Type{errorType}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.typeOf.NumMethod() != len(test.methods) {
				t.Fatalf("method count = %d, want %d", test.typeOf.NumMethod(), len(test.methods))
			}
			for name, signature := range test.methods {
				method, ok := test.typeOf.MethodByName(name)
				if !ok {
					t.Fatalf("missing method %s", name)
				}
				assertMethodSignature(t, method.Type, signature)
			}
		})
	}
}

type methodSignature struct {
	in  []reflect.Type
	out []reflect.Type
}

func assertMethodSignature(t *testing.T, actual reflect.Type, want methodSignature) {
	t.Helper()
	if actual.NumIn() != len(want.in) || actual.NumOut() != len(want.out) {
		t.Fatalf("signature = %v, want %d inputs and %d outputs", actual, len(want.in), len(want.out))
	}
	for index, typeOf := range want.in {
		if actual.In(index) != typeOf {
			t.Errorf("input %d = %v, want %v", index, actual.In(index), typeOf)
		}
	}
	for index, typeOf := range want.out {
		if actual.Out(index) != typeOf {
			t.Errorf("output %d = %v, want %v", index, actual.Out(index), typeOf)
		}
	}
}

func TestExtensionRequestAndResultFieldSetsAreExact(t *testing.T) {
	tests := []struct {
		value  any
		fields []fieldContract
	}{
		{ExtensionRegistration{}, []fieldContract{{"Descriptor", reflect.TypeOf(credentialprotocol.ExtensionDescriptor{})}, {"Factory", reflect.TypeOf((*ExtensionFactory)(nil)).Elem()}}},
		{ExtensionOpenRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"descriptor", reflect.TypeOf(credentialprotocol.ExtensionDescriptor{})}, {"host", reflect.TypeOf((*ExtensionHost)(nil)).Elem()}}},
		{ExtensionPrepareRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"expiresUnixNano", reflect.TypeOf(int64(0))}, {"bindingID", reflect.TypeOf(credentialprotocol.SafeID(""))}, {"bindingIndex", reflect.TypeOf(uint16(0))}, {"mode", reflect.TypeOf(credentialprotocol.DeliveryMode(0))}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
		{ExtensionPrepareResult{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
		{ExtensionExecRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"execBindingID", reflect.TypeOf(credentialprotocol.SafeID(""))}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
		{ExtensionExecResult{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
		{ExtensionRenewRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"expiresUnixNano", reflect.TypeOf(int64(0))}}},
		{ExtensionRevokeRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"reason", reflect.TypeOf(credentialprotocol.RevokeReason(0))}}},
		{SSHAgentEndpointRequest{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"bindingID", reflect.TypeOf(credentialprotocol.SafeID(""))}, {"bindingIndex", reflect.TypeOf(uint16(0))}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
		{SSHAcceptedPublication{}, []fieldContract{{"liveValue", reflect.TypeOf(liveValue{})}, {"identityDigest", reflect.TypeOf([32]byte{})}, {"revision", reflect.TypeOf(uint64(0))}, {"bindingIndex", reflect.TypeOf(uint16(0))}, {"ordinal", reflect.TypeOf(uint8(0))}, {"capabilitySHA256", reflect.TypeOf([32]byte{})}, {"execBinding", reflect.TypeOf((*ExecBindingCapability)(nil)).Elem()}}},
	}

	for _, test := range tests {
		typeOf := reflect.TypeOf(test.value)
		t.Run(typeOf.Name(), func(t *testing.T) {
			if typeOf.NumField() != len(test.fields) {
				t.Fatalf("field count = %d, want %d", typeOf.NumField(), len(test.fields))
			}
			for index, want := range test.fields {
				field := typeOf.Field(index)
				if field.Name != want.name || field.Type != want.typeOf {
					t.Errorf("field %d = %s %v, want %s %v", index, field.Name, field.Type, want.name, want.typeOf)
				}
				if field.Tag != "" {
					t.Errorf("field %s tag = %q, want none", field.Name, field.Tag)
				}
			}
		})
	}
}

type fieldContract struct {
	name   string
	typeOf reflect.Type
}

func TestClosedEnumValues(t *testing.T) {
	if ExtensionCleanupComplete != 1 || ExtensionCleanupRetryRequired != 2 || ExtensionCleanupStopVMRequired != 3 {
		t.Fatalf("cleanup values = %d, %d, %d", ExtensionCleanupComplete, ExtensionCleanupRetryRequired, ExtensionCleanupStopVMRequired)
	}
	if SSHShutdownRead != 1 || SSHShutdownWrite != 2 || SSHShutdownBoth != 3 {
		t.Fatalf("shutdown values = %d, %d, %d", SSHShutdownRead, SSHShutdownWrite, SSHShutdownBoth)
	}
	for _, value := range []ExtensionCleanupCategory{0, 4, 255} {
		if err := ValidateExtensionCleanupCategory(value); err == nil {
			t.Errorf("ValidateExtensionCleanupCategory(%d) succeeded", value)
		}
	}
	for _, value := range []SSHShutdownDirection{0, 4, 255} {
		if err := ValidateSSHShutdownDirection(value); err == nil {
			t.Errorf("ValidateSSHShutdownDirection(%d) succeeded", value)
		}
	}
}
