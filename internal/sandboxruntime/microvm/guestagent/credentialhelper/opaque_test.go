package credentialhelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type formattingTrapFactory struct{}

func (formattingTrapFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return nil, nil
}

func (formattingTrapFactory) Format(fmt.State, rune) {
	panic("factory formatting traversed")
}

func TestOpaqueConcreteTypesHaveNoPublicFields(t *testing.T) {
	if reflect.TypeOf((*ExecBindingCapability)(nil)).Elem().Kind() != reflect.Interface {
		t.Fatal("ExecBindingCapability must expose only an opaque interface")
	}
	for _, value := range []any{execBindingCapability{}, ExtensionCleanupResult{}, SSHIOResult{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Errorf("%s field %s is exported", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
	if _, ok := reflect.TypeOf((*ExecBindingCapability)(nil)).Elem().MethodByName("ID"); ok {
		t.Fatal("ExecBindingCapability exposes ID authority")
	}
	if _, ok := reflect.TypeOf((*ExecBindingCapability)(nil)).Elem().MethodByName("SHA256"); ok {
		t.Fatal("ExecBindingCapability exposes digest authority")
	}
}

func TestExtensionCleanupResultConstructionAndAccessors(t *testing.T) {
	for _, test := range []struct {
		absent   bool
		category ExtensionCleanupCategory
	}{
		{absent: true, category: ExtensionCleanupComplete},
		{absent: false, category: ExtensionCleanupRetryRequired},
		{absent: false, category: ExtensionCleanupStopVMRequired},
	} {
		result, err := NewExtensionCleanupResult(test.absent, test.category)
		if err != nil {
			t.Fatalf("NewExtensionCleanupResult() error = %v", err)
		}
		if result.ResourcesAbsent() != test.absent || result.Category() != test.category {
			t.Fatalf("result accessors = %v/%v", result.ResourcesAbsent(), result.Category())
		}
	}
	for _, test := range []struct {
		absent   bool
		category ExtensionCleanupCategory
	}{
		{absent: false, category: ExtensionCleanupComplete},
		{absent: true, category: ExtensionCleanupRetryRequired},
		{absent: true, category: ExtensionCleanupStopVMRequired},
		{absent: false, category: 99},
	} {
		if _, err := NewExtensionCleanupResult(test.absent, test.category); err == nil {
			t.Errorf("NewExtensionCleanupResult(%v, %v) succeeded", test.absent, test.category)
		}
	}
}

func TestSSHIOResultConstructionAndAccessors(t *testing.T) {
	result := NewSSHIOResult(4096, true, false)
	if result.ByteCount() != 4096 || !result.EOF() || result.Truncated() {
		t.Fatalf("result = count %d, EOF %v, truncated %v", result.ByteCount(), result.EOF(), result.Truncated())
	}
}

func TestSensitiveContractsDenySerializationAndFormatting(t *testing.T) {
	identity := [32]byte{}
	copy(identity[:], "super-secret-socket-fingerprint")
	request := ExtensionPrepareRequest{
		IdentityDigest: identity,
		Revision:       17,
		BindingID:      credentialprotocol.SafeID("secret-binding-marker"),
		Mode:           credentialprotocol.DeliveryModeSSHAgent,
	}
	cleanup, err := NewExtensionCleanupResult(false, ExtensionCleanupRetryRequired)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: formattingTrapFactory{}},
		&ExtensionRegistry{},
		ExtensionOpenRequest{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor()},
		request,
		ExtensionPrepareResult{ExecBinding: newExecBindingCapability()},
		ExtensionExecRequest{IdentityDigest: identity, Revision: 17, ExecBindingID: "secret-binding-marker"},
		ExtensionExecResult{ExecBinding: newExecBindingCapability()},
		ExtensionRenewRequest{IdentityDigest: identity, Revision: 17},
		ExtensionRevokeRequest{IdentityDigest: identity, Revision: 17, Reason: credentialprotocol.RevokeReasonRequested},
		SSHAgentEndpointRequest{IdentityDigest: identity, Revision: 17, BindingID: "secret-binding-marker"},
		SSHAcceptedPublication{IdentityDigest: identity, Revision: 17, CapabilitySHA256: identity},
		newExecBindingCapability(),
		cleanup,
		NewSSHIOResult(99, true, true),
	}
	for _, value := range values {
		t.Run(reflect.TypeOf(value).Name(), func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if encoded != nil || !errors.Is(err, ErrExtensionSerialization) {
				t.Fatalf("json.Marshal() = %q, %v", encoded, err)
			}
			jsonMarshaler, ok := value.(interface{ MarshalJSON() ([]byte, error) })
			if !ok {
				t.Fatal("value does not implement json.Marshaler")
			}
			encoded, err = jsonMarshaler.MarshalJSON()
			if encoded != nil || !errors.Is(err, ErrExtensionSerialization) || err.Error() != ErrExtensionSerialization.Error() {
				t.Fatalf("MarshalJSON() = %q, %v", encoded, err)
			}
			for _, rendered := range []string{
				fmt.Sprint(value), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
			} {
				if strings.Contains(rendered, "secret") || strings.Contains(rendered, "17") || strings.Contains(rendered, "99") {
					t.Fatalf("format leaked value: %q", rendered)
				}
				if !strings.Contains(rendered, "credentialhelper") {
					t.Fatalf("format = %q, want opaque package marker", rendered)
				}
			}
			textMarshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
			if !ok {
				t.Fatal("value does not implement encoding.TextMarshaler")
			}
			encoded, err = textMarshaler.MarshalText()
			if encoded != nil || !errors.Is(err, ErrExtensionSerialization) {
				t.Fatalf("MarshalText() = %q, %v", encoded, err)
			}
		})
	}
}
