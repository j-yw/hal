package credentialhelper

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestCoreLiveValuesDenyFormattingAndSerialization(t *testing.T) {
	path, err := NewRelativePathCapability("private/marker")
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		CoreGenerations{boot: "secret-generation"}, path, ManifestCapability{}, ExecPlanCapability{},
		CorePreparationCapability{digest: coreDigest("secret-capability")}, CorePreparedCapability{}, CoreExecutionCapability{}, CoreCleanupCapability{},
		CorePrepareRequest{}, CoreFileRequest{}, CoreCommitRequest{}, CorePreparedResult{}, CoreExecRequest{},
		CoreRenewRequest{}, CoreRevokeRequest{}, CoreInspectRequest{}, CoreOutputRequest{}, CoreOutputResult{},
		CoreExecResult{}, CoreCleanupResult{}, CoreInspection{}, CoreExecutionEvent{}, ContractError{},
		ExtensionOpenRequest{}, ExtensionPrepareRequest{}, ExtensionPrepareResult{}, ExtensionExecRequest{}, ExtensionExecResult{},
		ExtensionRenewRequest{}, ExtensionRevokeRequest{}, SSHAgentEndpointRequest{}, SSHAcceptedPublication{},
		execBindingCapability{}, ExtensionCleanupResult{}, SSHIOResult{},
		ServiceResult{}, ServiceBootstrap{}, ServiceAgentBindingRequest{}, ServiceJobObservationRequest{}, ServiceJobObservation{}, ServiceLoss{},
	}
	for _, value := range values {
		t.Run(reflect.TypeOf(value).Name(), func(t *testing.T) {
			pointer := reflect.New(reflect.TypeOf(value))
			pointer.Elem().Set(reflect.ValueOf(value))
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				if got := fmt.Sprintf(format, value); got != "credentialhelper.live[redacted]" {
					t.Fatalf("format %s = %q", format, got)
				}
				if got := fmt.Sprintf(format, pointer.Interface()); got != "credentialhelper.live[redacted]" {
					t.Fatalf("pointer format %s = %q", format, got)
				}
			}
			if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("MarshalJSON = %q, %v", encoded, err)
			}
			if encoded, err := json.Marshal(pointer.Interface()); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("pointer MarshalJSON = %q, %v", encoded, err)
			}
			if encoded, err := value.(encoding.TextMarshaler).MarshalText(); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("MarshalText = %q, %v", encoded, err)
			}
			if encoded, err := value.(encoding.BinaryMarshaler).MarshalBinary(); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("MarshalBinary = %q, %v", encoded, err)
			}

			before := pointer.Elem().Interface()
			if err := json.Unmarshal([]byte(`{"seed":"private"}`), pointer.Interface()); !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("UnmarshalJSON error = %v", err)
			}
			if err := pointer.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte("private")); !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("UnmarshalText error = %v", err)
			}
			if err := pointer.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private")); !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("UnmarshalBinary error = %v", err)
			}
			if after := pointer.Elem().Interface(); !reflect.DeepEqual(after, before) {
				t.Fatal("seed changed after denied unmarshal")
			}
		})
	}
}

func TestContractErrorCatalog(t *testing.T) {
	tests := []struct {
		err  error
		code ContractErrorCode
		text string
	}{
		{ErrContractInvalidArgument, ContractInvalidArgument, "credential helper contract invalid_argument"},
		{ErrContractTypedNil, ContractTypedNil, "credential helper contract typed_nil"},
		{ErrContractCorrelation, ContractCorrelation, "credential helper contract correlation"},
		{ErrContractTransition, ContractTransition, "credential helper contract transition"},
		{ErrContractCapability, ContractCapability, "credential helper contract capability"},
		{ErrContractOwnership, ContractOwnership, "credential helper contract ownership"},
		{ErrContractResultMatrix, ContractResultMatrix, "credential helper contract result_matrix"},
		{ErrContractDependency, ContractDependency, "credential helper contract dependency"},
		{ErrContractDestroyed, ContractDestroyed, "credential helper contract destroyed"},
	}
	for _, test := range tests {
		contract := test.err.(ContractError)
		if contract.Code() != test.code || contract.Error() != test.text || !errors.Is(contract, test.err) || errors.Is(contract, ErrContractDependency) && test.code != ContractDependency {
			t.Fatalf("error %d = %d, %q", test.code, contract.Code(), contract.Error())
		}
	}
}
