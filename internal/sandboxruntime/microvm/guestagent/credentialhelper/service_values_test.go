package credentialhelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type serviceTestHost struct{}

func (serviceTestHost) CreateSSHAgentEndpoint(context.Context, SSHAgentEndpointRequest) (SSHAgentEndpoint, error) {
	return nil, nil
}
func (serviceTestHost) PublishSSHAcceptedConnection(context.Context, SSHAcceptedPublication, SSHAgentConnection) error {
	return nil
}

func TestExtensionValuesCloneAndExposeOnlySafeCopies(t *testing.T) {
	descriptor := credentialprotocol.SSHRelayV1ExtensionDescriptor()
	request, err := NewExtensionOpenRequest(descriptor, serviceTestHost{})
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	first := request.Descriptor()
	if first.Modes[0] != credentialprotocol.DeliveryModeSSHAgent {
		t.Fatal("constructor retained descriptor alias")
	}
	first.Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	if request.Descriptor().Modes[0] != credentialprotocol.DeliveryModeSSHAgent {
		t.Fatal("descriptor accessor returned stored slice")
	}

	identity, digest, binding := serviceTestIdentityDigestBinding(t)
	prepared, err := NewExtensionPrepareRequest(identity, 7, 100, "ssh-binding", 0, credentialprotocol.DeliveryModeSSHAgent, binding)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.IdentityDigest() != identity || prepared.Revision() != 7 || prepared.ExpiresUnixNano() != 100 || prepared.BindingID() != "ssh-binding" || prepared.BindingIndex() != 0 || prepared.Mode() != credentialprotocol.DeliveryModeSSHAgent || validateExecBindingEcho(prepared.ExecBinding(), binding) != nil {
		t.Fatal("prepare accessors changed values")
	}
	publication, err := NewSSHAcceptedPublication(identity, 7, 0, 1, digest, binding)
	if err != nil || publication.CapabilitySHA256() != digest || validateExecBindingEcho(publication.ExecBinding(), binding) != nil {
		t.Fatalf("publication = %v", err)
	}
}

func TestSSHAcceptedPublicationOrdinalBounds(t *testing.T) {
	identity, digest, binding := serviceTestIdentityDigestBinding(t)
	for _, ordinal := range []uint8{0, credentialprotocol.SSHAgentRelayMaxLifetimeConnections + 1, 255} {
		if _, err := NewSSHAcceptedPublication(identity, 7, 0, ordinal, digest, binding); err != ErrContractInvalidArgument {
			t.Fatalf("ordinal %d error = %v", ordinal, err)
		}
	}
	if _, err := NewSSHAcceptedPublication(identity, 7, 0, credentialprotocol.SSHAgentRelayMaxLifetimeConnections, digest, binding); err != nil {
		t.Fatalf("maximum ordinal error = %v", err)
	}
}

func TestExecBindingCapabilityDigestAndEchoAreFrozen(t *testing.T) {
	identity, _, binding := serviceTestIdentityDigestBinding(t)
	manifest := sha256.Sum256([]byte("manifest"))
	transaction := sha256.Sum256([]byte("transaction"))
	generations := serviceTestGenerations(t)
	var canonical bytes.Buffer
	writeOpaque := func(value string) {
		_ = binary.Write(&canonical, binary.BigEndian, uint16(len(value)))
		_, _ = canonical.WriteString(value)
	}
	writeOpaque("hal/l8/guest-helper/extension-exec-binding/v1")
	_, _ = canonical.Write(identity[:])
	_, _ = canonical.Write(identity[:])
	_ = binary.Write(&canonical, binary.BigEndian, uint64(7))
	for _, generation := range []credentialprotocol.SafeID{generations.Boot(), generations.Helper(), generations.Job(), generations.Monitor(), generations.Mount(), generations.Cgroup()} {
		writeOpaque(string(generation))
	}
	_ = binary.Write(&canonical, binary.BigEndian, int64(100))
	_, _ = canonical.Write(manifest[:])
	_, _ = canonical.Write(transaction[:])
	_ = binary.Write(&canonical, binary.BigEndian, uint16(0))
	writeOpaque("ssh-binding")
	_ = canonical.WriteByte(byte(credentialprotocol.DeliveryModeSSHAgent))
	concrete, ok := binding.(execBindingCapability)
	if !ok || concrete.digest != sha256.Sum256(canonical.Bytes()) {
		t.Fatal("exec binding digest changed")
	}
	changed := execBindingCapability{digest: concrete.digest}
	changed.digest[0]++
	if validateExecBindingEcho(changed, binding) != ErrContractCapability {
		t.Fatal("changed binding echo accepted")
	}
	var typedNil *execBindingCapability
	if validateExecBindingEcho(typedNil, binding) != ErrContractCapability {
		t.Fatal("typed-nil binding echo accepted")
	}
}

func TestServiceRuntimeValuesAndCatalogs(t *testing.T) {
	identity := sha256.Sum256([]byte("identity"))
	bootstrapDigest := sha256.Sum256([]byte("bootstrap"))
	processDigest := sha256.Sum256([]byte("process"))
	bootstrap, err := NewServiceBootstrap(identity, "boot-1", "helper-1")
	if err != nil || bootstrap.BootNonce() != identity || bootstrap.BootGeneration() != "boot-1" || bootstrap.HelperGeneration() != "helper-1" {
		t.Fatalf("bootstrap = %#v, %v", bootstrap, err)
	}
	generations := serviceTestGenerations(t)
	observation, err := NewServiceJobObservation(generations, 100, 101)
	if err != nil || observation.Generations() != generations || observation.ObservedUnixNano() != 100 || observation.HardExpiryUnixNano() != 101 {
		t.Fatalf("observation = %#v, %v", observation, err)
	}
	if _, err := NewServiceJobObservation(generations, 101, 100); err != ErrContractInvalidArgument {
		t.Fatalf("regressing horizon error = %v", err)
	}
	bindingRequest, err := newServiceAgentBindingRequest(identity, bootstrapDigest, processDigest, "boot-1", "helper-1")
	if err != nil || bindingRequest.AgentIdentitySHA256() != identity || bindingRequest.BootstrapSHA256() != bootstrapDigest || bindingRequest.ProcessDescriptorSHA256() != processDigest || bindingRequest.BootGeneration() != "boot-1" || bindingRequest.HelperGeneration() != "helper-1" {
		t.Fatalf("agent binding request = %#v, %v", bindingRequest, err)
	}
	var requestID [16]byte
	requestID[0] = 1
	observationRequest, err := newServiceJobObservationRequest(ServiceOperationInspect, requestID, identity, 7, "boot-1", "helper-1")
	if err != nil || observationRequest.Operation() != ServiceOperationInspect || observationRequest.RequestID() != requestID || observationRequest.IdentityDigest() != identity || observationRequest.Revision() != 7 || observationRequest.BootGeneration() != "boot-1" || observationRequest.HelperGeneration() != "helper-1" {
		t.Fatalf("observation request = %#v, %v", observationRequest, err)
	}

	for value, name := range map[ServiceOperation]string{ServiceOperationPrepare: "prepare", ServiceOperationExec: "exec", ServiceOperationRenew: "renew", ServiceOperationRevoke: "revoke", ServiceOperationInspect: "inspect"} {
		if ValidateServiceOperation(value) != nil || value.String() != name {
			t.Errorf("operation %d = %q", value, value.String())
		}
	}
	for value, name := range map[ServiceLossCategory]string{ServiceLossAgent: "agent", ServiceLossJob: "job", ServiceLossMonitor: "monitor", ServiceLossMount: "mount", ServiceLossCgroup: "cgroup"} {
		loss, err := NewServiceLoss(value)
		if err != nil || loss.Category() != value || value.String() != name {
			t.Errorf("loss %d = %q, %v", value, value.String(), err)
		}
	}
	for _, value := range []uint8{0, 6, 255} {
		if ValidateServiceOperation(ServiceOperation(value)) == nil || ValidateServiceLossCategory(ServiceLossCategory(value)) == nil {
			t.Errorf("unknown service catalog value %d accepted", value)
		}
	}
	for _, test := range []struct {
		disposition ServiceDisposition
		reason      credentialprotocol.CloseReason
	}{
		{ServiceClosed, credentialprotocol.CloseReasonNormal},
		{ServiceClosed, credentialprotocol.CloseReasonShutdown},
		{ServiceStopVMRequired, credentialprotocol.CloseReasonHelperLoss},
	} {
		result, err := newServiceResult(test.disposition, test.reason)
		if err != nil || result.Disposition() != test.disposition || result.CloseReason() != test.reason {
			t.Fatalf("service result = %#v, %v", result, err)
		}
	}
	if _, err := newServiceResult(ServiceClosed, credentialprotocol.CloseReasonHelperLoss); err != ErrContractResultMatrix {
		t.Fatalf("invalid result error = %v", err)
	}
}

func TestServiceAndCoreInterfaceMethodSetsAreExact(t *testing.T) {
	assertInterfaceMethodNames(t, reflect.TypeOf((*ServiceRuntime)(nil)).Elem(), []string{"BeginCleanup", "BindAgent", "Bootstrap", "Close", "Loss", "ObserveJob"})
	assertInterfaceMethodNames(t, reflect.TypeOf((*ServiceCleanupBudget)(nil)).Elem(), []string{"Close", "Context", "DeadlineExceeded", "Limit"})
	assertInterfaceMethodNames(t, reflect.TypeOf((*Core)(nil)).Elem(), []string{"BeginExec", "BeginPrepare", "Close", "Inspect", "Renew", "Revoke"})
	assertInterfaceMethodNames(t, reflect.TypeOf((*CorePreparation)(nil)).Elem(), []string{"Commit", "Rollback", "StageFile"})
	assertInterfaceMethodNames(t, reflect.TypeOf((*CoreExecution)(nil)).Elem(), []string{"Cancel", "GrantOutput", "Next", "WriteStdin"})
	if reflect.TypeOf(ServiceCleanupBudget(nil)) != nil || serviceCleanupLimit != 30*time.Second {
		t.Fatal("cleanup budget type or frozen duration changed")
	}
}

func TestServiceExtensionAndEventFieldLayoutsAreExact(t *testing.T) {
	fields := []struct {
		value any
		names []string
	}{
		{ServiceOptions{}, []string{"Core", "Transport", "Policy", "Extensions", "Host", "Runtime"}},
		{ServiceResult{}, []string{"liveValue", "disposition", "closeReason"}},
		{ServiceBootstrap{}, []string{"liveValue", "bootNonce", "bootGeneration", "helperGeneration"}},
		{ServiceAgentBindingRequest{}, []string{"liveValue", "agentIdentitySHA256", "bootstrapSHA256", "processDescriptorSHA256", "bootGeneration", "helperGeneration"}},
		{ServiceJobObservationRequest{}, []string{"liveValue", "operation", "requestID", "identityDigest", "revision", "bootGeneration", "helperGeneration"}},
		{ServiceJobObservation{}, []string{"liveValue", "generations", "observedUnixNano", "hardExpiryUnixNano"}},
		{ServiceLoss{}, []string{"liveValue", "category"}},
		{CoreExecutionEvent{}, []string{"liveValue", "kind", "output", "body", "complete"}},
		{execBindingCapability{}, []string{"liveValue", "digest"}},
	}
	for _, contract := range fields {
		typeOf := reflect.TypeOf(contract.value)
		if typeOf.NumField() != len(contract.names) {
			t.Fatalf("%s fields = %d, want %d", typeOf.Name(), typeOf.NumField(), len(contract.names))
		}
		for index, name := range contract.names {
			field := typeOf.Field(index)
			if field.Name != name || field.Tag != "" {
				t.Errorf("%s field %d = %s tag %q, want %s untagged", typeOf.Name(), index, field.Name, field.Tag, name)
			}
		}
	}
	assertInterfaceMethodNames(t, reflect.TypeOf((*CoreOutputBody)(nil)).Elem(), []string{"Borrow", "Destroy", "Len", "SHA256"})
	if CoreExecutionEventOutput != 1 || CoreExecutionEventComplete != 2 || ServiceClosed != 1 || ServiceStopVMRequired != 2 {
		t.Fatal("service/event catalog values changed")
	}
}

func assertInterfaceMethodNames(t *testing.T, typeOf reflect.Type, want []string) {
	t.Helper()
	if typeOf.NumMethod() != len(want) {
		t.Fatalf("%s methods = %d, want %d", typeOf.Name(), typeOf.NumMethod(), len(want))
	}
	for index, name := range want {
		if typeOf.Method(index).Name != name {
			t.Errorf("%s method %d = %s, want %s", typeOf.Name(), index, typeOf.Method(index).Name, name)
		}
	}
}

func serviceTestIdentityDigestBinding(t *testing.T) ([32]byte, [32]byte, ExecBindingCapability) {
	t.Helper()
	identity := sha256.Sum256([]byte("identity"))
	manifest := sha256.Sum256([]byte("manifest"))
	transaction := sha256.Sum256([]byte("transaction"))
	binding, err := newExecBindingCapability(identity, identity, 7, serviceTestGenerations(t), 100, manifest, transaction, 0, "ssh-binding", credentialprotocol.DeliveryModeSSHAgent)
	if err != nil {
		t.Fatal(err)
	}
	return identity, sha256.Sum256([]byte("capability")), binding
}

func serviceTestGenerations(t *testing.T) CoreGenerations {
	t.Helper()
	value, err := NewCoreGenerations("boot-1", "helper-1", "job-1", "monitor-1", "mount-1", "cgroup-1")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
