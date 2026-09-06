package l8composition

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

var (
	ErrCompositionDependency    = errors.New("L8 process composition dependency is invalid")
	ErrCompositionRegistration  = errors.New("L8 process composition registration is invalid")
	ErrCompositionPolicy        = errors.New("L8 process composition policy is invalid")
	ErrCompositionPanic         = errors.New("L8 process composition dependency panicked")
	ErrCompositionHelper        = errors.New("L8 helper composition failed")
	ErrCompositionClient        = errors.New("L8 client composition failed")
	ErrCompositionSerialization = errors.New("L8 process composition serialization is denied")
)

// HelperOptions is the complete privileged-helper process dependency set.
// Host and Runtime are independent authorities and are never recovered from
// Core or from the SSH registration.
type HelperOptions struct {
	Core      credentialhelper.Core
	Transport credentialhelper.Transport
	Policy    credentialhelper.Policy
	Host      credentialhelper.ExtensionHost
	Runtime   credentialhelper.ServiceRuntime
	SSH       credentialhelper.ExtensionRegistration
}

// ClientOptions is the complete unprivileged-client process dependency set.
// The authenticated transport, fixed policy, and one SSH registration must be
// supplied explicitly; composition installs no defaults.
type ClientOptions struct {
	Transport credentialclient.Transport
	Policy    credentialclient.Policy
	SSH       credentialclient.ExtensionRegistration
}

// NewHelper constructs exactly one process-local registry and passes every
// explicit dependency directly into the generic helper service constructor.
func NewHelper(options HelperOptions) (*credentialhelper.Service, ProcessDescriptor, error) {
	if !configuredCompositionDependency(options.Core) ||
		!configuredCompositionDependency(options.Transport) ||
		!configuredCompositionDependency(options.Policy) ||
		!configuredCompositionDependency(options.Host) ||
		!configuredCompositionDependency(options.Runtime) {
		return nil, ProcessDescriptor{}, ErrCompositionDependency
	}
	registry, err := credentialhelper.NewExtensionRegistry(options.SSH)
	if err != nil {
		return nil, ProcessDescriptor{}, ErrCompositionRegistration
	}
	extensions := registry.Descriptors()
	if !exactSSHCompositionExtensions(extensions) {
		return nil, ProcessDescriptor{}, ErrCompositionRegistration
	}
	policySHA256, policyErr := snapshotHelperPolicy(options.Policy)
	if policyErr != nil {
		return nil, ProcessDescriptor{}, policyErr
	}
	descriptor := ProcessDescriptor{
		ContractVersion: ProcessDescriptorContractVersion,
		Role:            ProcessRoleHelper,
		Extensions:      credentialprotocol.CloneExtensionDescriptors(extensions),
		PolicySHA256:    policySHA256,
	}
	if _, err := EncodeProcessDescriptor(descriptor); err != nil {
		return nil, ProcessDescriptor{}, ErrCompositionRegistration
	}
	service, err := credentialhelper.NewService(credentialhelper.ServiceOptions{
		Core:       options.Core,
		Transport:  options.Transport,
		Policy:     options.Policy,
		Extensions: registry,
		Host:       options.Host,
		Runtime:    options.Runtime,
	})
	if err != nil || service == nil {
		return nil, ProcessDescriptor{}, ErrCompositionHelper
	}
	return service, cloneProcessCompositionDescriptor(descriptor), nil
}

// NewClient constructs exactly one process-local registry and one immutable
// process descriptor view. The generic client independently pins the view into
// its temporary locked mapping and destroys that mapping before this returns.
func NewClient(options ClientOptions) (*credentialclient.Client, ProcessDescriptor, error) {
	if !configuredCompositionDependency(options.Transport) || !configuredCompositionDependency(options.Policy) {
		return nil, ProcessDescriptor{}, ErrCompositionDependency
	}
	registry, err := credentialclient.NewExtensionRegistry(options.SSH)
	if err != nil {
		return nil, ProcessDescriptor{}, ErrCompositionRegistration
	}
	extensions := registry.Descriptors()
	if !exactSSHCompositionExtensions(extensions) {
		return nil, ProcessDescriptor{}, ErrCompositionRegistration
	}
	policySHA256, policyErr := snapshotClientPolicy(options.Policy)
	if policyErr != nil {
		return nil, ProcessDescriptor{}, policyErr
	}
	descriptor := ProcessDescriptor{
		ContractVersion: ProcessDescriptorContractVersion,
		Role:            ProcessRoleClient,
		Extensions:      credentialprotocol.CloneExtensionDescriptors(extensions),
		PolicySHA256:    policySHA256,
	}
	view, err := newClientProcessDescriptor(descriptor)
	if err != nil {
		return nil, ProcessDescriptor{}, ErrCompositionPolicy
	}
	client, err := credentialclient.NewClient(credentialclient.ClientOptions{
		Transport:  options.Transport,
		Policy:     options.Policy,
		Extensions: registry,
		Descriptor: view,
	})
	if err != nil || client == nil {
		return nil, ProcessDescriptor{}, ErrCompositionClient
	}
	return client, cloneProcessCompositionDescriptor(descriptor), nil
}

func exactSSHCompositionExtensions(extensions []credentialprotocol.ExtensionDescriptor) bool {
	return len(extensions) == 1 && credentialprotocol.ExtensionDescriptorEqual(extensions[0], credentialprotocol.SSHRelayV1ExtensionDescriptor())
}

func snapshotHelperPolicy(policy credentialhelper.Policy) ([32]byte, error) {
	first, panicked := readHelperPolicyDescriptor(policy)
	if panicked {
		return [32]byte{}, ErrCompositionPanic
	}
	second, panicked := readHelperPolicyDescriptor(policy)
	if panicked {
		return [32]byte{}, ErrCompositionPanic
	}
	expected := processPolicyDigest(helperPolicyID)
	if first.ID() != credentialprotocol.SafeID(helperPolicyID) ||
		first.ID() != second.ID() ||
		first.SHA256() != second.SHA256() ||
		first.SHA256() != expected {
		return [32]byte{}, ErrCompositionPolicy
	}
	return first.SHA256(), nil
}

func snapshotClientPolicy(policy credentialclient.Policy) ([32]byte, error) {
	first, panicked := readClientPolicyDescriptor(policy)
	if panicked {
		return [32]byte{}, ErrCompositionPanic
	}
	second, panicked := readClientPolicyDescriptor(policy)
	if panicked {
		return [32]byte{}, ErrCompositionPanic
	}
	expected := processPolicyDigest(clientPolicyID)
	if first.ID() != credentialprotocol.SafeID(clientPolicyID) ||
		first.ID() != second.ID() ||
		first.SHA256() != second.SHA256() ||
		first.SHA256() != expected {
		return [32]byte{}, ErrCompositionPolicy
	}
	return first.SHA256(), nil
}

func readHelperPolicyDescriptor(policy credentialhelper.Policy) (descriptor credentialhelper.PolicyDescriptor, panicked bool) {
	defer func() {
		if recover() != nil {
			descriptor = credentialhelper.PolicyDescriptor{}
			panicked = true
		}
	}()
	return policy.Descriptor(), false
}

func readClientPolicyDescriptor(policy credentialclient.Policy) (descriptor credentialclient.PolicyDescriptor, panicked bool) {
	defer func() {
		if recover() != nil {
			descriptor = credentialclient.PolicyDescriptor{}
			panicked = true
		}
	}()
	return policy.Descriptor(), false
}

func configuredCompositionDependency(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && reflected.Kind() == reflect.Interface {
		if reflected.IsNil() {
			return false
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() {
		return false
	}
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return !reflected.IsNil()
	default:
		return true
	}
}

type clientProcessDescriptor struct {
	compositionLiveValue
	descriptor    ProcessDescriptor
	encodedLength uint16
	sha256        [32]byte
}

func newClientProcessDescriptor(descriptor ProcessDescriptor) (clientProcessDescriptor, error) {
	if descriptor.Role != ProcessRoleClient {
		return clientProcessDescriptor{}, ErrProcessDescriptorRole
	}
	encoded, err := EncodeProcessDescriptor(descriptor)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxProcessDescriptorBytes {
		return clientProcessDescriptor{}, ErrProcessDescriptorContract
	}
	digest := sha256.Sum256(encoded)
	clear(encoded[:cap(encoded)])
	return clientProcessDescriptor{
		descriptor:    cloneProcessCompositionDescriptor(descriptor),
		encodedLength: uint16(len(encoded)),
		sha256:        digest,
	}, nil
}

func (view clientProcessDescriptor) ContractVersion() uint8 { return processDescriptorWireVersion }
func (view clientProcessDescriptor) Role() uint8            { return uint8(view.descriptor.Role) }
func (view clientProcessDescriptor) PolicySHA256() [32]byte { return view.descriptor.PolicySHA256 }
func (view clientProcessDescriptor) Extensions() []credentialprotocol.ExtensionDescriptor {
	return credentialprotocol.CloneExtensionDescriptors(view.descriptor.Extensions)
}
func (view clientProcessDescriptor) EncodedLength() uint16 { return view.encodedLength }
func (view clientProcessDescriptor) SHA256() [32]byte      { return view.sha256 }
func (view clientProcessDescriptor) WriteCanonical(sink credentialmemory.CredentialSink) error {
	if !configuredCompositionDependency(sink) {
		return ErrCompositionDependency
	}
	encoded, err := EncodeProcessDescriptor(view.descriptor)
	if err != nil {
		return ErrProcessDescriptorContract
	}
	defer clear(encoded[:cap(encoded)])
	if len(encoded) != int(view.encodedLength) || sha256.Sum256(encoded) != view.sha256 || sink.MaxCredentialBytes() != len(encoded) {
		return ErrProcessDescriptorContract
	}
	if err := sink.WriteCredential(encoded); err != nil {
		return ErrProcessDescriptorContract
	}
	return nil
}

func cloneProcessCompositionDescriptor(descriptor ProcessDescriptor) ProcessDescriptor {
	return ProcessDescriptor{
		ContractVersion: descriptor.ContractVersion,
		Role:            descriptor.Role,
		Extensions:      credentialprotocol.CloneExtensionDescriptors(descriptor.Extensions),
		PolicySHA256:    descriptor.PolicySHA256,
	}
}

type compositionLiveValue struct{}

func (compositionLiveValue) MarshalJSON() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (compositionLiveValue) MarshalText() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (compositionLiveValue) MarshalBinary() ([]byte, error) { return nil, ErrCompositionSerialization }
func (*compositionLiveValue) UnmarshalJSON([]byte) error    { return ErrCompositionSerialization }
func (*compositionLiveValue) UnmarshalText([]byte) error    { return ErrCompositionSerialization }
func (*compositionLiveValue) UnmarshalBinary([]byte) error  { return ErrCompositionSerialization }
func (compositionLiveValue) String() string                 { return "l8composition.live[redacted]" }
func (compositionLiveValue) GoString() string               { return "l8composition.live[redacted]" }
func (compositionLiveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("l8composition.live[redacted]"))
}

func (HelperOptions) MarshalJSON() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (HelperOptions) MarshalText() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (HelperOptions) MarshalBinary() ([]byte, error) { return nil, ErrCompositionSerialization }
func (*HelperOptions) UnmarshalJSON([]byte) error    { return ErrCompositionSerialization }
func (*HelperOptions) UnmarshalText([]byte) error    { return ErrCompositionSerialization }
func (*HelperOptions) UnmarshalBinary([]byte) error  { return ErrCompositionSerialization }
func (HelperOptions) String() string                 { return "l8composition.live[redacted]" }
func (HelperOptions) GoString() string               { return "l8composition.live[redacted]" }
func (HelperOptions) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("l8composition.live[redacted]"))
}

func (ClientOptions) MarshalJSON() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (ClientOptions) MarshalText() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (ClientOptions) MarshalBinary() ([]byte, error) { return nil, ErrCompositionSerialization }
func (*ClientOptions) UnmarshalJSON([]byte) error    { return ErrCompositionSerialization }
func (*ClientOptions) UnmarshalText([]byte) error    { return ErrCompositionSerialization }
func (*ClientOptions) UnmarshalBinary([]byte) error  { return ErrCompositionSerialization }
func (ClientOptions) String() string                 { return "l8composition.live[redacted]" }
func (ClientOptions) GoString() string               { return "l8composition.live[redacted]" }
func (ClientOptions) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("l8composition.live[redacted]"))
}

func (ProcessDescriptor) MarshalJSON() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (ProcessDescriptor) MarshalText() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (ProcessDescriptor) MarshalBinary() ([]byte, error) { return nil, ErrCompositionSerialization }
func (*ProcessDescriptor) UnmarshalJSON([]byte) error    { return ErrCompositionSerialization }
func (*ProcessDescriptor) UnmarshalText([]byte) error    { return ErrCompositionSerialization }
func (*ProcessDescriptor) UnmarshalBinary([]byte) error  { return ErrCompositionSerialization }
func (ProcessDescriptor) String() string                 { return "l8composition.live[redacted]" }
func (ProcessDescriptor) GoString() string               { return "l8composition.live[redacted]" }
func (ProcessDescriptor) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("l8composition.live[redacted]"))
}

func (CompositionDescriptor) MarshalJSON() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (CompositionDescriptor) MarshalText() ([]byte, error)   { return nil, ErrCompositionSerialization }
func (CompositionDescriptor) MarshalBinary() ([]byte, error) { return nil, ErrCompositionSerialization }
func (*CompositionDescriptor) UnmarshalJSON([]byte) error    { return ErrCompositionSerialization }
func (*CompositionDescriptor) UnmarshalText([]byte) error    { return ErrCompositionSerialization }
func (*CompositionDescriptor) UnmarshalBinary([]byte) error  { return ErrCompositionSerialization }
func (CompositionDescriptor) String() string                 { return "l8composition.live[redacted]" }
func (CompositionDescriptor) GoString() string               { return "l8composition.live[redacted]" }
func (CompositionDescriptor) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("l8composition.live[redacted]"))
}
