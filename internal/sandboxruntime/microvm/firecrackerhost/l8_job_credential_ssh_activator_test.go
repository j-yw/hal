package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/sshrelay"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestProductionL8JobCredentialSSHRelayActivatorPublicAPIIsExact(t *testing.T) {
	constructor := reflect.TypeOf(NewProductionL8JobCredentialSSHRelayActivator)
	wantConstructor := reflect.TypeOf((func(*sshrelay.Registry, sshrelay.ConfigIdentity) (*ProductionL8JobCredentialSSHRelayActivator, error))(nil))
	if constructor != wantConstructor {
		t.Fatalf("NewProductionL8JobCredentialSSHRelayActivator type = %v, want %v", constructor, wantConstructor)
	}
	activatorType := reflect.TypeOf((*ProductionL8JobCredentialSSHRelayActivator)(nil))
	l8D6AssertExactExportedMethodSet(t, activatorType, map[string]reflect.Type{
		"Activate":        reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator, context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest) (l8JobCredentialSSHRelayHandle, error))(nil)),
		"Format":          reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator, fmt.State, rune))(nil)),
		"GoString":        reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator) string)(nil)),
		"MarshalBinary":   reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator) ([]byte, error))(nil)),
		"MarshalJSON":     reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator) ([]byte, error))(nil)),
		"MarshalText":     reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator) ([]byte, error))(nil)),
		"String":          reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator) string)(nil)),
		"UnmarshalBinary": reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator, []byte) error)(nil)),
		"UnmarshalJSON":   reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator, []byte) error)(nil)),
		"UnmarshalText":   reflect.TypeOf((func(*ProductionL8JobCredentialSSHRelayActivator, []byte) error)(nil)),
	})
	var _ l8JobCredentialSSHRelayActivator = (*ProductionL8JobCredentialSSHRelayActivator)(nil)
}

func TestProductionL8JobCredentialSSHActivatorRequiresSSHAgentMode(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{
		sandboxruntime.JobCredentialDeliveryModeHTTPProxy,
		sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeHTTPProxy, ServiceID: "azure-openai-responses-v1",
	})
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialSSHRelayInvalid) {
		t.Fatalf("http activate = %#v, %v", handle, err)
	}
	if registry.acquires != 0 {
		t.Fatalf("http mode acquired a lease: %d", registry.acquires)
	}
	handle, err = activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[1], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
		t.Fatalf("ssh activate = %#v, %v", handle, err)
	}
	if registry.acquires != 1 {
		t.Fatalf("ssh acquires = %d, want 1", registry.acquires)
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorAcquiresExactLeaseAndPolicy(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	binding := sandboxruntime.JobCredentialBindingRequest{ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent}
	handle, err := activator.Activate(context.Background(), identity, binding)
	if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
		t.Fatalf("Activate = %#v, %v", handle, err)
	}
	if handle.PolicyID() != "ssh-policy-1" || handle.PolicyRevision() != 4 {
		t.Fatalf("policy = %q/%d", handle.PolicyID(), handle.PolicyRevision())
	}
	if registry.acquires != 1 || len(registry.leases) != 1 {
		t.Fatalf("acquires=%d leases=%d", registry.acquires, len(registry.leases))
	}
	request := registry.lastRequest
	if !sshrelay.ConfigIdentityEqual(request.ConfigIdentity(), config) {
		t.Fatal("acquire used a different registry entry identity")
	}
	if string(request.RuntimeGeneration()) != identity.RuntimeGeneration ||
		string(request.ProcessGeneration()) != identity.FirecrackerProcessGeneration ||
		string(request.VsockGeneration()) != identity.VsockGeneration ||
		string(request.WorkerJobGeneration()) != identity.WorkerJobID ||
		string(request.ActivationGeneration()) != identity.ActivationGeneration ||
		string(request.RelayGeneration()) != identity.CredentialGeneration {
		t.Fatalf("acquire generations = %#v", request)
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorRenewAndRevokeUseExactLease(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if registry.leases[0].closes != 1 || !registry.leases[0].closed {
		t.Fatalf("revoke closed lease = %+v", registry.leases[0])
	}
	if err := handle.Renew(context.Background()); !errors.Is(err, ErrL8JobCredentialSSHRelayInvalid) {
		t.Fatalf("renew after revoke = %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("idempotent revoke = %v", err)
	}
	if registry.leases[0].closes != 1 {
		t.Fatalf("idempotent revoke reclosed lease: %d", registry.leases[0].closes)
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorFailedRevokeKeepsOwnership(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	registry.closeErr = errors.New("token=ssh-secret path=/run/user/1000/agent.sock peer=ssh-ed25519-canary")
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = handle.Revoke(context.Background())
	if !errors.Is(err, ErrL8JobCredentialSSHRelayUnavailable) {
		t.Fatalf("failed revoke = %v", err)
	}
	l8JobCredentialSSHRelayAssertSafeError(t, err)
	if registry.leases[0].closed {
		t.Fatal("failed revoke dropped lease ownership")
	}
	registry.closeErr = nil
	if err := handle.Renew(context.Background()); err != nil {
		t.Fatalf("renew after failed revoke: %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("retry revoke: %v", err)
	}
	if !registry.leases[0].closed || registry.leases[0].closes != 2 {
		t.Fatalf("retry revoke lease = %+v", registry.leases[0])
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorDeniesSerialization(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if err != nil {
		t.Fatal(err)
	}
	values := []any{activator, handle, &ProductionL8JobCredentialSSHRelayActivator{}, &productionL8JobCredentialSSHRelayHandle{policyID: "ssh-policy-1"}}
	for _, value := range values {
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8JobCredentialSSHRelaySerialization) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		if err := json.Unmarshal([]byte(`{}`), value); !errors.Is(err, ErrL8JobCredentialSSHRelaySerialization) {
			t.Fatalf("json.Unmarshal(%T) = %v", value, err)
		}
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if rendered != l8JobCredentialSSHRelayValuePlaceholder {
				t.Fatalf("format %T = %q", value, rendered)
			}
			for _, seed := range []string{"ssh-policy-1", "/run/user/", "agent.sock", "ssh-ed25519"} {
				if strings.Contains(rendered, seed) {
					t.Fatalf("format leaked %q: %q", seed, rendered)
				}
			}
		}
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorRedactsErrors(t *testing.T) {
	registry, config := l8JobCredentialSSHRelayFakeRegistry(t)
	canary := "token=ssh-secret path=/run/user/1000/agent.sock peer=ssh-ed25519-canary SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	registry.err = errors.New(canary)
	activator, err := newProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if !l8JobCredentialRuntimeValueIsNil(handle) || !errors.Is(err, ErrL8JobCredentialSSHRelayUnavailable) {
		t.Fatalf("canary activate = %#v, %v", handle, err)
	}
	l8JobCredentialSSHRelayAssertSafeError(t, err)
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("activate leaked canary: %v", err)
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorWrapsDaemonRegistry(t *testing.T) {
	config, err := sshrelay.NewConfigIdentity("entry-a", "daemon-a", "entry-generation-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	policyIdentity, err := sshrelay.NewPolicyIdentity("ssh-policy-1", 4)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := sshrelay.NewLivePolicy(policyIdentity, []sshrelay.PolicyRule{{
		Fingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmED25519,
		Flags:        []credentialprotocol.SSHAgentRSAFlags{0},
	}})
	if err != nil {
		t.Fatal(err)
	}
	entry := &l8JobCredentialSSHRelayEntryFake{identity: config, policy: policy}
	registry, err := sshrelay.NewRegistry(sshrelay.RegistryOptions{
		DaemonGeneration: "daemon-a",
		Entries:          []sshrelay.LiveHostAgentEntry{entry},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close(context.Background()) })
	activator, err := NewProductionL8JobCredentialSSHRelayActivator(registry, config)
	if err != nil {
		t.Fatal(err)
	}
	identity := l8JobCredentialSSHRelayIdentity(t, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeSSHAgent})
	handle, err := activator.Activate(context.Background(), identity, sandboxruntime.JobCredentialBindingRequest{
		ID: identity.BindingIDs[0], Mode: sandboxruntime.JobCredentialDeliveryModeSSHAgent,
	})
	if err != nil || l8JobCredentialRuntimeValueIsNil(handle) {
		t.Fatalf("Activate through sshrelay.Registry = %#v, %v", handle, err)
	}
	if handle.PolicyID() != "ssh-policy-1" || handle.PolicyRevision() != 4 {
		t.Fatalf("policy = %q/%d", handle.PolicyID(), handle.PolicyRevision())
	}
	if entry.opens != 0 {
		t.Fatalf("activator opened an agent connection: %d", entry.opens)
	}
	if err := handle.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := handle.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if entry.opens != 0 {
		t.Fatalf("renew/revoke opened an agent connection: %d", entry.opens)
	}
}

func TestProductionL8JobCredentialSSHRelayActivatorRejectsInvalidConstructor(t *testing.T) {
	config, err := sshrelay.NewConfigIdentity("entry-a", "daemon-a", "entry-generation-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *sshrelay.Registry
	if activator, ctorErr := NewProductionL8JobCredentialSSHRelayActivator(nil, config); activator != nil || !errors.Is(ctorErr, ErrL8JobCredentialSSHRelayInvalid) {
		t.Fatalf("nil registry = %#v, %v", activator, ctorErr)
	}
	if activator, ctorErr := NewProductionL8JobCredentialSSHRelayActivator(typedNil, config); activator != nil || !errors.Is(ctorErr, ErrL8JobCredentialSSHRelayInvalid) {
		t.Fatalf("typed-nil registry = %#v, %v", activator, ctorErr)
	}
	if activator, ctorErr := NewProductionL8JobCredentialSSHRelayActivator(&sshrelay.Registry{}, sshrelay.ConfigIdentity{}); activator != nil || !errors.Is(ctorErr, ErrL8JobCredentialSSHRelayInvalid) {
		t.Fatalf("zero config = %#v, %v", activator, ctorErr)
	}
}

func l8JobCredentialSSHRelayIdentity(t *testing.T, modes []sandboxruntime.JobCredentialDeliveryMode) sandboxruntime.JobCredentialIdentity {
	t.Helper()
	seed := l8JobCredentialRuntimeSeed(t, l8JobCredentialRuntimeNow(), modes)
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func l8JobCredentialSSHRelayFakeRegistry(t *testing.T) (*l8JobCredentialSSHRelayRegistryFake, sshrelay.ConfigIdentity) {
	t.Helper()
	config, err := sshrelay.NewConfigIdentity("entry-a", "daemon-a", "entry-generation-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := sshrelay.NewPolicyIdentity("ssh-policy-1", 4)
	if err != nil {
		t.Fatal(err)
	}
	return &l8JobCredentialSSHRelayRegistryFake{config: config, policy: policy}, config
}

func l8JobCredentialSSHRelayAssertSafeError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := err.Error()
	for _, forbidden := range []string{
		"ssh-secret", "/run/user/", "agent.sock", "ssh-ed25519-canary", "SHA256:",
		"token=", "/private/", "OPENAI_API_KEY", "sk_live",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}

type l8JobCredentialSSHRelayRegistryFake struct {
	mu          sync.Mutex
	config      sshrelay.ConfigIdentity
	policy      sshrelay.PolicyIdentity
	acquires    int
	lastRequest sshrelay.AcquireRequest
	err         error
	closeErr    error
	leases      []*l8JobCredentialSSHRelayLeaseFake
}

func (fake *l8JobCredentialSSHRelayRegistryFake) Acquire(_ context.Context, request sshrelay.AcquireRequest) (sshrelay.Lease, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.acquires++
	fake.lastRequest = request
	if fake.err != nil {
		return nil, fake.err
	}
	lease := &l8JobCredentialSSHRelayLeaseFake{parent: fake, config: fake.config, policy: fake.policy}
	fake.leases = append(fake.leases, lease)
	return lease, nil
}

type l8JobCredentialSSHRelayLeaseFake struct {
	parent *l8JobCredentialSSHRelayRegistryFake
	config sshrelay.ConfigIdentity
	policy sshrelay.PolicyIdentity
	mu     sync.Mutex
	closes int
	closed bool
}

func (lease *l8JobCredentialSSHRelayLeaseFake) Identity() sshrelay.ConfigIdentity {
	return lease.config
}
func (lease *l8JobCredentialSSHRelayLeaseFake) PolicyIdentity() sshrelay.PolicyIdentity {
	return lease.policy
}
func (*l8JobCredentialSSHRelayLeaseFake) OpenVerifiedConnection(context.Context) (sshrelay.VerifiedAgentConnection, error) {
	panic("ssh relay activator must not open agent connections")
}
func (lease *l8JobCredentialSSHRelayLeaseFake) Close(context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.closes++
	if lease.parent.closeErr != nil {
		return lease.parent.closeErr
	}
	lease.closed = true
	return nil
}

type l8JobCredentialSSHRelayEntryFake struct {
	identity sshrelay.ConfigIdentity
	policy   sshrelay.LivePolicy
	opens    int
}

func (entry *l8JobCredentialSSHRelayEntryFake) Identity() sshrelay.ConfigIdentity {
	return entry.identity
}
func (entry *l8JobCredentialSSHRelayEntryFake) Policy() sshrelay.LivePolicy { return entry.policy }
func (entry *l8JobCredentialSSHRelayEntryFake) Open(context.Context) (sshrelay.AgentConnection, error) {
	entry.opens++
	return nil, errors.New("test host-agent entry does not open agents")
}
func (*l8JobCredentialSSHRelayEntryFake) VerifyPeer(context.Context, sshrelay.AgentConnection) (sshrelay.PeerProof, error) {
	return sshrelay.PeerProof{}, errors.New("test host-agent entry does not verify peers")
}
