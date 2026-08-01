package l7network

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
)

func TestFirecrackerHostTopologyLaunchHandoffIsOpaqueAndExact(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	session := preparedLaunchHandoffSession(identity, spec, &fakeProcessNamespaceLease{})

	descriptor, err := session.LaunchDescriptor(identity)
	if err != nil {
		t.Fatal(err)
	}
	interfaceID, hostDevice, guestMAC, ok := descriptor.NetworkInterface()
	if !ok || interfaceID != "net1" || hostDevice != spec.name || guestMAC != spec.mac {
		t.Fatalf("NetworkInterface() = %q, %q, %q, %t", interfaceID, hostDevice, guestMAC, ok)
	}
	guestInterface, ipv4, ipv4Gateway, ipv6, ipv6Gateway, proxyURL, ok := descriptor.StaticNetwork()
	if !ok || guestInterface != "eth0" || ipv4 != spec.guestIPv4Prefix.String() || ipv4Gateway != spec.gatewayIPv4.String() ||
		ipv6 != spec.guestIPv6Prefix.String() || ipv6Gateway != spec.gatewayIPv6.String() ||
		proxyURL != "http://192.0.2.2:43123" {
		t.Fatalf("StaticNetwork() = %q, %q, %q, %q, %q, %q, %t", guestInterface, ipv4, ipv4Gateway, ipv6, ipv6Gateway, proxyURL, ok)
	}
	topologyGeneration, runtimeGeneration, ok := descriptor.ProofGenerations()
	if !ok || topologyGeneration != identity.TopologyGenerationID || runtimeGeneration != identity.RuntimeGenerationID {
		t.Fatalf("ProofGenerations() = %q, %q, %t", topologyGeneration, runtimeGeneration, ok)
	}
	payload, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "{}" {
		t.Fatalf("LaunchDescriptor JSON = %s, want opaque object", payload)
	}
	for _, raw := range []string{spec.name, spec.mac, spec.proxyAddress.String(), spec.guestIPv4Prefix.String()} {
		if strings.Contains(string(payload), raw) {
			t.Fatalf("LaunchDescriptor JSON leaked %q in %s", raw, payload)
		}
	}
}

func TestFirecrackerHostTopologyNamespaceHandoffDuplicatesAndRevokes(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	lease := &fakeProcessNamespaceLease{}
	session := preparedLaunchHandoffSession(identity, spec, lease)

	provider, err := session.ProcessNamespace(identity)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "{}" {
		t.Fatalf("ProcessNamespace JSON = %s, want opaque object", payload)
	}
	user, network, err := provider.DuplicateForNamespaceProcess()
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || network == nil || user.Fd() <= 2 || network.Fd() <= 2 || user.Fd() == network.Fd() {
		t.Fatalf("namespace duplicates = %#v, %#v", user, network)
	}
	if err := errors.Join(user.Close(), network.Close()); err != nil {
		t.Fatal(err)
	}
	if lease.duplicateCalls != 1 || lease.closeCalls != 0 {
		t.Fatalf("namespace calls = duplicate %d, close %d", lease.duplicateCalls, lease.closeCalls)
	}

	session.mu.Lock()
	session.quarantined = true
	session.metadata = Metadata{Identity: identity, Status: StatusQuarantined}
	session.mu.Unlock()
	if _, _, err := provider.DuplicateForNamespaceProcess(); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("DuplicateForNamespaceProcess() after quarantine = %v, want ErrProofMismatch", err)
	}
	if lease.duplicateCalls != 1 || lease.closeCalls != 0 {
		t.Fatalf("revoked namespace calls = duplicate %d, close %d", lease.duplicateCalls, lease.closeCalls)
	}
}

func TestFirecrackerHostTopologyLaunchHandoffRejectsMismatchAndZeroValues(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	session := preparedLaunchHandoffSession(identity, spec, &fakeProcessNamespaceLease{})
	mismatch := identity
	mismatch.RuntimeGenerationID = "other-runtime-generation"
	if _, err := session.LaunchDescriptor(mismatch); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("LaunchDescriptor(mismatch) = %v", err)
	}
	if _, err := session.ProcessNamespace(mismatch); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("ProcessNamespace(mismatch) = %v", err)
	}
	var descriptor LaunchDescriptor
	if _, _, _, ok := descriptor.NetworkInterface(); ok {
		t.Fatal("zero LaunchDescriptor produced network interface values")
	}
	if _, _, ok := descriptor.ProofGenerations(); ok {
		t.Fatal("zero LaunchDescriptor produced proof generations")
	}
}

func preparedLaunchHandoffSession(identity Identity, spec tapSpec, namespace NamespaceLease) *Session {
	return &Session{
		identity: identity, namespace: namespace, tapSpec: spec,
		tap:          tapState{name: spec.name, generation: spec.generation, fingerprint: spec.fingerprint(), ifIndex: 41},
		metadata:     Metadata{Identity: identity, Status: StatusHostPrepared, StructuralInspected: true, TAPInspected: true, RulesInspected: true},
		rulesPresent: true,
	}
}

type fakeProcessNamespaceLease struct {
	duplicateCalls int
	closeCalls     int
}

func (*fakeProcessNamespaceLease) RuleNamespace() linuxrules.NamespaceHandle {
	return linuxrules.NewNamespaceHandle(10, 11)
}

func (l *fakeProcessNamespaceLease) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	l.duplicateCalls++
	user, err := os.Open(os.DevNull)
	if err != nil {
		return nil, nil, err
	}
	network, err := os.Open(os.DevNull)
	if err != nil {
		_ = user.Close()
		return nil, nil, err
	}
	return user, network, nil
}

func (l *fakeProcessNamespaceLease) Close() error {
	l.closeCalls++
	return nil
}
