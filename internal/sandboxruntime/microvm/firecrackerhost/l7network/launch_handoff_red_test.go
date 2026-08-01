package l7network

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestFirecrackerHostTopologyNamespaceDuplicateSerializesRevocation(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	lease := &gatedProcessNamespaceLease{started: make(chan struct{}), release: make(chan struct{})}
	session := preparedLaunchHandoffSession(identity, spec, lease)
	provider, err := session.ProcessNamespace(identity)
	if err != nil {
		t.Fatal(err)
	}

	type duplicateResult struct {
		user    *os.File
		network *os.File
		err     error
	}
	duplicated := make(chan duplicateResult, 1)
	go func() {
		user, network, duplicateErr := provider.DuplicateForNamespaceProcess()
		duplicated <- duplicateResult{user: user, network: network, err: duplicateErr}
	}()
	select {
	case <-lease.started:
	case <-time.After(time.Second):
		t.Fatal("namespace duplication did not reach the retained lease")
	}
	revoked := make(chan struct{})
	go func() {
		session.mu.Lock()
		session.quarantined = true
		session.metadata = Metadata{Identity: identity, Status: StatusQuarantined}
		session.mu.Unlock()
		close(revoked)
	}()
	select {
	case <-revoked:
		t.Fatal("revocation crossed an in-flight namespace duplication")
	default:
	}
	close(lease.release)
	result := <-duplicated
	if result.err != nil || result.user == nil || result.network == nil {
		t.Fatalf("serialized duplicate = %#v", result)
	}
	if err := errors.Join(result.user.Close(), result.network.Close()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("revocation remained blocked after duplication returned")
	}
	if _, _, err := provider.DuplicateForNamespaceProcess(); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("post-revocation duplicate = %v, want ErrProofMismatch", err)
	}
}

func TestFirecrackerHostTopologyNamespaceDuplicateContainsPartialError(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	lease := &partialProcessNamespaceLease{}
	session := preparedLaunchHandoffSession(identity, spec, lease)
	provider, err := session.ProcessNamespace(identity)
	if err != nil {
		t.Fatal(err)
	}
	user, network, err := provider.DuplicateForNamespaceProcess()
	if !errors.Is(err, ErrTopologyPrepareFailed) || user != nil || network != nil {
		t.Fatalf("partial duplicate = %#v, %#v, %v", user, network, err)
	}
	if err.Error() != ErrTopologyPrepareFailed.Error() {
		t.Fatalf("partial duplicate error = %q, want sanitized sentinel", err)
	}
	if lease.partial == nil {
		t.Fatal("partial duplicate was not created")
	}
	if _, statErr := lease.partial.Stat(); statErr == nil {
		t.Fatal("partial duplicate remained open")
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

type gatedProcessNamespaceLease struct {
	fakeProcessNamespaceLease
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

func (l *gatedProcessNamespaceLease) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	l.startOnce.Do(func() { close(l.started) })
	<-l.release
	return l.fakeProcessNamespaceLease.DuplicateForNamespaceProcess()
}

type partialProcessNamespaceLease struct {
	fakeProcessNamespaceLease
	partial *os.File
}

func (l *partialProcessNamespaceLease) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	partial, err := os.Open(os.DevNull)
	if err != nil {
		return nil, nil, err
	}
	l.partial = partial
	return partial, nil, errors.New("private namespace duplicate failure at /proc/self/fd/77")
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
