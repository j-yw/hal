package l7network

import (
	"errors"
	"net"
	"os"
	"strconv"
)

const (
	launchInterfaceID    = "net1"
	launchGuestInterface = "eth0"
)

type launchDescriptorSeal struct{}

var activeLaunchDescriptorSeal = &launchDescriptorSeal{}

// LaunchDescriptor is an opaque live-only handoff of the exact prepared TAP,
// static guest network, proxy mapping, and proof generations. Its raw values
// are available only through explicit methods and never through JSON.
type LaunchDescriptor struct {
	seal     *launchDescriptorSeal
	identity Identity
	spec     tapSpec
}

func (d LaunchDescriptor) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (d LaunchDescriptor) NetworkInterface() (interfaceID, hostDeviceName, guestMAC string, ok bool) {
	if !d.valid() {
		return "", "", "", false
	}
	return launchInterfaceID, d.spec.name, d.spec.mac, true
}

func (d LaunchDescriptor) StaticNetwork() (
	guestInterfaceName, ipv4Address, ipv4Gateway, ipv6Address, ipv6Gateway, proxyURL string,
	ok bool,
) {
	if !d.valid() {
		return "", "", "", "", "", "", false
	}
	return launchGuestInterface,
		d.spec.guestIPv4Prefix.String(), d.spec.gatewayIPv4.String(),
		d.spec.guestIPv6Prefix.String(), d.spec.gatewayIPv6.String(),
		"http://" + net.JoinHostPort(d.spec.proxyAddress.String(), strconv.Itoa(int(d.spec.proxyPort))),
		true
}

func (d LaunchDescriptor) ProofGenerations() (topologyGeneration, runtimeGeneration string, ok bool) {
	if !d.valid() {
		return "", "", false
	}
	return d.identity.TopologyGenerationID, d.identity.RuntimeGenerationID, true
}

func (d LaunchDescriptor) valid() bool {
	return d.seal == activeLaunchDescriptorSeal && validIdentity(d.identity) &&
		d.spec.proxyAddress.IsValid() && d.spec.proxyPort != 0 &&
		d.spec == staticTAPSpec(d.identity, d.spec.proxyAddress, d.spec.proxyPort)
}

// LaunchDescriptor returns one immutable live-only view of the exact prepared
// topology generation. It performs no live calls or mutation.
func (s *Session) LaunchDescriptor(identity Identity) (LaunchDescriptor, error) {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return LaunchDescriptor{}, ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.launchHandoffReadyLocked() {
		return LaunchDescriptor{}, ErrProofMismatch
	}
	return LaunchDescriptor{seal: activeLaunchDescriptorSeal, identity: identity, spec: s.tapSpec}, nil
}

type namespaceProcessDuplicator interface {
	DuplicateForNamespaceProcess() (*os.File, *os.File, error)
}

// ProcessNamespace is a revocable duplicate-only view of session-owned
// namespace descriptors. The session retains and closes the original borrow.
type ProcessNamespace struct {
	session  *Session
	identity Identity
}

func (*ProcessNamespace) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ProcessNamespace returns a wrapper that validates the exact live session on
// every duplicate. It never transfers ownership of retained session files.
func (s *Session) ProcessNamespace(identity Identity) (*ProcessNamespace, error) {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return nil, ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.launchHandoffReadyLocked() {
		return nil, ErrProofMismatch
	}
	provider, ok := s.namespace.(namespaceProcessDuplicator)
	if !ok || interfaceIsNil(provider) {
		return nil, ErrTopologyPrepareFailed
	}
	return &ProcessNamespace{session: s, identity: identity}, nil
}

func (p *ProcessNamespace) DuplicateForNamespaceProcess() (*os.File, *os.File, error) {
	if p == nil || p.session == nil || p.identity != p.session.identity || !validIdentity(p.identity) {
		return nil, nil, ErrIdentityMismatch
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.launchHandoffReadyLocked() {
		return nil, nil, ErrProofMismatch
	}
	provider, ok := s.namespace.(namespaceProcessDuplicator)
	if !ok || interfaceIsNil(provider) {
		return nil, nil, ErrTopologyPrepareFailed
	}
	user, network, err := provider.DuplicateForNamespaceProcess()
	if err != nil || !validProcessNamespaceDuplicates(user, network) {
		return nil, nil, containProcessNamespaceDuplicates(user, network)
	}
	return user, network, nil
}

func (s *Session) launchHandoffReadyLocked() bool {
	if s == nil || s.metadata.Identity != s.identity || s.metadata.Status != StatusHostPrepared ||
		!s.metadata.StructuralInspected || !s.metadata.TAPInspected || !s.metadata.RulesInspected ||
		s.quarantined || !s.rulesPresent || s.rulesRemoved || s.retainedCleanup != retainedCleanupNone ||
		interfaceIsNil(s.namespace) || !s.tap.valid(s.tapSpec) {
		return false
	}
	expected := staticTAPSpec(s.identity, s.tapSpec.proxyAddress, s.tapSpec.proxyPort)
	return s.tapSpec == expected
}

func validProcessNamespaceDuplicates(user, network *os.File) bool {
	return user != nil && network != nil && user != network &&
		user.Fd() > 2 && network.Fd() > 2 && user.Fd() != network.Fd()
}

func containProcessNamespaceDuplicates(user, network *os.File) error {
	var closeErr error
	if user != nil {
		closeErr = errors.Join(closeErr, user.Close())
	}
	if network != nil && network != user {
		closeErr = errors.Join(closeErr, network.Close())
	}
	if closeErr != nil {
		return errors.Join(ErrTopologyPrepareFailed, ErrCleanupIncomplete)
	}
	return ErrTopologyPrepareFailed
}
