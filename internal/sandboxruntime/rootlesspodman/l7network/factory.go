// Package l7network composes the explicitly enabled rootless-Podman L7
// policy-proxy, exact runtime namespace, raw-packet verifier, and Linux rule
// adapters. The parent rootlesspodman package remains independent of concrete
// Linux enforcement implementations.
package l7network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

var (
	ErrInvalidConfiguration = errors.New("rootless Podman L7 composition invalid configuration")
	ErrProxyUnavailable     = errors.New("rootless Podman L7 proxy unavailable")
	ErrNamespaceUnverified  = errors.New("rootless Podman L7 namespace unverified")
	ErrRuleProofUnverified  = errors.New("rootless Podman L7 rule proof unverified")
	ErrIdentityMismatch     = errors.New("rootless Podman L7 identity mismatch")
	ErrQuarantineFailed     = errors.New("rootless Podman L7 quarantine failed")
	ErrCleanupIncomplete    = errors.New("rootless Podman L7 cleanup incomplete")
	ErrTopologyCollision    = errors.New("rootless Podman L7 topology collision")
)

const defaultCleanupTimeout = 5 * time.Second

// ProxyGeneration is an opaque live-only handle to one listener generation.
type ProxyGeneration interface {
	Address() string
	Loss() <-chan struct{}
}

// Proxy owns exact-generation listener lifecycle. Stop must reject a stale
// generation rather than stopping a replacement listener.
type Proxy interface {
	Start(context.Context, networkenforcement.Plan) (ProxyGeneration, error)
	Endpoint(ProxyGeneration) (string, error)
	Active(context.Context, networkenforcement.Plan, ProxyGeneration) error
	Stop(context.Context, networkenforcement.Plan, ProxyGeneration) error
}

type RuleAdapter interface {
	ApplyAndInspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error)
	Inspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error)
	Quarantine(context.Context, linuxrules.ExpectedRuleSet) error
	Cleanup(context.Context, linuxrules.ExpectedRuleSet) error
}

// NamespaceResolution retains the exact Podman-owned namespace descriptors
// and the structurally inspected live link parameters used by the rule model.
type NamespaceResolution struct {
	Namespace           linuxrules.NamespaceHandle `json:"-"`
	InterfaceName       string                     `json:"-"`
	WorkloadIPv6Address string                     `json:"-"`
	GatewayIPv6Address  string                     `json:"-"`
	IPv6PrefixBits      uint8                      `json:"-"`
	Close               io.Closer                  `json:"-"`
}

type NamespaceResolver interface {
	Resolve(context.Context, rootlesspodman.NetworkTopologyTargetRequest) (NamespaceResolution, error)
}

type RawPacketVerifierFactory func(rootlesspodman.NetworkTopologyTargetRequest) (linuxrules.RawPacketIsolationVerifier, error)

type FactoryOptions struct {
	Identity                 rootlesspodman.NetworkTopologyIdentity
	Plan                     networkenforcement.Plan
	Proxy                    Proxy
	NamespaceResolver        NamespaceResolver
	Rules                    RuleAdapter
	RawPacketVerifierFactory RawPacketVerifierFactory
	GuestProxyAddress        string
	TableName                string
	CleanupTimeout           time.Duration
}

type Factory struct {
	mu      sync.Mutex
	options FactoryOptions
	current *Session
}

func NewFactory(options FactoryOptions) (*Factory, error) {
	options.Plan = networkenforcement.SanitizePlan(options.Plan)
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	guestAddress, guestErr := netip.ParseAddr(strings.TrimSpace(options.GuestProxyAddress))
	if !validIdentity(options.Identity) || !planMatchesIdentity(options.Plan, options.Identity) ||
		options.Proxy == nil || options.NamespaceResolver == nil || options.Rules == nil || options.RawPacketVerifierFactory == nil ||
		guestErr != nil || guestAddress.IsUnspecified() || guestAddress.IsLoopback() || guestAddress.IsMulticast() ||
		!safeNFTName(options.TableName) || options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	options.GuestProxyAddress = guestAddress.String()
	return &Factory{options: options}, nil
}

func (f *Factory) PrepareNetworkTopology(ctx context.Context, request rootlesspodman.NetworkTopologyPrepareRequest) (rootlesspodman.NetworkTopologyPreparation, error) {
	if f == nil || !safeID(request.SandboxName) {
		return rootlesspodman.NetworkTopologyPreparation{}, ErrInvalidConfiguration
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil && !f.current.isCleaned() {
		return rootlesspodman.NetworkTopologyPreparation{}, ErrTopologyCollision
	}
	generation, err := f.options.Proxy.Start(ctx, f.options.Plan)
	if err != nil || generation == nil || generation.Loss() == nil {
		if generation != nil {
			if stopErr := f.stopPartial(generation); stopErr != nil {
				return rootlesspodman.NetworkTopologyPreparation{}, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
			}
		}
		return rootlesspodman.NetworkTopologyPreparation{}, ErrProxyUnavailable
	}
	endpoint, err := f.options.Proxy.Endpoint(generation)
	if err != nil {
		if f.stopPartial(generation) != nil {
			return rootlesspodman.NetworkTopologyPreparation{}, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return rootlesspodman.NetworkTopologyPreparation{}, ErrProxyUnavailable
	}
	_, port, err := validatedEndpoint(endpoint, f.options.GuestProxyAddress)
	if err != nil {
		if f.stopPartial(generation) != nil {
			return rootlesspodman.NetworkTopologyPreparation{}, errors.Join(ErrProxyUnavailable, ErrCleanupIncomplete)
		}
		return rootlesspodman.NetworkTopologyPreparation{}, ErrProxyUnavailable
	}
	session := &Session{
		identity: f.options.Identity, plan: f.options.Plan, proxy: f.options.Proxy, generation: generation,
		resolver: f.options.NamespaceResolver, rules: f.options.Rules, rawPacketVerifierFactory: f.options.RawPacketVerifierFactory,
		guestProxyAddress: f.options.GuestProxyAddress, proxyPort: port, tableName: f.options.TableName,
		cleanupTimeout: f.options.CleanupTimeout,
	}
	f.current = session
	return rootlesspodman.NetworkTopologyPreparation{
		Identity:   f.options.Identity,
		CreateArgs: []string{"--network", "pasta:--no-map-gw,--map-host-loopback=" + f.options.GuestProxyAddress + ",-t,none,-u,none,-T,none,-U,none"},
		Session:    session,
	}, nil
}

func (f *Factory) stopPartial(generation ProxyGeneration) error {
	ctx, cancel := context.WithTimeout(context.Background(), f.options.CleanupTimeout)
	defer cancel()
	return f.options.Proxy.Stop(ctx, f.options.Plan, generation)
}

type Session struct {
	mu                       sync.Mutex
	identity                 rootlesspodman.NetworkTopologyIdentity
	plan                     networkenforcement.Plan
	proxy                    Proxy
	generation               ProxyGeneration
	resolver                 NamespaceResolver
	rules                    RuleAdapter
	rawPacketVerifierFactory RawPacketVerifierFactory
	guestProxyAddress        string
	proxyPort                uint16
	tableName                string
	cleanupTimeout           time.Duration
	resolution               NamespaceResolution
	expected                 linuxrules.ExpectedRuleSet
	proof                    rootlesspodman.NetworkTopologyProof
	prepared                 bool
	active                   bool
	quarantined              bool
	cleaned                  bool
	rulesCleaned             bool
	proxyStopped             bool
}

func (s *Session) Activate(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) (rootlesspodman.NetworkTopologyProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || s.active || !s.matches(request) {
		return rootlesspodman.NetworkTopologyProof{}, ErrIdentityMismatch
	}
	if err := s.proxy.Active(ctx, s.plan, s.generation); err != nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrProxyUnavailable
	}
	resolution, err := s.resolver.Resolve(ctx, request)
	if err != nil || resolution.Close == nil {
		if resolution.Close != nil {
			s.resolution = resolution
			if closeErr := resolution.Close.Close(); closeErr == nil {
				s.resolution.Close = nil
			}
		}
		return rootlesspodman.NetworkTopologyProof{}, ErrNamespaceUnverified
	}
	s.resolution = resolution
	correlation := correlationFromIdentity(s.identity)
	rawPacketVerifier, err := s.rawPacketVerifierFactory(request)
	if err != nil || rawPacketVerifier == nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrNamespaceUnverified
	}
	expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{
		Correlation: correlation, Profile: linuxrules.RuleProfileWorkloadOutput,
		Namespace: resolution.Namespace, TableName: s.tableName, InterfaceName: resolution.InterfaceName,
		ProxyAddress: s.guestProxyAddress, ProxyPort: s.proxyPort, RawPacketIsolation: rawPacketVerifier,
		WorkloadIPv6Address: resolution.WorkloadIPv6Address, GatewayIPv6Address: resolution.GatewayIPv6Address,
		IPv6PrefixBits: resolution.IPv6PrefixBits,
	})
	if err != nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrNamespaceUnverified
	}
	s.expected = expected
	s.prepared = true
	if err := s.proxy.Active(ctx, s.plan, s.generation); err != nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrProxyUnavailable
	}
	metadata, err := s.rules.ApplyAndInspect(ctx, expected)
	if err != nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrRuleProofUnverified
	}
	if err := s.proxy.Active(ctx, s.plan, s.generation); err != nil {
		return rootlesspodman.NetworkTopologyProof{}, ErrProxyUnavailable
	}
	proof, err := proofFromMetadata(s.identity, request, metadata)
	if err != nil {
		return rootlesspodman.NetworkTopologyProof{}, err
	}
	s.proof = proof
	s.active = true
	return proof, nil
}

func (s *Session) Inspect(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) (rootlesspodman.NetworkTopologyProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || !s.active || !s.prepared || !s.matches(request) {
		return rootlesspodman.NetworkTopologyProof{}, ErrIdentityMismatch
	}
	if err := s.proxy.Active(ctx, s.plan, s.generation); err != nil {
		s.active = false
		return rootlesspodman.NetworkTopologyProof{}, ErrProxyUnavailable
	}
	metadata, err := s.rules.Inspect(ctx, s.expected)
	if err != nil {
		s.active = false
		return rootlesspodman.NetworkTopologyProof{}, ErrRuleProofUnverified
	}
	if err := s.proxy.Active(ctx, s.plan, s.generation); err != nil {
		s.active = false
		return rootlesspodman.NetworkTopologyProof{}, ErrProxyUnavailable
	}
	proof, err := proofFromMetadata(s.identity, request, metadata)
	if err != nil || proof.RuleDigest != s.proof.RuleDigest {
		s.active = false
		return rootlesspodman.NetworkTopologyProof{}, ErrRuleProofUnverified
	}
	s.proof = proof
	return proof, nil
}

func (s *Session) ProxyEnvironment(request rootlesspodman.NetworkTopologyTargetRequest) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || !s.active || !s.matches(request) {
		return nil
	}
	select {
	case <-s.generation.Loss():
		s.active = false
		return nil
	default:
	}
	endpoint := "http://" + net.JoinHostPort(s.guestProxyAddress, strconv.Itoa(int(s.proxyPort)))
	return map[string]string{"HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint, "http_proxy": endpoint, "https_proxy": endpoint}
}

func (s *Session) Revoke(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	s.proof = rootlesspodman.NetworkTopologyProof{}
	if s.cleaned || !s.matches(request) {
		return ErrIdentityMismatch
	}
	if !s.prepared || s.quarantined {
		return nil
	}
	if err := s.rules.Quarantine(ctx, s.expected); err != nil {
		return ErrQuarantineFailed
	}
	s.quarantined = true
	return nil
}

func (s *Session) Cleanup(_ context.Context, request rootlesspodman.NetworkTopologyTargetRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	s.proof = rootlesspodman.NetworkTopologyProof{}
	if s.cleaned {
		return nil
	}
	if !s.matchesAllowEmptyTarget(request) {
		return ErrIdentityMismatch
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cleanupTimeout)
	defer cancel()
	var result error
	if s.prepared && !s.rulesCleaned {
		if err := s.rules.Cleanup(ctx, s.expected); err != nil {
			result = errors.Join(result, ErrCleanupIncomplete)
		} else {
			s.rulesCleaned = true
		}
	}
	if s.resolution.Close != nil {
		if err := s.resolution.Close.Close(); err != nil {
			result = errors.Join(result, ErrCleanupIncomplete)
		} else {
			s.resolution.Close = nil
		}
	}
	if !s.proxyStopped {
		if err := s.proxy.Stop(ctx, s.plan, s.generation); err != nil {
			result = errors.Join(result, ErrCleanupIncomplete)
		} else {
			s.proxyStopped = true
		}
	}
	if result == nil {
		s.cleaned = true
	}
	return result
}

func (s *Session) Loss() <-chan struct{} {
	if s == nil || s.generation == nil {
		return nil
	}
	return s.generation.Loss()
}

func (s *Session) isCleaned() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.cleaned }

func (s *Session) matches(request rootlesspodman.NetworkTopologyTargetRequest) bool {
	return request.Identity == s.identity && request.Target.ID != "" && request.Target.ID == request.Target.Runtime.RuntimeID &&
		request.Target.Runtime.Driver == rootlesspodman.DriverID && safeID(request.Target.ID) && safeID(request.Target.Name)
}

func (s *Session) matchesAllowEmptyTarget(request rootlesspodman.NetworkTopologyTargetRequest) bool {
	if request.Identity != s.identity {
		return false
	}
	if request.Target.ID == "" && request.Target.Runtime.RuntimeID == "" {
		return true
	}
	return s.matches(request)
}

func proofFromMetadata(identity rootlesspodman.NetworkTopologyIdentity, request rootlesspodman.NetworkTopologyTargetRequest, metadata networkenforcement.RuleLifecycleMetadata) (rootlesspodman.NetworkTopologyProof, error) {
	correlation := correlationFromIdentity(identity)
	metadata = networkenforcement.SanitizeRuleLifecycleMetadata(metadata)
	if metadata.Status != networkenforcement.LifecycleStatusActive || metadata.Correlation == nil ||
		!networkenforcement.EnforcementCorrelationsEqual(*metadata.Correlation, correlation) || metadata.Inspection == nil ||
		metadata.Inspection.Status != networkenforcement.RuleInspectionStatusInspected || metadata.Inspection.Correlation == nil ||
		!networkenforcement.EnforcementCorrelationsEqual(*metadata.Inspection.Correlation, correlation) || metadata.Inspection.RuleDigest == "" ||
		metadata.LinkLayerIsolation == nil || !networkenforcement.RawPacketIsolationProofMatches(*metadata.LinkLayerIsolation, correlation) ||
		len(metadata.WarningCodes) != 0 {
		return rootlesspodman.NetworkTopologyProof{}, ErrRuleProofUnverified
	}
	return rootlesspodman.NetworkTopologyProof{Identity: identity, RuntimeID: request.Target.Runtime.RuntimeID,
		RuleDigest: metadata.Inspection.RuleDigest, ProxyActive: true, RulesInspected: true}, nil
}

func validatedEndpoint(endpoint, guest string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, 0, ErrProxyUnavailable
	}
	address, err := netip.ParseAddr(host)
	guestAddress, guestErr := netip.ParseAddr(guest)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || guestErr != nil || portErr != nil || port == 0 || !address.IsLoopback() || address.Is4() != guestAddress.Is4() {
		return netip.Addr{}, 0, ErrProxyUnavailable
	}
	return address, uint16(port), nil
}

func validIdentity(identity rootlesspodman.NetworkTopologyIdentity) bool {
	if identity.RuntimeDriver != rootlesspodman.DriverID {
		return false
	}
	values := []string{identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeGenerationID,
		identity.PlanID, identity.PolicySnapshotID, identity.ProxySessionID, identity.ProxyGenerationID,
		identity.TopologyGenerationID, identity.RuleGenerationID}
	seen := map[string]bool{}
	for _, value := range values {
		if !safeID(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func planMatchesIdentity(plan networkenforcement.Plan, identity rootlesspodman.NetworkTopologyIdentity) bool {
	presetValid := plan.PolicySnapshot != nil && (plan.PolicySnapshot.Preset == networkenforcement.PolicyPresetDenyByDefault || plan.PolicySnapshot.Preset == networkenforcement.PolicyPresetAllowListed)
	return plan.ID == identity.PlanID && plan.PolicySnapshot != nil && plan.PolicySnapshot.ID == identity.PolicySnapshotID &&
		presetValid && plan.DefaultPosture == networkenforcement.DefaultPostureDenyByDefault &&
		plan.Proxy != nil && plan.Proxy.ProxySessionID == identity.ProxySessionID && plan.Proxy.Mechanism == networkenforcement.EnforcementMechanismProxy &&
		plan.Proxy.HTTP == networkenforcement.ProxyRoutingModeRouteViaProxy && plan.Proxy.HTTPS == networkenforcement.ProxyRoutingModeRouteViaProxy &&
		plan.Firewall != nil && plan.Firewall.Mode == networkenforcement.FirewallIntentModeApply && plan.Firewall.Mechanism == networkenforcement.EnforcementMechanismFirewall
}

func correlationFromIdentity(identity rootlesspodman.NetworkTopologyIdentity) networkenforcement.EnforcementCorrelation {
	return networkenforcement.EnforcementCorrelation{SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID}
}

func safeID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func safeNFTName(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for i, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') || (i == 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

type compositionError struct{ reason error }

func (e compositionError) Error() string {
	return fmt.Sprintf("rootless Podman L7 composition failed: %s", e.reason)
}
func (e compositionError) Unwrap() error { return e.reason }
