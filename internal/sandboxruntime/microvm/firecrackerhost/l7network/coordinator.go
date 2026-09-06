package l7network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

const (
	mappingInterfaceName = "pasta0"
	ruleTableName        = "hal_fc_l7"
)

type Coordinator struct {
	mu      sync.Mutex
	options Options
	current *Session
}

type Session struct {
	mu               sync.Mutex
	coordinator      *Coordinator
	identity         Identity
	plan             networkenforcement.Plan
	proxy            ProxyGeneration
	topologyIdentity linuxtopology.Identity
	topology         TopologySession
	namespace        NamespaceLease
	tapSpec          tapSpec
	tap              tapState
	expectedRules    linuxrules.ExpectedRuleSet
	journal          JournalLease
	metadata         Metadata
	rulesPresent     bool
	quarantined      bool
	rulesRemoved     bool
	tapRemoved       bool
	topologyRemoved  bool
	proxyStopped     bool
	journalRemoved   bool
	journalReleased  bool
	guestBinding     RunningGuestBinding
	guestSnapshot    runningGuestSnapshot
	preVMAbort       bool
	retainedCleanup  retainedCleanupMode
	proxyLoss        <-chan struct{}
	topologyLoss     <-chan linuxtopology.Loss
	loss             chan ProxyLossResult
	lossPublish      sync.Once
}

type retainedCleanupMode uint8

const (
	retainedCleanupNone retainedCleanupMode = iota
	retainedCleanupRollback
	retainedCleanupReleaseJournal
	retainedCleanupReleaseRecoveryJournal
	retainedCleanupReleaseRecoveryHandles
	retainedCleanupUnavailable
)

func New(input Options) (*Coordinator, error) {
	options := input
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	coordinator := &Coordinator{options: options}
	if !options.Enabled {
		return coordinator, nil
	}
	if interfaceIsNil(options.Proxy) || interfaceIsNil(options.Topology) || interfaceIsNil(options.TAP) || interfaceIsNil(options.Rules) ||
		interfaceIsNil(options.GuestIsolation) || interfaceIsNil(options.VMTermination) ||
		options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	if options.Journal == nil {
		journal, err := newFileJournalStore(options.StateDir)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		options.Journal = journal
		coordinator.options = options
	} else if interfaceIsNil(options.Journal) {
		return nil, ErrInvalidConfiguration
	}
	return coordinator, nil
}

func (c *Coordinator) Prepare(ctx context.Context, request PrepareRequest) (*Session, error) {
	if c == nil || !c.options.Enabled {
		return nil, ErrDisabled
	}
	if !validIdentity(request.Identity) || !planMatchesIdentity(request.Plan, request.Identity) {
		return nil, ErrInvalidIdentity
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrTopologyPrepareFailed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, ErrTopologyCollision
	}

	session := &Session{coordinator: c, identity: request.Identity, plan: networkenforcement.SanitizePlan(request.Plan),
		topologyIdentity: topologyIdentity(request.Identity), metadata: Metadata{Identity: request.Identity, Status: StatusPrepared},
		loss: make(chan ProxyLossResult, 1)}
	lease, err := c.options.Journal.Acquire(ctx, request.Identity)
	if err != nil {
		primary := sanitizeJournalAcquireError(err)
		if interfaceIsNil(lease) {
			return nil, primary
		}
		session.journal = lease
		return c.releasePrepareJournal(session, primary)
	}
	if interfaceIsNil(lease) {
		return c.retainPrepareCleanup(session, retainedCleanupUnavailable, ErrCleanupIncomplete)
	}
	session.journal = lease
	if stale, loadErr := lease.Load(); loadErr == nil {
		if stale.identity != request.Identity {
			return c.releasePrepareJournal(session, ErrInvalidIdentity)
		}
		return c.releasePrepareJournal(session, ErrStaleTopologyUnverified)
	} else if !errors.Is(loadErr, ErrJournalNotFound) {
		return c.releasePrepareJournal(session, ErrStaleTopologyUnverified)
	}

	if err := session.save(ctx, journalStageProxyStarting); err != nil {
		return c.releasePrepareJournal(session, ErrCleanupIncomplete)
	}
	session.proxy, err = c.options.Proxy.Start(ctx, session.plan)
	if err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	if interfaceIsNil(session.proxy) {
		session.proxy = nil
		return c.retainUntrackedPrepareUncertainty(session, ErrProxyUnavailable)
	}
	session.proxyLoss = session.proxy.Loss()
	if session.proxyLoss == nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	endpoint, err := c.options.Proxy.Endpoint(session.proxy)
	if err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	proxyAddress, proxyPort, guestProxyAddress, err := validatedProxyEndpoint(endpoint)
	if err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	if err := c.options.Proxy.Active(ctx, session.plan, session.proxy); err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	if err := session.save(ctx, journalStageTopologyStarting); err != nil {
		return c.failPrepare(session, ErrCleanupIncomplete)
	}
	topology, err := c.options.Topology.Start(ctx, linuxtopology.StartRequest{Identity: session.topologyIdentity,
		Mapping: linuxtopology.Mapping{ProxyEndpoint: endpoint, GuestProxyAddress: guestProxyAddress.String(), NamespaceInterface: mappingInterfaceName}})
	if topology != nil && !interfaceIsNil(topology) {
		session.topology = topology
	}
	if topology != nil && interfaceIsNil(topology) {
		session.stopKnownProxyAfterUntrackedPrepare()
		return c.retainUntrackedPrepareUncertainty(session, ErrTopologyPrepareFailed)
	}
	if err != nil || topology == nil {
		return c.failPrepare(session, ErrTopologyPrepareFailed)
	}
	if !topologyMetadataMatches(topology.Metadata(), session.topologyIdentity) {
		return c.failPrepare(session, ErrProofMismatch)
	}
	session.topologyLoss = topology.Losses()
	if session.topologyLoss == nil {
		return c.failPrepare(session, ErrTopologyPrepareFailed)
	}
	namespace, err := topology.BorrowNamespace()
	if !interfaceIsNil(namespace) {
		session.namespace = namespace
	}
	if err != nil || interfaceIsNil(namespace) {
		return c.failPrepare(session, ErrTopologyPrepareFailed)
	}
	if err := session.save(ctx, journalStageTopologyPrepared); err != nil {
		return c.failPrepare(session, ErrCleanupIncomplete)
	}

	spec := staticTAPSpec(request.Identity, proxyAddress, proxyPort)
	tap, err := c.options.TAP.CreateConfigure(ctx, namespace, spec)
	if tap.valid(spec) {
		session.tapSpec, session.tap = spec, tap
	}
	if err != nil || !tap.valid(spec) {
		return c.failPrepare(session, ErrTopologyPrepareFailed)
	}
	if err := session.save(ctx, journalStageTAPCreated); err != nil {
		return c.failPrepare(session, ErrCleanupIncomplete)
	}
	if err := c.options.TAP.Inspect(ctx, namespace, tap, spec); err != nil {
		return c.failPrepare(session, ErrProofMismatch)
	}

	corr := correlation(request.Identity)
	if err := c.options.Proxy.Active(ctx, session.plan, session.proxy); err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{
		Correlation: corr, Profile: linuxrules.RuleProfileForwardedTAP, Namespace: namespace.RuleNamespace(),
		TableName: ruleTableName, InterfaceName: spec.name, MappingInterfaceName: mappingInterfaceName,
		ProxyAddress: spec.proxyAddress.String(), ProxyPort: spec.proxyPort,
		WorkloadIPv6Address: spec.guestIPv6Prefix.Addr().String(), GatewayIPv6Address: spec.gatewayIPv6.String(),
		IPv6PrefixBits: uint8(spec.guestIPv6Prefix.Bits()), AllowIPv6DAD: true,
	})
	if err != nil {
		return c.failPrepare(session, ErrTopologyPrepareFailed)
	}
	session.expectedRules = expected
	ruleMetadata, err := c.options.Rules.ApplyAndInspect(ctx, expected)
	session.rulesPresent = true
	if err != nil {
		return c.failPrepare(session, ErrRuleApplyFailed)
	}
	ruleDigest, err := inspectedRuleDigest(ruleMetadata, corr)
	if err != nil {
		return c.failPrepare(session, ErrRuleInspectionFailed)
	}
	session.metadata = Metadata{Identity: request.Identity, Status: StatusHostPrepared, StructuralInspected: true,
		TAPInspected: true, RulesInspected: true, RuleDigest: ruleDigest}
	if err := session.save(ctx, journalStageRulesInspected); err != nil {
		return c.failPrepare(session, ErrCleanupIncomplete)
	}
	if err := c.options.TAP.Inspect(ctx, namespace, tap, spec); err != nil {
		return c.failPrepare(session, ErrProofMismatch)
	}
	if err := c.options.Proxy.Active(ctx, session.plan, session.proxy); err != nil {
		return c.failPrepare(session, ErrProxyUnavailable)
	}
	// Only a session prepared in this process may use the pre-VM rollback
	// boundary. Reconciled sessions keep the zero value and require exact VM
	// termination proof before cleanup.
	session.preVMAbort = true
	if err := session.armEnforcementLossWatcher(); err != nil {
		return c.failPrepare(session, err)
	}
	c.current = session
	return session, nil
}

func (c *Coordinator) failPrepare(session *Session, primary error) (*Session, error) {
	if cleanupErr := session.rollback(); cleanupErr != nil {
		return c.retainPrepareCleanup(session, retainedCleanupRollback, primary)
	}
	return nil, primary
}

func (c *Coordinator) retainUntrackedPrepareUncertainty(session *Session, primary error) (*Session, error) {
	return c.retainPrepareCleanup(session, retainedCleanupUnavailable, primary)
}

func (c *Coordinator) retainPrepareCleanup(session *Session, mode retainedCleanupMode, primary error) (*Session, error) {
	session.retainedCleanup = mode
	session.metadata.Status = StatusCleanupIncomplete
	c.current = session
	return session, errors.Join(primary, ErrCleanupIncomplete)
}

func (c *Coordinator) releasePrepareJournal(session *Session, primary error) (*Session, error) {
	if session == nil {
		return nil, errors.Join(primary, ErrCleanupIncomplete)
	}
	if interfaceIsNil(session.journal) {
		return c.retainPrepareCleanup(session, retainedCleanupUnavailable, primary)
	}
	if err := session.journal.Release(); err != nil {
		return c.retainPrepareCleanup(session, retainedCleanupReleaseJournal, primary)
	}
	session.journalReleased = true
	return nil, primary
}

func (c *Coordinator) releaseRecoveryHandles(session *Session, primary error) (*Session, error) {
	if session == nil {
		return nil, errors.Join(primary, ErrCleanupIncomplete)
	}
	if !interfaceIsNil(session.namespace) {
		if err := session.namespace.Close(); err != nil {
			return c.retainPrepareCleanup(session, retainedCleanupReleaseRecoveryHandles, primary)
		}
		session.namespace = nil
	}
	return c.releaseRecoveryJournal(session, primary)
}

func (c *Coordinator) releaseRecoveryJournal(session *Session, primary error) (*Session, error) {
	if session == nil {
		return nil, errors.Join(primary, ErrCleanupIncomplete)
	}
	if interfaceIsNil(session.journal) {
		return c.retainPrepareCleanup(session, retainedCleanupUnavailable, primary)
	}
	if err := session.journal.Release(); err != nil {
		return c.retainPrepareCleanup(session, retainedCleanupReleaseRecoveryJournal, primary)
	}
	session.journalReleased = true
	return nil, primary
}

func (s *Session) stopKnownProxyAfterUntrackedPrepare() {
	if s == nil || s.coordinator == nil || interfaceIsNil(s.proxy) || s.proxyStopped {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.coordinator.options.CleanupTimeout)
	defer cancel()
	if s.coordinator.options.Proxy.Stop(ctx, s.plan, s.proxy) == nil {
		s.proxyStopped = true
	}
}

func (s *Session) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata
}

func (s *Session) MarshalJSON() ([]byte, error) { return json.Marshal(s.Metadata()) }

func (s *Session) Loss() <-chan ProxyLossResult {
	if s == nil {
		return nil
	}
	return s.loss
}

func (s *Session) armEnforcementLossWatcher() error {
	if s == nil || s.proxyLoss == nil || s.topologyLoss == nil {
		return ErrTopologyPrepareFailed
	}
	// The unbuffered acknowledgement is one case in the watcher's loss
	// select. Its rendezvous is the publication linearization point: an
	// earlier loss is returned to Prepare, while a later loss is contained by
	// the same watcher after publication.
	armed := make(chan error)
	go s.watchEnforcementLoss(armed)
	return <-armed
}

func (s *Session) watchEnforcementLoss(armed chan<- error) {
	if hook := s.coordinator.options.beforeLossArm; hook != nil {
		hook()
	}
	if pending := s.pendingEnforcementLoss(); pending != nil {
		armed <- pending
		close(armed)
		return
	}
	select {
	case <-s.proxyLoss:
		armed <- ErrProxyUnavailable
		close(armed)
		return
	case <-s.topologyLoss:
		armed <- ErrTopologyPrepareFailed
		close(armed)
		return
	case armed <- nil:
		close(armed)
	}
	s.containEnforcementLoss()
}

func (s *Session) containEnforcementLoss() {
	select {
	case <-s.proxyLoss:
	case <-s.topologyLoss:
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.coordinator.options.CleanupTimeout)
	defer cancel()
	err := sanitizeProxyLossError(s.Quarantine(ctx, s.identity))
	result := ProxyLossResult{metadata: s.Metadata(), err: err}
	s.lossPublish.Do(func() {
		s.loss <- result
		close(s.loss)
	})
}

func (s *Session) pendingEnforcementLoss() error {
	select {
	case <-s.proxyLoss:
		return ErrProxyUnavailable
	default:
	}
	select {
	case <-s.topologyLoss:
		return ErrTopologyPrepareFailed
	default:
		return nil
	}
}

func sanitizeProxyLossError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrCleanupIncomplete):
		return ErrCleanupIncomplete
	default:
		return ErrQuarantineFailed
	}
}

func proxyLossErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrCleanupIncomplete):
		return "cleanup_incomplete"
	case errors.Is(err, ErrQuarantineFailed):
		return "quarantine_failed"
	default:
		return ""
	}
}

func (s *Session) Inspect(ctx context.Context, identity Identity) (Metadata, error) {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return Metadata{}, ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metadata.Status != StatusInspected || s.quarantined {
		return s.metadata, ErrProofMismatch
	}
	snapshot, err := s.inspectReadyGuestAndHost(ctx, s.guestBinding, s.guestSnapshot)
	if err != nil {
		return s.quarantineOnDrift(ctx, err)
	}
	s.guestSnapshot = snapshot
	return s.metadata, nil
}

// InspectAfterGuestReady composes the first guest-bound proof only after the
// outer Firecracker controller has accepted readiness. It then freshly
// re-inspects every host component in locked order before exposing inspected,
// active-eligible metadata. StatusActive remains owned by that outer controller.
func (s *Session) InspectAfterGuestReady(
	ctx context.Context,
	identity Identity,
	binding RunningGuestBinding,
) (Metadata, error) {
	if s == nil || identity != s.identity || !validIdentity(identity) || interfaceIsNil(binding) {
		return Metadata{}, ErrIdentityMismatch
	}
	if _, ok := snapshotRunningGuestBinding(binding, correlation(identity)); !ok {
		return Metadata{}, ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A validated running-guest binding crosses the VM-ownership boundary even
	// when the following inspection fails and quarantines the session.
	s.preVMAbort = false
	if s.metadata.Status != StatusHostPrepared || s.quarantined {
		return s.metadata, ErrProofMismatch
	}
	snapshot, err := s.inspectReadyGuestAndHost(ctx, binding, runningGuestSnapshot{})
	if err != nil {
		return s.quarantineOnDrift(ctx, err)
	}
	if err := s.save(ctx, journalStageInspected); err != nil {
		return s.quarantineOnDrift(ctx, ErrCleanupIncomplete)
	}
	s.guestBinding = binding
	s.guestSnapshot = snapshot
	s.metadata.Status = StatusInspected
	s.metadata.RawPacketIsolationVerified = true
	return s.metadata, nil
}

func (s *Session) inspectReadyGuestAndHost(
	ctx context.Context,
	binding RunningGuestBinding,
	expectedSnapshot runningGuestSnapshot,
) (runningGuestSnapshot, error) {
	corr := correlation(s.identity)
	verifier := s.coordinator.options.GuestIsolation
	before, ok := snapshotRunningGuestBinding(binding, corr)
	if interfaceIsNil(verifier) || !ok {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	if expectedSnapshot.readinessProofID != "" &&
		(before.correlation != expectedSnapshot.correlation || before.readinessProofID != expectedSnapshot.readinessProofID) {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	request := RunningGuestRawPacketIsolationRequest{
		Correlation: corr, ReadinessProofID: before.readinessProofID, Binding: binding,
	}
	verified, err := verifier.VerifyRunningGuestRawPacketIsolation(ctx, request)
	rawProof := networkenforcement.SanitizeRawPacketIsolationProof(verified.RawPacketProof)
	if err != nil || verified.ReadinessProofID != before.readinessProofID ||
		!networkenforcement.RawPacketIsolationProofMatches(rawProof, corr) {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	before.rawPacketProofID = rawProof.ID
	if expectedSnapshot.rawPacketProofID != "" && before.rawPacketProofID != expectedSnapshot.rawPacketProofID {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	if err := s.coordinator.options.Proxy.Active(ctx, s.plan, s.proxy); err != nil {
		return runningGuestSnapshot{}, ErrProxyUnavailable
	}
	if err := s.coordinator.options.TAP.Inspect(ctx, s.namespace, s.tap, s.tapSpec); err != nil {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	ruleMetadata, err := s.coordinator.options.Rules.Inspect(ctx, s.expectedRules)
	if err != nil {
		return runningGuestSnapshot{}, ErrRuleInspectionFailed
	}
	digest, err := inspectedRuleDigest(ruleMetadata, corr)
	if err != nil || digest != s.metadata.RuleDigest {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	if err := s.coordinator.options.TAP.Inspect(ctx, s.namespace, s.tap, s.tapSpec); err != nil {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	if err := s.coordinator.options.Proxy.Active(ctx, s.plan, s.proxy); err != nil {
		return runningGuestSnapshot{}, ErrProxyUnavailable
	}
	after, ok := snapshotRunningGuestBinding(binding, corr)
	if !ok || after.correlation != before.correlation || after.readinessProofID != before.readinessProofID {
		return runningGuestSnapshot{}, ErrProofMismatch
	}
	after.rawPacketProofID = before.rawPacketProofID
	return after, nil
}

func (s *Session) quarantineOnDrift(ctx context.Context, primary error) (Metadata, error) {
	if !s.quarantined && s.rulesPresent && !s.rulesRemoved {
		if err := s.coordinator.options.Rules.Quarantine(ctx, s.expectedRules); err != nil {
			s.metadata = failedMetadata(s.identity)
			return s.metadata, errors.Join(primary, ErrQuarantineFailed)
		}
		if err := s.save(ctx, journalStageQuarantined); err != nil {
			return s.metadata, errors.Join(primary, ErrCleanupIncomplete)
		}
		s.quarantined = true
		s.metadata = Metadata{Identity: s.identity, Status: StatusQuarantined}
	}
	return s.metadata, primary
}

func (s *Session) Quarantine(ctx context.Context, identity Identity) error {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metadata.Status == StatusStopped || s.quarantined || !s.rulesPresent || s.rulesRemoved {
		return nil
	}
	if err := s.coordinator.options.Rules.Quarantine(ctx, s.expectedRules); err != nil {
		s.metadata = failedMetadata(s.identity)
		return ErrQuarantineFailed
	}
	if err := s.save(ctx, journalStageQuarantined); err != nil {
		return ErrCleanupIncomplete
	}
	s.quarantined = true
	s.metadata = Metadata{Identity: s.identity, Status: StatusQuarantined}
	return nil
}

// AbortBeforeVM reverses a successfully prepared topology only while no guest
// binding has crossed the VM-ownership boundary. It also retries a retained
// prepare rollback. Cleanup uses the session's independent bounded context;
// caller cancellation cannot leave a prepared mapping active by itself.
func (s *Session) AbortBeforeVM(_ context.Context, identity Identity) error {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return ErrIdentityMismatch
	}
	s.mu.Lock()
	if s.retainedCleanup != retainedCleanupNone {
		err := s.retryRetainedCleanupLocked()
		s.mu.Unlock()
		return err
	}
	if s.metadata.Status == StatusStopped {
		s.mu.Unlock()
		s.coordinator.clearCurrentSession(s)
		return nil
	}
	preVMStatus := s.metadata.Status == StatusHostPrepared || s.metadata.Status == StatusQuarantined ||
		s.metadata.Status == StatusCleanupIncomplete
	if !s.preVMAbort || !preVMStatus || !interfaceIsNil(s.guestBinding) {
		s.mu.Unlock()
		return ErrCleanupIncomplete
	}
	if err := s.rollback(); err != nil {
		s.retainedCleanup = retainedCleanupRollback
		s.metadata = Metadata{Identity: s.identity, Status: StatusCleanupIncomplete}
		s.mu.Unlock()
		return ErrCleanupIncomplete
	}
	s.metadata = Metadata{Identity: s.identity, Status: StatusStopped}
	s.preVMAbort = false
	s.mu.Unlock()
	s.coordinator.clearCurrentSession(s)
	return nil
}

func (s *Session) CleanupAfterVMQuiesced(_ context.Context, identity Identity, binding TerminatedVMBinding) error {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retainedCleanup != retainedCleanupNone {
		return ErrCleanupIncomplete
	}
	if s.metadata.Status == StatusStopped {
		s.coordinator.clearCurrentSession(s)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.coordinator.options.CleanupTimeout)
	defer cancel()
	if !s.verifyVMTermination(ctx, binding) {
		return ErrVMNotQuiesced
	}
	if s.rulesPresent && !s.quarantined {
		return ErrQuarantineFailed
	}
	if !s.rulesRemoved && s.rulesPresent {
		if err := s.coordinator.options.Rules.Cleanup(ctx, s.expectedRules); err != nil {
			s.metadata = failedMetadata(s.identity)
			return ErrCleanupIncomplete
		}
		if err := s.save(ctx, journalStageRulesRemoved); err != nil {
			return ErrCleanupIncomplete
		}
		s.rulesRemoved = true
	}
	if !s.tapRemoved && s.tap.name != "" {
		if err := s.coordinator.options.TAP.Delete(ctx, s.namespace, s.tap, s.tapSpec); err != nil {
			s.metadata = failedMetadata(s.identity)
			return ErrCleanupIncomplete
		}
		if err := s.save(ctx, journalStageTAPRemoved); err != nil {
			return ErrCleanupIncomplete
		}
		s.tapRemoved = true
	}
	if !s.topologyRemoved {
		if !interfaceIsNil(s.namespace) {
			if err := s.namespace.Close(); err != nil {
				return ErrCleanupIncomplete
			}
			s.namespace = nil
		}
		if !interfaceIsNil(s.topology) {
			metadata, err := s.coordinator.options.Topology.Stop(ctx, s.topologyIdentity)
			if err != nil || metadata.Status != linuxtopology.StatusStopped {
				return ErrCleanupIncomplete
			}
		}
		if err := s.save(ctx, journalStageTopologyRemoved); err != nil {
			return ErrCleanupIncomplete
		}
		s.topologyRemoved = true
	}
	if !s.proxyStopped && !interfaceIsNil(s.proxy) {
		if err := s.coordinator.options.Proxy.Stop(ctx, s.plan, s.proxy); err != nil {
			return ErrCleanupIncomplete
		}
		s.proxyStopped = true
	}
	if !s.journalRemoved {
		if err := s.journal.Remove(); err != nil {
			return ErrCleanupIncomplete
		}
		s.journalRemoved = true
	}
	if !s.journalReleased {
		if err := s.journal.Release(); err != nil {
			return ErrCleanupIncomplete
		}
		s.journalReleased = true
	}
	s.metadata = Metadata{Identity: s.identity, Status: StatusStopped}
	s.coordinator.clearCurrentSession(s)
	return nil
}

// RetryFailedPrepareCleanup retries only rollback work retained by Prepare
// before VM ownership was possible. It never accepts a VM-quiescence claim and
// cannot be used for a successfully prepared or runtime-owned session.
func (s *Session) RetryFailedPrepareCleanup(_ context.Context, identity Identity) error {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retainedCleanup != retainedCleanupRollback {
		return ErrCleanupIncomplete
	}
	return s.retryRetainedCleanupLocked()
}

// RetryRetainedCleanup retries only the exact cleanup operation retained by a
// failed pre-VM preparation or recovery boundary.
func (s *Session) RetryRetainedCleanup(_ context.Context, identity Identity) error {
	if s == nil || identity != s.identity || !validIdentity(identity) {
		return ErrIdentityMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retryRetainedCleanupLocked()
}

func (s *Session) retryRetainedCleanupLocked() error {
	if s.metadata.Status != StatusCleanupIncomplete {
		return ErrCleanupIncomplete
	}
	switch s.retainedCleanup {
	case retainedCleanupRollback:
		if err := s.rollback(); err != nil {
			return ErrCleanupIncomplete
		}
	case retainedCleanupReleaseJournal:
		if interfaceIsNil(s.journal) || s.journal.Release() != nil {
			return ErrCleanupIncomplete
		}
		s.journalReleased = true
	case retainedCleanupReleaseRecoveryJournal:
		if interfaceIsNil(s.journal) || s.journal.Release() != nil {
			return ErrCleanupIncomplete
		}
		s.journalReleased = true
		s.retainedCleanup = retainedCleanupUnavailable
		return ErrCleanupIncomplete
	case retainedCleanupReleaseRecoveryHandles:
		if !interfaceIsNil(s.namespace) {
			if err := s.namespace.Close(); err != nil {
				return ErrCleanupIncomplete
			}
			s.namespace = nil
		}
		if interfaceIsNil(s.journal) || s.journal.Release() != nil {
			s.retainedCleanup = retainedCleanupReleaseRecoveryJournal
			return ErrCleanupIncomplete
		}
		s.journalReleased = true
		s.retainedCleanup = retainedCleanupUnavailable
		return ErrCleanupIncomplete
	default:
		return ErrCleanupIncomplete
	}
	s.retainedCleanup = retainedCleanupNone
	s.metadata = Metadata{Identity: s.identity, Status: StatusStopped}
	s.coordinator.clearCurrentSession(s)
	return nil
}

func (c *Coordinator) clearCurrentSession(session *Session) {
	if c == nil || session == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == session {
		c.current = nil
	}
}

func (s *Session) verifyVMTermination(ctx context.Context, binding TerminatedVMBinding) bool {
	verifier := s.coordinator.options.VMTermination
	corr := correlation(s.identity)
	before, ok := snapshotTerminatedVMBinding(binding, corr)
	if interfaceIsNil(verifier) || !ok {
		return false
	}
	proof, err := verifier.VerifyVMTermination(ctx, VMTerminationRequest{
		Correlation: corr, TerminationProofID: before.terminationProofID, Binding: binding,
	})
	if err != nil || !safeIDPattern.MatchString(proof.ID) || proof.TerminationProofID != before.terminationProofID ||
		!networkenforcement.EnforcementCorrelationsEqual(proof.Correlation, corr) || !proof.Stopped || !proof.Reaped {
		return false
	}
	after, ok := snapshotTerminatedVMBinding(binding, corr)
	return ok && after == before
}

func (s *Session) rollback() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.coordinator.options.CleanupTimeout)
	defer cancel()
	if s.rulesPresent && !s.rulesRemoved {
		if !s.quarantined {
			if err := s.coordinator.options.Rules.Quarantine(ctx, s.expectedRules); err != nil {
				return ErrCleanupIncomplete
			}
			s.quarantined = true
		}
		if err := s.coordinator.options.Rules.Cleanup(ctx, s.expectedRules); err != nil {
			return ErrCleanupIncomplete
		}
		s.rulesRemoved = true
	}
	if s.tap.name != "" && !s.tapRemoved {
		if err := s.coordinator.options.TAP.Delete(ctx, s.namespace, s.tap, s.tapSpec); err != nil {
			return ErrCleanupIncomplete
		}
		s.tapRemoved = true
	}
	if !interfaceIsNil(s.namespace) {
		if err := s.namespace.Close(); err != nil {
			return ErrCleanupIncomplete
		}
		s.namespace = nil
	}
	if !interfaceIsNil(s.topology) && !s.topologyRemoved {
		metadata, err := s.coordinator.options.Topology.Stop(ctx, s.topologyIdentity)
		if err != nil || metadata.Status != linuxtopology.StatusStopped {
			return ErrCleanupIncomplete
		}
		s.topologyRemoved = true
	}
	if !interfaceIsNil(s.proxy) && !s.proxyStopped {
		if err := s.coordinator.options.Proxy.Stop(ctx, s.plan, s.proxy); err != nil {
			return ErrCleanupIncomplete
		}
		s.proxyStopped = true
	}
	if s.journal.Remove() != nil || s.journal.Release() != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func (s *Session) save(ctx context.Context, stage journalStage) error {
	if interfaceIsNil(s.journal) {
		return ErrCleanupIncomplete
	}
	record := journalRecord{identity: s.identity, stage: stage, tapName: s.tap.name,
		tapFingerprint: s.tap.fingerprint, tapIfIndex: s.tap.ifIndex, ruleDigest: s.metadata.RuleDigest}
	if s.tapSpec.proxyAddress.IsValid() {
		record.proxyAddress = s.tapSpec.proxyAddress.String()
		record.proxyPort = s.tapSpec.proxyPort
	}
	return s.journal.Save(ctx, record)
}

func staticTAPSpec(identity Identity, proxyAddress netip.Addr, proxyPort uint16) tapSpec {
	digest := sha256.Sum256([]byte(identity.TopologyGenerationID + "\x00" + identity.RuleGenerationID))
	name := "ht" + hex.EncodeToString(digest[:])[:10]
	macBytes := digest[:6]
	macBytes[0] = (macBytes[0] | 2) & 0xfe
	mac := net.HardwareAddr(macBytes).String()
	return tapSpec{generation: identity.TopologyGenerationID, name: name, mac: mac, mappingInterface: mappingInterfaceName,
		proxyAddress: proxyAddress, proxyPort: proxyPort,
		guestIPv4Prefix: netip.PrefixFrom(netip.MustParseAddr("172.31.255.2"), 30), gatewayIPv4: netip.MustParseAddr("172.31.255.1"),
		guestIPv6Prefix: netip.PrefixFrom(netip.MustParseAddr("fd00:6861:6c::2"), 126), gatewayIPv6: netip.MustParseAddr("fd00:6861:6c::1")}
}

func validatedProxyEndpoint(endpoint string) (netip.Addr, uint16, netip.Addr, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, 0, netip.Addr{}, ErrProxyUnavailable
	}
	address, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if addressErr != nil || portErr != nil || port == 0 || !address.IsLoopback() || address.Zone() != "" {
		return netip.Addr{}, 0, netip.Addr{}, ErrProxyUnavailable
	}
	guest := netip.MustParseAddr("192.0.2.2")
	if address.Is6() {
		guest = netip.MustParseAddr("2001:db8::2")
	}
	return guest, uint16(port), guest, nil
}

func topologyMetadataMatches(metadata linuxtopology.Metadata, identity linuxtopology.Identity) bool {
	return metadata.Identity == identity && metadata.Status == linuxtopology.StatusPrepared &&
		metadata.StructuralInspected && metadata.MappingReachable
}

func recoveryTopologyMetadataMatches(metadata linuxtopology.Metadata, identity linuxtopology.Identity) bool {
	return metadata.Identity == identity && metadata.Status == linuxtopology.StatusRecoveryOnly &&
		!metadata.StructuralInspected && !metadata.MappingReachable
}

func inspectedRuleDigest(metadata networkenforcement.RuleLifecycleMetadata, expected networkenforcement.EnforcementCorrelation) (string, error) {
	metadata = networkenforcement.SanitizeRuleLifecycleMetadata(metadata)
	if metadata.Status != networkenforcement.LifecycleStatusActive || metadata.Correlation == nil ||
		!networkenforcement.EnforcementCorrelationsEqual(*metadata.Correlation, expected) || metadata.Inspection == nil ||
		metadata.Inspection.Status != networkenforcement.RuleInspectionStatusInspected || metadata.Inspection.Correlation == nil ||
		!networkenforcement.EnforcementCorrelationsEqual(*metadata.Inspection.Correlation, expected) ||
		metadata.Inspection.RuleDigest == "" || len(metadata.WarningCodes) != 0 || len(metadata.Inspection.WarningCodes) != 0 {
		return "", ErrRuleInspectionFailed
	}
	return metadata.Inspection.RuleDigest, nil
}

func failedMetadata(identity Identity) Metadata {
	return Metadata{Identity: identity, Status: StatusCleanupIncomplete}
}

func sanitizeJournalAcquireError(err error) error {
	switch {
	case errors.Is(err, ErrTopologyCollision):
		return ErrTopologyCollision
	case errors.Is(err, ErrJournalRetired):
		return ErrJournalRetired
	case errors.Is(err, ErrStaleTopologyUnverified):
		return ErrStaleTopologyUnverified
	default:
		return ErrCleanupIncomplete
	}
}
