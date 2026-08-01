package l7network

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
)

// RecoveryTopology is the narrow exact-ownership boundary required to reopen
// a topology after daemon restart. Implementations must verify the durable
// linuxtopology process/start and namespace identity; names or recorded PIDs
// alone are not sufficient.
type RecoveryTopology interface {
	Recover(context.Context, Identity) (TopologyLifecycle, TopologySession, error)
}

type ReconcilerOptions struct {
	Recovery       RecoveryTopology
	TAP            TAPLifecycle
	Rules          RuleAdapter
	VMTermination  VMTerminationVerifier
	Journal        JournalStore
	StateDir       string
	CleanupTimeout time.Duration
}

type Reconciler struct{ options ReconcilerOptions }

func NewReconciler(input ReconcilerOptions) (*Reconciler, error) {
	options := input
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	if interfaceIsNil(options.Recovery) || interfaceIsNil(options.TAP) || interfaceIsNil(options.Rules) || interfaceIsNil(options.VMTermination) ||
		options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	if options.Journal == nil {
		journal, err := newFileJournalStore(options.StateDir)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		options.Journal = journal
	} else if interfaceIsNil(options.Journal) {
		return nil, ErrInvalidConfiguration
	}
	return &Reconciler{options: options}, nil
}

// Recover never restores inspected or active proof. It reopens exact owned
// state, quarantines the exact rule generation first, and returns the same
// two-stage Session API used by the runtime coordinator.
func (r *Reconciler) Recover(ctx context.Context, identity Identity) (*Session, error) {
	if r == nil || !validIdentity(identity) {
		return nil, ErrInvalidIdentity
	}
	coordinator := &Coordinator{options: Options{Enabled: true, TAP: r.options.TAP, Rules: r.options.Rules,
		VMTermination: r.options.VMTermination, Journal: r.options.Journal, CleanupTimeout: r.options.CleanupTimeout}}
	session := &Session{coordinator: coordinator, identity: identity,
		metadata: Metadata{Identity: identity, Status: StatusCleanupIncomplete}}
	lease, err := r.options.Journal.Acquire(ctx, identity)
	if err != nil {
		primary := sanitizeJournalAcquireError(err)
		if interfaceIsNil(lease) {
			return nil, primary
		}
		session.journal = lease
		return coordinator.releaseRecoveryJournal(session, primary)
	}
	if interfaceIsNil(lease) {
		return coordinator.retainPrepareCleanup(session, retainedCleanupUnavailable, ErrStaleTopologyUnverified)
	}
	session.journal = lease
	record, err := lease.Load()
	if err != nil || record.identity != identity || stageOrder(record.stage) < stageOrder(journalStageTAPCreated) {
		return coordinator.releaseRecoveryJournal(session, ErrStaleTopologyUnverified)
	}
	if record.stage == journalStageTopologyRemoved {
		session.proxyStopped, session.rulesRemoved, session.tapRemoved, session.topologyRemoved = true, true, true, true
		session.metadata.Status = StatusQuarantined
		return session, nil
	}
	lifecycle, topology, err := r.options.Recovery.Recover(ctx, identity)
	if err != nil || interfaceIsNil(lifecycle) || interfaceIsNil(topology) || !topologyMetadataMatches(topology.Metadata(), topologyIdentity(identity)) {
		return coordinator.releaseRecoveryJournal(session, ErrStaleTopologyUnverified)
	}
	coordinator.options.Topology = lifecycle
	session.topologyIdentity, session.topology = topologyIdentity(identity), topology
	namespace, err := topology.BorrowNamespace()
	if !interfaceIsNil(namespace) {
		session.namespace = namespace
	}
	if err != nil || interfaceIsNil(namespace) {
		if !interfaceIsNil(namespace) {
			return coordinator.releaseRecoveryHandles(session, ErrStaleTopologyUnverified)
		}
		return coordinator.releaseRecoveryJournal(session, ErrStaleTopologyUnverified)
	}
	proxyAddress, err := netip.ParseAddr(record.proxyAddress)
	if err != nil || record.proxyPort == 0 {
		return coordinator.releaseRecoveryHandles(session, ErrStaleTopologyUnverified)
	}
	spec := staticTAPSpec(identity, proxyAddress, record.proxyPort)
	tap := tapState{name: record.tapName, generation: identity.TopologyGenerationID,
		fingerprint: record.tapFingerprint, ifIndex: record.tapIfIndex}
	if !tap.valid(spec) {
		return coordinator.releaseRecoveryHandles(session, ErrStaleTopologyUnverified)
	}
	expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{Correlation: correlation(identity),
		Profile: linuxrules.RuleProfileForwardedTAP, Namespace: namespace.RuleNamespace(), TableName: ruleTableName,
		InterfaceName: spec.name, MappingInterfaceName: mappingInterfaceName, ProxyAddress: spec.proxyAddress.String(), ProxyPort: spec.proxyPort,
		WorkloadIPv6Address: spec.guestIPv6Prefix.Addr().String(), GatewayIPv6Address: spec.gatewayIPv6.String(),
		IPv6PrefixBits: uint8(spec.guestIPv6Prefix.Bits()), AllowIPv6DAD: true})
	if err != nil {
		return coordinator.releaseRecoveryHandles(session, ErrStaleTopologyUnverified)
	}
	session.tapSpec, session.tap, session.expectedRules, session.proxyStopped, session.rulesPresent = spec, tap, expected, true, true
	switch record.stage {
	case journalStageQuarantined:
		session.quarantined = true
		session.metadata.Status = StatusQuarantined
	case journalStageRulesRemoved:
		session.quarantined, session.rulesRemoved = true, true
		session.metadata.Status = StatusQuarantined
	case journalStageTAPRemoved:
		session.quarantined, session.rulesRemoved, session.tapRemoved = true, true, true
		session.metadata.Status = StatusQuarantined
	default:
		if err := session.Quarantine(ctx, identity); err != nil {
			if errors.Is(err, ErrQuarantineFailed) {
				return session, errors.Join(ErrStaleTopologyUnverified, ErrQuarantineFailed)
			}
			return session, errors.Join(ErrStaleTopologyUnverified, ErrCleanupIncomplete)
		}
	}
	return session, nil
}
