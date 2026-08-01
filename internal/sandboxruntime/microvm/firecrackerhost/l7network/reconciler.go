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
	lease, err := r.options.Journal.Acquire(ctx, identity)
	if err != nil {
		return nil, sanitizeJournalAcquireError(err)
	}
	if interfaceIsNil(lease) {
		return nil, ErrStaleTopologyUnverified
	}
	record, err := lease.Load()
	if err != nil || record.identity != identity || stageOrder(record.stage) < stageOrder(journalStageTAPCreated) {
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	if record.stage == journalStageTopologyRemoved {
		coordinator := &Coordinator{options: Options{Enabled: true, TAP: r.options.TAP, Rules: r.options.Rules,
			VMTermination: r.options.VMTermination, Journal: r.options.Journal, CleanupTimeout: r.options.CleanupTimeout}}
		return &Session{coordinator: coordinator, identity: identity, journal: lease, proxyStopped: true,
			rulesRemoved: true, tapRemoved: true, topologyRemoved: true,
			metadata: Metadata{Identity: identity, Status: StatusQuarantined}}, nil
	}
	lifecycle, topology, err := r.options.Recovery.Recover(ctx, identity)
	if err != nil || interfaceIsNil(lifecycle) || interfaceIsNil(topology) || !topologyMetadataMatches(topology.Metadata(), topologyIdentity(identity)) {
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	namespace, err := topology.BorrowNamespace()
	if err != nil || interfaceIsNil(namespace) {
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	proxyAddress, err := netip.ParseAddr(record.proxyAddress)
	if err != nil || record.proxyPort == 0 {
		_ = namespace.Close()
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	spec := staticTAPSpec(identity, proxyAddress, record.proxyPort)
	tap := tapState{name: record.tapName, generation: identity.TopologyGenerationID,
		fingerprint: record.tapFingerprint, ifIndex: record.tapIfIndex}
	if !tap.valid(spec) {
		_ = namespace.Close()
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{Correlation: correlation(identity),
		Profile: linuxrules.RuleProfileForwardedTAP, Namespace: namespace.RuleNamespace(), TableName: ruleTableName,
		InterfaceName: spec.name, MappingInterfaceName: mappingInterfaceName, ProxyAddress: spec.proxyAddress.String(), ProxyPort: spec.proxyPort,
		WorkloadIPv6Address: spec.guestIPv6Prefix.Addr().String(), GatewayIPv6Address: spec.gatewayIPv6.String(),
		IPv6PrefixBits: uint8(spec.guestIPv6Prefix.Bits()), AllowIPv6DAD: true})
	if err != nil {
		_ = namespace.Close()
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	}
	coordinator := &Coordinator{options: Options{Enabled: true, Topology: lifecycle, TAP: r.options.TAP, Rules: r.options.Rules,
		VMTermination: r.options.VMTermination, Journal: r.options.Journal, CleanupTimeout: r.options.CleanupTimeout}}
	session := &Session{coordinator: coordinator, identity: identity, topologyIdentity: topologyIdentity(identity), topology: topology,
		namespace: namespace, tapSpec: spec, tap: tap, expectedRules: expected, journal: lease, proxyStopped: true,
		metadata: Metadata{Identity: identity, Status: StatusCleanupIncomplete}, rulesPresent: true}
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
