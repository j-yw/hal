// Package l7network owns the explicitly enabled Firecracker host-network
// topology foundation. It prepares and inspects host state, but deliberately
// does not start a VM or publish active enforcement proof.
package l7network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

var (
	ErrDisabled                = errors.New("Firecracker host topology disabled")
	ErrUnsupported             = errors.New("Firecracker host topology unsupported")
	ErrInvalidConfiguration    = errors.New("Firecracker host topology invalid configuration")
	ErrInvalidIdentity         = errors.New("Firecracker host topology invalid identity")
	ErrIdentityMismatch        = errors.New("Firecracker host topology identity mismatch")
	ErrTopologyCollision       = errors.New("Firecracker host topology collision")
	ErrProxyUnavailable        = errors.New("Firecracker host topology proxy unavailable")
	ErrTopologyPrepareFailed   = errors.New("Firecracker host topology prepare failed")
	ErrRuleApplyFailed         = errors.New("Firecracker host topology rule apply failed")
	ErrRuleInspectionFailed    = errors.New("Firecracker host topology rule inspection failed")
	ErrProofMismatch           = errors.New("Firecracker host topology proof mismatch")
	ErrQuarantineFailed        = errors.New("Firecracker host topology quarantine failed")
	ErrCleanupIncomplete       = errors.New("Firecracker host topology cleanup incomplete")
	ErrStaleTopologyUnverified = errors.New("Firecracker host topology stale state unverified")
	ErrVMNotQuiesced           = errors.New("Firecracker VM is not confirmed quiesced")
	ErrJournalNotFound         = errors.New("Firecracker host topology journal not found")
)

const defaultCleanupTimeout = 5 * time.Second

var safeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

type Status string

const (
	StatusPrepared          Status = "prepared"
	StatusHostPrepared      Status = "host_prepared"
	StatusInspected         Status = "inspected"
	StatusActive            Status = "active" // reserved for the later runtime coordinator
	StatusQuarantined       Status = "quarantined"
	StatusCleanupIncomplete Status = "cleanup_incomplete"
	StatusStopped           Status = "stopped"
)

// Identity contains only safe immutable correlation identifiers. Each field
// must be present and distinct, preventing one generation from substituting
// for another at a cleanup boundary.
type Identity struct {
	SandboxID            string `json:"sandboxId"`
	ExecutionID          string `json:"executionId"`
	WorkerID             string `json:"workerId"`
	RuntimeGenerationID  string `json:"runtimeGenerationId"`
	PlanID               string `json:"planId"`
	PolicySnapshotID     string `json:"policySnapshotId"`
	ProxySessionID       string `json:"proxySessionId"`
	ProxyGenerationID    string `json:"proxyGenerationId"`
	TopologyGenerationID string `json:"topologyGenerationId"`
	RuleGenerationID     string `json:"ruleGenerationId"`
}

type Metadata struct {
	Identity                   Identity `json:"identity"`
	Status                     Status   `json:"status"`
	StructuralInspected        bool     `json:"structuralInspected,omitempty"`
	TAPInspected               bool     `json:"tapInspected,omitempty"`
	RulesInspected             bool     `json:"rulesInspected,omitempty"`
	RawPacketIsolationVerified bool     `json:"rawPacketIsolationVerified,omitempty"`
	RuleDigest                 string   `json:"ruleDigest,omitempty"`
}

// ProxyLossResult is the live-only outcome published after the session-owned
// proxy loss watcher has completed its quarantine attempt. Err returns only a
// package sentinel, never an adapter error.
type ProxyLossResult struct {
	metadata Metadata
	err      error
}

func (r ProxyLossResult) Metadata() Metadata { return r.metadata }

func (r ProxyLossResult) Err() error { return r.err }

func (r ProxyLossResult) MarshalJSON() ([]byte, error) {
	type resultJSON struct {
		Metadata  Metadata `json:"metadata"`
		ErrorCode string   `json:"errorCode,omitempty"`
	}
	return json.Marshal(resultJSON{Metadata: r.metadata, ErrorCode: proxyLossErrorCode(r.err)})
}

type PrepareRequest struct {
	Identity Identity                `json:"identity"`
	Plan     networkenforcement.Plan `json:"plan"`
}

type ProxyGeneration interface {
	Address() string
	Loss() <-chan struct{}
}

type ProxyLifecycle interface {
	Start(context.Context, networkenforcement.Plan) (ProxyGeneration, error)
	Endpoint(ProxyGeneration) (string, error)
	Active(context.Context, networkenforcement.Plan, ProxyGeneration) error
	Stop(context.Context, networkenforcement.Plan, ProxyGeneration) error
}

type TopologySession interface {
	Metadata() linuxtopology.Metadata
	BorrowNamespace() (NamespaceLease, error)
	// Losses reports loss of an exact topology-owned process generation. A
	// prepared Firecracker topology must provide this live signal.
	Losses() <-chan linuxtopology.Loss
}

type TopologyLifecycle interface {
	Start(context.Context, linuxtopology.StartRequest) (TopologySession, error)
	Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error)
}

// NamespaceLease is an opaque live-only borrow of the exact topology-owned
// namespace. RuleNamespace contains descriptor numbers only while the lease
// remains open; neither is serializable.
type NamespaceLease interface {
	RuleNamespace() linuxrules.NamespaceHandle
	Close() error
}

type RuleAdapter interface {
	ApplyAndInspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error)
	Inspect(context.Context, linuxrules.ExpectedRuleSet) (networkenforcement.RuleLifecycleMetadata, error)
	Quarantine(context.Context, linuxrules.ExpectedRuleSet) error
	Cleanup(context.Context, linuxrules.ExpectedRuleSet) error
}

// RunningGuestBinding is an opaque live-only binding to the exact guest whose
// readiness was accepted by the outer Firecracker controller. The safe
// correlation and proof ID let this package reject a stale or substituted
// binding without exposing its process, transport, or guest details.
type RunningGuestBinding interface {
	GuestCorrelation() networkenforcement.EnforcementCorrelation
	GuestReadinessProofID() string
}

// RunningGuestRawPacketIsolationRequest keeps the live binding private while
// carrying only redaction-safe immutable identity beside it.
type RunningGuestRawPacketIsolationRequest struct {
	Correlation      networkenforcement.EnforcementCorrelation `json:"correlation"`
	ReadinessProofID string                                    `json:"readinessProofId"`
	Binding          RunningGuestBinding                       `json:"-"`
}

// RunningGuestRawPacketIsolationProof binds the mechanically inspected raw
// packet result to the exact readiness proof accepted by the controller.
type RunningGuestRawPacketIsolationProof struct {
	ReadinessProofID string
	RawPacketProof   networkenforcement.RawPacketIsolationProof
}

// RunningGuestRawPacketIsolationVerifier must mechanically inspect the exact
// ready guest represented by request.Binding. Static image properties,
// requested capability drops, and correlation-only proofs are insufficient.
type RunningGuestRawPacketIsolationVerifier interface {
	VerifyRunningGuestRawPacketIsolation(context.Context, RunningGuestRawPacketIsolationRequest) (RunningGuestRawPacketIsolationProof, error)
}

// TerminatedVMBinding is an opaque live-only binding to the exact Firecracker
// generation whose terminal state was observed by the outer controller.
type TerminatedVMBinding interface {
	VMCorrelation() networkenforcement.EnforcementCorrelation
	VMTerminationProofID() string
}

type VMTerminationRequest struct {
	Correlation        networkenforcement.EnforcementCorrelation
	TerminationProofID string
	Binding            TerminatedVMBinding
}

// VMTerminationProof is safe evidence that the exact process generation is
// both stopped and reaped. A stopped-but-unreaped process is not authoritative
// cleanup permission.
type VMTerminationProof struct {
	ID                 string
	TerminationProofID string
	Correlation        networkenforcement.EnforcementCorrelation
	Stopped            bool
	Reaped             bool
}

type VMTerminationVerifier interface {
	VerifyVMTermination(context.Context, VMTerminationRequest) (VMTerminationProof, error)
}

type TAPLifecycle interface {
	CreateConfigure(context.Context, NamespaceLease, tapSpec) (tapState, error)
	Inspect(context.Context, NamespaceLease, tapState, tapSpec) error
	Delete(context.Context, NamespaceLease, tapState, tapSpec) error
}

type JournalStore interface {
	Acquire(context.Context, Identity) (JournalLease, error)
}

type JournalLease interface {
	Load() (journalRecord, error)
	Save(context.Context, journalRecord) error
	Remove() error
	Release() error
}

type Options struct {
	Enabled        bool
	Proxy          ProxyLifecycle
	Topology       TopologyLifecycle
	TAP            TAPLifecycle
	Rules          RuleAdapter
	GuestIsolation RunningGuestRawPacketIsolationVerifier
	VMTermination  VMTerminationVerifier
	Journal        JournalStore
	StateDir       string
	CleanupTimeout time.Duration
}

type runningGuestSnapshot struct {
	correlation      networkenforcement.EnforcementCorrelation
	readinessProofID string
	rawPacketProofID string
}

type terminatedVMSnapshot struct {
	correlation        networkenforcement.EnforcementCorrelation
	terminationProofID string
}

type tapSpec struct {
	generation       string
	name             string
	mac              string
	mappingInterface string
	proxyAddress     netip.Addr
	proxyPort        uint16
	guestIPv4Prefix  netip.Prefix
	gatewayIPv4      netip.Addr
	guestIPv6Prefix  netip.Prefix
	gatewayIPv6      netip.Addr
}

func (s tapSpec) fingerprint() string {
	digest := sha256.Sum256([]byte(s.generation + "\x00" + s.name + "\x00" + s.mac + "\x00" +
		s.mappingInterface + "\x00" + s.proxyAddress.String() + "\x00" + s.guestIPv4Prefix.String() + "\x00" +
		s.gatewayIPv4.String() + "\x00" + s.guestIPv6Prefix.String() + "\x00" + s.gatewayIPv6.String()))
	return hex.EncodeToString(digest[:])
}

type tapState struct {
	name        string
	generation  string
	fingerprint string
	ifIndex     int
}

func (s tapState) valid(spec tapSpec) bool {
	return s.name != "" && s.name == spec.name && s.generation == spec.generation &&
		s.fingerprint == spec.fingerprint() && s.ifIndex > 0 && s.ifIndex <= maxTAPIfIndex
}

type journalStage string

const (
	journalStageProxyStarting    journalStage = "proxy_starting"
	journalStageTopologyStarting journalStage = "topology_starting"
	journalStageTopologyPrepared journalStage = "topology_prepared"
	journalStageTAPCreated       journalStage = "tap_created"
	journalStageRulesInspected   journalStage = "rules_inspected"
	journalStageInspected        journalStage = "inspected"
	journalStageQuarantined      journalStage = "quarantined"
	journalStageRulesRemoved     journalStage = "rules_removed"
	journalStageTAPRemoved       journalStage = "tap_removed"
	journalStageTopologyRemoved  journalStage = "topology_removed"
)

type journalRecord struct {
	identity       Identity
	stage          journalStage
	tapName        string
	tapFingerprint string
	tapIfIndex     int
	ruleDigest     string
	proxyAddress   string
	proxyPort      uint16
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	type metadataJSON Metadata
	return json.Marshal(metadataJSON(m))
}

func validIdentity(identity Identity) bool {
	values := []string{identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.RuntimeGenerationID,
		identity.PlanID, identity.PolicySnapshotID, identity.ProxySessionID, identity.ProxyGenerationID,
		identity.TopologyGenerationID, identity.RuleGenerationID}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !safeIDPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func snapshotRunningGuestBinding(binding RunningGuestBinding, expected networkenforcement.EnforcementCorrelation) (runningGuestSnapshot, bool) {
	if interfaceIsNil(binding) {
		return runningGuestSnapshot{}, false
	}
	snapshot := runningGuestSnapshot{
		correlation:      networkenforcement.SanitizeEnforcementCorrelation(binding.GuestCorrelation()),
		readinessProofID: binding.GuestReadinessProofID(),
	}
	return snapshot, safeIDPattern.MatchString(snapshot.readinessProofID) &&
		networkenforcement.EnforcementCorrelationsEqual(snapshot.correlation, expected)
}

func snapshotTerminatedVMBinding(binding TerminatedVMBinding, expected networkenforcement.EnforcementCorrelation) (terminatedVMSnapshot, bool) {
	if interfaceIsNil(binding) {
		return terminatedVMSnapshot{}, false
	}
	snapshot := terminatedVMSnapshot{
		correlation:        networkenforcement.SanitizeEnforcementCorrelation(binding.VMCorrelation()),
		terminationProofID: binding.VMTerminationProofID(),
	}
	return snapshot, safeIDPattern.MatchString(snapshot.terminationProofID) &&
		networkenforcement.EnforcementCorrelationsEqual(snapshot.correlation, expected)
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func planMatchesIdentity(plan networkenforcement.Plan, identity Identity) bool {
	plan = networkenforcement.SanitizePlan(plan)
	return plan.ID == identity.PlanID && plan.PolicySnapshot != nil && plan.PolicySnapshot.ID == identity.PolicySnapshotID &&
		(plan.PolicySnapshot.Preset == networkenforcement.PolicyPresetDenyByDefault || plan.PolicySnapshot.Preset == networkenforcement.PolicyPresetAllowListed) &&
		plan.DefaultPosture == networkenforcement.DefaultPostureDenyByDefault && plan.Proxy != nil &&
		plan.Proxy.ProxySessionID == identity.ProxySessionID && plan.Proxy.Mechanism == networkenforcement.EnforcementMechanismProxy &&
		plan.Proxy.HTTP == networkenforcement.ProxyRoutingModeRouteViaProxy && plan.Proxy.HTTPS == networkenforcement.ProxyRoutingModeRouteViaProxy &&
		plan.Firewall != nil && plan.Firewall.Mode == networkenforcement.FirewallIntentModeApply &&
		plan.Firewall.Mechanism == networkenforcement.EnforcementMechanismFirewall
}

func correlation(identity Identity) networkenforcement.EnforcementCorrelation {
	return networkenforcement.EnforcementCorrelation{SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID,
		WorkerID: identity.WorkerID, RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID,
		PolicySnapshotID: identity.PolicySnapshotID, ProxySessionID: identity.ProxySessionID,
		ProxyGenerationID: identity.ProxyGenerationID, TopologyGenerationID: identity.TopologyGenerationID,
		RuleGenerationID: identity.RuleGenerationID}
}

func topologyIdentity(identity Identity) linuxtopology.Identity {
	return linuxtopology.Identity{SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID}
}
