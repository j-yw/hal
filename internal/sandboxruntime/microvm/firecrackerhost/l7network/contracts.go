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
	Enabled            bool
	Proxy              ProxyLifecycle
	Topology           TopologyLifecycle
	TAP                TAPLifecycle
	Rules              RuleAdapter
	RawPacketIsolation linuxrules.RawPacketIsolationVerifier
	Journal            JournalStore
	StateDir           string
	CleanupTimeout     time.Duration
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
}

func (s tapState) valid(spec tapSpec) bool {
	return s.name != "" && s.name == spec.name && s.generation == spec.generation && s.fingerprint == spec.fingerprint()
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
