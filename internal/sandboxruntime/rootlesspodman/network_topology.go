package rootlesspodman

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	defaultNetworkTopologyCleanupTimeout = 5 * time.Second
	topologyGenerationLabel              = "dev.jywlabs.hal.topology.generation"
	runtimeGenerationLabel               = "dev.jywlabs.hal.runtime.generation"
	ruleGenerationLabel                  = "dev.jywlabs.hal.network-rules.generation"
	topologyAdapterID                    = "rootless-podman-l7"
)

var (
	ErrNetworkTopologyIdentityInvalid         = errors.New("network topology identity invalid")
	ErrNetworkTopologyCreateArgsInvalid       = errors.New("network topology create arguments invalid")
	ErrNetworkTopologyPrepareFailed           = errors.New("network topology prepare failed")
	ErrNetworkTopologySessionMissing          = errors.New("network topology session missing")
	ErrNetworkTopologyInactive                = errors.New("network topology inactive")
	ErrNetworkTopologyActivationFailed        = errors.New("network topology activation failed")
	ErrNetworkTopologyInspectionFailed        = errors.New("network topology inspection failed")
	ErrNetworkTopologyProofMismatch           = errors.New("network topology proof mismatch")
	ErrNetworkTopologyProxyEnvironmentInvalid = errors.New("network topology proxy environment invalid")
	ErrNetworkTopologyRevokeFailed            = errors.New("network topology revoke failed")
	ErrNetworkTopologyCleanupFailed           = errors.New("network topology cleanup failed")
	ErrNetworkTopologyCollision               = errors.New("network topology generation collision")
)

// NetworkTopologyIdentity contains only safe immutable correlation IDs. Live
// endpoints, namespace handles, process IDs, rule bodies, and paths belong to
// the injected session and must never be copied into this value.
type NetworkTopologyIdentity struct {
	SandboxID            string
	ExecutionID          string
	WorkerID             string
	RuntimeDriver        string
	RuntimeGenerationID  string
	PlanID               string
	PolicySnapshotID     string
	ProxySessionID       string
	ProxyGenerationID    string
	TopologyGenerationID string
	RuleGenerationID     string
}

// NetworkTopologyPrepareRequest identifies the stopped container that the
// factory is preparing to own. The factory supplies all other correlation IDs.
type NetworkTopologyPrepareRequest struct {
	SandboxName string
}

// NetworkTopologyPreparation is returned before Podman create. CreateArgs are
// accepted only when they describe the single explicit bounded pasta mapping.
type NetworkTopologyPreparation struct {
	Identity   NetworkTopologyIdentity
	CreateArgs []string
	Session    NetworkTopologySession
}

// NetworkTopologyTargetRequest binds a live operation to one exact Podman
// runtime generation and its previously validated safe identity.
type NetworkTopologyTargetRequest struct {
	Identity NetworkTopologyIdentity
	Target   sandboxruntime.Target
}

// NetworkTopologyProof is the fakeable runtime-owned inspection result. It is
// safe metadata only; the proxy endpoint and Linux inspection payload stay in
// the session implementation.
type NetworkTopologyProof struct {
	Identity       NetworkTopologyIdentity
	RuntimeID      string
	RuleDigest     string
	ProxyActive    bool
	RulesInspected bool
}

// NetworkTopologyFactory is the disabled-by-default L7 injection seam.
type NetworkTopologyFactory interface {
	PrepareNetworkTopology(context.Context, NetworkTopologyPrepareRequest) (NetworkTopologyPreparation, error)
}

// NetworkTopologySession owns one exact live proxy/topology/rule generation.
// Revoke must quarantine before Cleanup removes owned resources. Loss closes
// when the proxy generation can no longer support active proof.
type NetworkTopologySession interface {
	Activate(context.Context, NetworkTopologyTargetRequest) (NetworkTopologyProof, error)
	Inspect(context.Context, NetworkTopologyTargetRequest) (NetworkTopologyProof, error)
	ProxyEnvironment(NetworkTopologyTargetRequest) map[string]string
	Revoke(context.Context, NetworkTopologyTargetRequest) error
	Cleanup(context.Context, NetworkTopologyTargetRequest) error
	Loss() <-chan struct{}
}

// NetworkTopologyError deliberately omits injected error detail so endpoints,
// namespace paths, rule bodies, and process metadata cannot cross the runtime
// boundary. Reason remains unwrap-compatible for stable classification.
type NetworkTopologyError struct {
	Operation string
	Reason    error
}

func (e *NetworkTopologyError) Error() string {
	if e == nil {
		return ""
	}
	operation := safeTopologyOperation(e.Operation)
	if operation == "" {
		operation = "lifecycle"
	}
	reason := safeTopologyReason(e.Reason)
	return fmt.Sprintf("%s network topology %s failed: %s", DriverID, operation, reason.Error())
}

func (e *NetworkTopologyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return safeTopologyReason(e.Reason)
}

type networkTopologyEntry struct {
	mu            sync.Mutex
	identity      NetworkTopologyIdentity
	session       NetworkTopologySession
	target        sandboxruntime.Target
	proxyAddress  netip.Addr
	loss          <-chan struct{}
	proof         NetworkTopologyProof
	active        bool
	cleaned       bool
	deleteDone    bool
	watchStop     chan struct{}
	watchStart    sync.Once
	watchStopOnce sync.Once
}

func (d *Driver) prepareNetworkTopology(ctx context.Context, name string) (*networkTopologyEntry, []string, error) {
	if d == nil || d.networkTopologyFactory == nil {
		return nil, nil, nil
	}
	preparation, err := d.networkTopologyFactory.PrepareNetworkTopology(ctx, NetworkTopologyPrepareRequest{SandboxName: name})
	if err != nil {
		if preparation.Session != nil {
			d.cleanupUnregisteredTopology(preparation.Identity, preparation.Session, sandboxruntime.Target{})
		}
		return nil, nil, topologyError(OperationCreate, ErrNetworkTopologyPrepareFailed)
	}
	entry := &networkTopologyEntry{
		identity:  preparation.Identity,
		session:   preparation.Session,
		watchStop: make(chan struct{}),
	}
	var loss <-chan struct{}
	if preparation.Session != nil {
		loss = preparation.Session.Loss()
	}
	proxyAddress, validationErr := validateNetworkTopologyPreparation(preparation, loss)
	if validationErr != nil {
		if preparation.Session != nil {
			d.cleanupUnregisteredTopology(preparation.Identity, preparation.Session, sandboxruntime.Target{})
		}
		return nil, nil, validationErr
	}
	entry.proxyAddress = proxyAddress
	entry.loss = loss
	return entry, cloneStringSlice(preparation.CreateArgs), nil
}

func validateNetworkTopologyPreparation(preparation NetworkTopologyPreparation, loss <-chan struct{}) (netip.Addr, error) {
	if preparation.Session == nil || loss == nil || !validNetworkTopologyIdentity(preparation.Identity) {
		return netip.Addr{}, topologyError(OperationCreate, ErrNetworkTopologyIdentityInvalid)
	}
	proxyAddress, err := validatePastaCreateArgs(preparation.CreateArgs)
	if err != nil {
		return netip.Addr{}, topologyError(OperationCreate, ErrNetworkTopologyCreateArgsInvalid)
	}
	return proxyAddress, nil
}

func validNetworkTopologyIdentity(identity NetworkTopologyIdentity) bool {
	values := []string{
		identity.SandboxID,
		identity.ExecutionID,
		identity.WorkerID,
		identity.RuntimeGenerationID,
		identity.PlanID,
		identity.PolicySnapshotID,
		identity.ProxySessionID,
		identity.ProxyGenerationID,
		identity.TopologyGenerationID,
		identity.RuleGenerationID,
	}
	if identity.RuntimeDriver != DriverID {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !safeTopologyIdentifier(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validatePastaCreateArgs(args []string) (netip.Addr, error) {
	if len(args) != 2 || args[0] != "--network" {
		return netip.Addr{}, ErrNetworkTopologyCreateArgsInvalid
	}
	const prefix = "pasta:"
	if !strings.HasPrefix(args[1], prefix) {
		return netip.Addr{}, ErrNetworkTopologyCreateArgsInvalid
	}
	options := strings.Split(strings.TrimPrefix(args[1], prefix), ",")
	if len(options) != 10 ||
		options[0] != "--no-map-gw" ||
		!strings.HasPrefix(options[1], "--map-host-loopback=") ||
		options[2] != "-t" || options[3] != "none" ||
		options[4] != "-u" || options[5] != "none" ||
		options[6] != "-T" || options[7] != "none" ||
		options[8] != "-U" || options[9] != "none" {
		return netip.Addr{}, ErrNetworkTopologyCreateArgsInvalid
	}
	address, err := netip.ParseAddr(strings.TrimPrefix(options[1], "--map-host-loopback="))
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return netip.Addr{}, ErrNetworkTopologyCreateArgsInvalid
	}
	return address, nil
}

func (d *Driver) registerNetworkTopology(entry *networkTopologyEntry, target sandboxruntime.Target) error {
	if d == nil || entry == nil {
		return nil
	}
	key, err := exactTopologyRuntimeID(target)
	if err != nil {
		return err
	}
	entry.target = target
	d.networkTopologyMu.Lock()
	defer d.networkTopologyMu.Unlock()
	if d.networkTopologySessions == nil {
		d.networkTopologySessions = make(map[string]*networkTopologyEntry)
	}
	if _, exists := d.networkTopologySessions[key]; exists {
		return topologyError(OperationCreate, ErrNetworkTopologyCollision)
	}
	d.networkTopologySessions[key] = entry
	return nil
}

func (d *Driver) topologyEntryForTarget(target sandboxruntime.Target) (*networkTopologyEntry, error) {
	if d == nil || d.networkTopologyFactory == nil {
		return nil, nil
	}
	key, err := exactTopologyRuntimeID(target)
	if err != nil {
		return nil, topologyError(OperationExec, ErrNetworkTopologySessionMissing)
	}
	d.networkTopologyMu.Lock()
	entry := d.networkTopologySessions[key]
	d.networkTopologyMu.Unlock()
	if entry == nil {
		return nil, topologyError(OperationExec, ErrNetworkTopologySessionMissing)
	}
	return entry, nil
}

func exactTopologyRuntimeID(target sandboxruntime.Target) (string, error) {
	runtimeID := strings.TrimSpace(target.Runtime.RuntimeID)
	if runtimeID == "" || !safeTopologyIdentifier(runtimeID) {
		return "", ErrNetworkTopologySessionMissing
	}
	if targetID := strings.TrimSpace(target.ID); targetID == "" || targetID != runtimeID {
		return "", ErrNetworkTopologySessionMissing
	}
	if driver := strings.TrimSpace(target.Runtime.Driver); driver != "" && driver != DriverID {
		return "", ErrNetworkTopologySessionMissing
	}
	return runtimeID, nil
}

func (d *Driver) activateNetworkTopology(ctx context.Context, entry *networkTopologyEntry, target *sandboxruntime.Target) error {
	if entry == nil || target == nil {
		return topologyError(OperationStart, ErrNetworkTopologySessionMissing)
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.cleaned {
		return topologyError(OperationStart, ErrNetworkTopologySessionMissing)
	}
	request := NetworkTopologyTargetRequest{Identity: entry.identity, Target: *target}
	proof, err := entry.session.Activate(ctx, request)
	if err != nil {
		return topologyError(OperationStart, ErrNetworkTopologyActivationFailed)
	}
	if err := validateNetworkTopologyProof(entry, *target, proof); err != nil {
		return err
	}
	inspected, err := entry.session.Inspect(ctx, request)
	if err != nil {
		return topologyError(OperationStart, ErrNetworkTopologyInspectionFailed)
	}
	if inspected != proof {
		return topologyError(OperationStart, ErrNetworkTopologyProofMismatch)
	}
	if err := validateNetworkTopologyProof(entry, *target, inspected); err != nil {
		return err
	}
	select {
	case <-entry.loss:
		return topologyError(OperationStart, ErrNetworkTopologyActivationFailed)
	default:
	}
	entry.target = *target
	entry.proof = inspected
	entry.active = true
	projectNetworkTopologyProof(target, inspected)
	d.watchNetworkTopologyLoss(entry)
	return nil
}

func validateNetworkTopologyProof(entry *networkTopologyEntry, target sandboxruntime.Target, proof NetworkTopologyProof) error {
	runtimeID, err := exactTopologyRuntimeID(target)
	if err != nil || entry == nil || proof.Identity != entry.identity || proof.RuntimeID != runtimeID ||
		!proof.ProxyActive || !proof.RulesInspected || !safeTopologyIdentifier(proof.RuleDigest) {
		return topologyError(OperationStart, ErrNetworkTopologyProofMismatch)
	}
	return nil
}

func (d *Driver) watchNetworkTopologyLoss(entry *networkTopologyEntry) {
	if entry == nil || entry.session == nil {
		return
	}
	if entry.loss == nil {
		return
	}
	entry.watchStart.Do(func() {
		go func() {
			select {
			case <-entry.loss:
				d.revokeNetworkTopologyAfterLoss(entry)
			case <-entry.watchStop:
			}
		}()
	})
}

func (d *Driver) revokeNetworkTopologyAfterLoss(entry *networkTopologyEntry) {
	entry.mu.Lock()
	if entry.cleaned || !entry.active {
		entry.mu.Unlock()
		return
	}
	target := entry.target
	entry.mu.Unlock()
	_ = d.revokeAndCleanupNetworkTopology(entry, target, OperationStop, true, func(ctx context.Context) error {
		ref, err := containerRef(target)
		if err != nil {
			return operationError(OperationStop, CommandResult{}, err)
		}
		_, err = d.runLifecycleCommand(ctx, CommandRequest{Operation: OperationStop, Args: d.stopArgs(ref)})
		return err
	})
}

func (d *Driver) topologyExecEnvironment(ctx context.Context, target sandboxruntime.Target, caller map[string]string) (map[string]string, error) {
	entry, err := d.topologyEntryForTarget(target)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return cloneStringMap(caller), nil
	}
	entry.mu.Lock()
	if entry.cleaned || !entry.active {
		entry.mu.Unlock()
		return nil, topologyError(OperationExec, ErrNetworkTopologyInactive)
	}
	request := NetworkTopologyTargetRequest{Identity: entry.identity, Target: target}
	inspected, inspectErr := entry.session.Inspect(ctx, request)
	if inspectErr != nil || inspected != entry.proof || validateNetworkTopologyProof(entry, target, inspected) != nil {
		entry.active = false
		entry.proof = NetworkTopologyProof{}
		entry.mu.Unlock()
		d.quiesceNetworkTopologyAfterProofLoss(entry, target)
		return nil, topologyError(OperationExec, ErrNetworkTopologyInspectionFailed)
	}
	proxyEnv := entry.session.ProxyEnvironment(request)
	if err := validateNetworkTopologyProxyEnvironment(proxyEnv, entry.proxyAddress); err != nil {
		entry.active = false
		entry.proof = NetworkTopologyProof{}
		entry.mu.Unlock()
		d.quiesceNetworkTopologyAfterProofLoss(entry, target)
		return nil, topologyError(OperationExec, ErrNetworkTopologyProxyEnvironmentInvalid)
	}
	env := cloneStringMap(caller)
	if env == nil {
		env = make(map[string]string, len(proxyEnv))
	}
	for _, key := range []string{"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"} {
		delete(env, key)
	}
	for key, value := range proxyEnv {
		env[key] = value
	}
	entry.mu.Unlock()
	return env, nil
}

func validateNetworkTopologyProxyEnvironment(values map[string]string, proxyAddress netip.Addr) error {
	required := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}
	if len(values) != len(required) || !proxyAddress.IsValid() {
		return ErrNetworkTopologyProxyEnvironmentInvalid
	}
	endpoint := ""
	for _, key := range required {
		value, ok := values[key]
		if !ok || value == "" || (endpoint != "" && value != endpoint) {
			return ErrNetworkTopologyProxyEnvironmentInvalid
		}
		endpoint = value
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrNetworkTopologyProxyEnvironmentInvalid
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || address.Zone() != "" || address != proxyAddress || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return ErrNetworkTopologyProxyEnvironmentInvalid
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return ErrNetworkTopologyProxyEnvironmentInvalid
	}
	return nil
}

func (d *Driver) quiesceNetworkTopologyAfterProofLoss(entry *networkTopologyEntry, target sandboxruntime.Target) {
	_ = d.revokeAndCleanupNetworkTopology(entry, target, OperationExec, true, func(ctx context.Context) error {
		ref, err := containerRef(target)
		if err != nil {
			return operationError(OperationStop, CommandResult{}, err)
		}
		_, err = d.runLifecycleCommand(ctx, CommandRequest{Operation: OperationStop, Args: d.stopArgs(ref)})
		return err
	})
}

func (d *Driver) revokeAndCleanupNetworkTopology(entry *networkTopologyEntry, target sandboxruntime.Target, operation string, retainTombstone bool, runtimeAction func(context.Context) error) error {
	if entry == nil {
		ctx := context.Background()
		return runtimeAction(ctx)
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.cleaned {
		err := runtimeAction(context.Background())
		if err == nil && !retainTombstone {
			d.removeNetworkTopologyEntry(entry, target)
		}
		return err
	}
	entry.active = false
	entry.proof = NetworkTopologyProof{}
	request := NetworkTopologyTargetRequest{Identity: entry.identity, Target: target}
	ctx, cancel := d.networkTopologyCleanupContext()
	defer cancel()
	var result error
	if err := entry.session.Revoke(ctx, request); err != nil {
		result = errors.Join(result, topologyError(operation, ErrNetworkTopologyRevokeFailed))
	}
	if operation != OperationDelete || !entry.deleteDone {
		if err := runtimeAction(ctx); err != nil {
			return errors.Join(result, err, topologyError(operation, ErrNetworkTopologyCleanupFailed))
		}
		if operation == OperationDelete {
			// The entry is bound to one exact runtime generation. Retain successful
			// removal ownership across a transient session cleanup failure so a
			// retry can finish cleanup without deleting the absent container again.
			entry.deleteDone = true
		}
	}
	if err := entry.session.Cleanup(ctx, request); err != nil {
		return errors.Join(result, topologyError(operation, ErrNetworkTopologyCleanupFailed))
	}
	entry.cleaned = true
	entry.watchStopOnce.Do(func() { close(entry.watchStop) })
	if !retainTombstone {
		d.removeNetworkTopologyEntry(entry, target)
	}
	return result
}

func (d *Driver) rollbackNetworkTopologyStart(entry *networkTopologyEntry, target sandboxruntime.Target, cause error) error {
	cleanupErr := d.revokeAndCleanupNetworkTopology(entry, target, OperationStart, false, func(ctx context.Context) error {
		ref, err := containerRef(target)
		if err != nil {
			return operationError(OperationStop, CommandResult{}, err)
		}
		_, err = d.runLifecycleCommand(ctx, CommandRequest{Operation: OperationStop, Args: d.stopArgs(ref)})
		return err
	})
	return errors.Join(cause, cleanupErr)
}

func (d *Driver) removeNetworkTopologyEntry(entry *networkTopologyEntry, target sandboxruntime.Target) {
	key, err := exactTopologyRuntimeID(target)
	if err != nil {
		return
	}
	d.networkTopologyMu.Lock()
	if d.networkTopologySessions[key] == entry {
		delete(d.networkTopologySessions, key)
	}
	d.networkTopologyMu.Unlock()
}

func (d *Driver) cleanupUnregisteredTopology(identity NetworkTopologyIdentity, session NetworkTopologySession, target sandboxruntime.Target) {
	ctx, cancel := d.networkTopologyCleanupContext()
	defer cancel()
	_ = session.Cleanup(ctx, NetworkTopologyTargetRequest{Identity: identity, Target: target})
}

func (d *Driver) networkTopologyCleanupContext() (context.Context, context.CancelFunc) {
	timeout := defaultNetworkTopologyCleanupTimeout
	if d != nil && d.networkTopologyCleanupTimeout > 0 {
		timeout = d.networkTopologyCleanupTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func projectNetworkTopologyProof(target *sandboxruntime.Target, proof NetworkTopologyProof) {
	if target == nil {
		return
	}
	metadata := sandboxruntime.RuntimeMetadata{}
	if target.Runtime.Metadata != nil {
		if existing := sandboxruntime.SanitizeRuntimeMetadata(target.Runtime.Metadata); existing != nil {
			metadata = *existing
		}
	}
	identity := proof.Identity
	metadata.NetworkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(&sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               identity.PlanID,
			Source:           "runtime",
			Operation:        "l7_topology",
			PolicySnapshotID: identity.PolicySnapshotID,
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_mapping", "inspect_rules"},
		},
		Orchestration: &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           identity.PlanID,
			AdapterID:        topologyAdapterID,
			Status:           "active",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_mapping", "inspect_rules"},
			PolicySnapshotID: identity.PolicySnapshotID,
			PolicyPreset:     "deny_by_default",
			Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				ID: identity.ProxyGenerationID, PlanID: identity.PlanID, AdapterID: topologyAdapterID,
				Status: "active", Mechanisms: []string{"proxy"}, Operations: []string{"proxy_mapping"},
				PolicySnapshotID: identity.PolicySnapshotID, PolicyPreset: "deny_by_default", ReasonCode: "active",
			},
			Rules: []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{{
				ID: identity.RuleGenerationID, PlanID: identity.PlanID, AdapterID: topologyAdapterID,
				Status: "active", Mechanisms: []string{"firewall"}, Operations: []string{"inspect_rules"},
				PolicySnapshotID: identity.PolicySnapshotID, PolicyPreset: "deny_by_default", ReasonCode: "active",
			}},
			ReasonCode: "active",
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID: identity.PlanID, AdapterID: topologyAdapterID,
			Outcome: "best_effort", EnforcementMode: "best_effort",
			Mechanisms: []string{"proxy", "firewall"}, Operations: []string{"proxy_mapping", "inspect_rules"},
			PolicySnapshotID: identity.PolicySnapshotID, PolicyPreset: "deny_by_default",
			ReasonCode: "best_effort", WarningCodes: []string{"capability_downgraded"},
		},
	})
	target.Runtime.Metadata = sandboxruntime.SanitizeRuntimeMetadata(&metadata)
}

func clearNetworkTopologyProof(target *sandboxruntime.Target) {
	if target == nil || target.Runtime.Metadata == nil {
		return
	}
	metadata := *target.Runtime.Metadata
	metadata.NetworkEnforcement = nil
	target.Runtime.Metadata = sandboxruntime.SanitizeRuntimeMetadata(&metadata)
}

func (d *Driver) projectCurrentNetworkTopologyProof(target *sandboxruntime.Target) {
	if target == nil || d == nil || d.networkTopologyFactory == nil {
		return
	}
	clearNetworkTopologyProof(target)
	entry, err := d.topologyEntryForTarget(*target)
	if err != nil || entry == nil {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.active && !entry.cleaned {
		projectNetworkTopologyProof(target, entry.proof)
	}
}

func (d *Driver) createArgsWithNetworkTopology(name string, createArgs []string, identity *NetworkTopologyIdentity) []string {
	return d.createArgsWithNetworkTopologyImage(name, d.image, createArgs, identity)
}

func (d *Driver) createArgsWithNetworkTopologyImage(name, image string, createArgs []string, identity *NetworkTopologyIdentity) []string {
	args := []string{
		d.podmanPath,
		"create",
		"--pull=never",
		"--init",
		"--name", name,
		"--hostname", name,
		"--label", labelRuntime + "=" + DriverID,
		"--label", labelSandboxName + "=" + name,
	}
	if identity != nil {
		args = append(args,
			"--cap-drop=ALL",
			"--label", topologyGenerationLabel+"="+identity.TopologyGenerationID,
			"--label", runtimeGenerationLabel+"="+identity.RuntimeGenerationID,
			"--label", ruleGenerationLabel+"="+identity.RuleGenerationID,
		)
		args = append(args, createArgs...)
	}
	return append(args,
		"--security-opt", "no-new-privileges",
		"--workdir", d.workDir,
		image,
		"sleep", "infinity",
	)
}

func safeTopologyIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func safeTopologyOperation(value string) string {
	switch value {
	case OperationCreate, OperationStart, OperationInspect, OperationStop, OperationDelete, OperationExec:
		return value
	default:
		return ""
	}
}

func safeTopologyReason(reason error) error {
	for _, candidate := range []error{
		ErrNetworkTopologyIdentityInvalid,
		ErrNetworkTopologyCreateArgsInvalid,
		ErrNetworkTopologyPrepareFailed,
		ErrNetworkTopologySessionMissing,
		ErrNetworkTopologyInactive,
		ErrNetworkTopologyActivationFailed,
		ErrNetworkTopologyInspectionFailed,
		ErrNetworkTopologyProofMismatch,
		ErrNetworkTopologyProxyEnvironmentInvalid,
		ErrNetworkTopologyRevokeFailed,
		ErrNetworkTopologyCleanupFailed,
		ErrNetworkTopologyCollision,
	} {
		if errors.Is(reason, candidate) {
			return candidate
		}
	}
	return ErrNetworkTopologyPrepareFailed
}

func topologyError(operation string, reason error) error {
	return &NetworkTopologyError{Operation: operation, Reason: safeTopologyReason(reason)}
}
