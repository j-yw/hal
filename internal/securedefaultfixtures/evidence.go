package securedefaultfixtures

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

// Proof identifies one fake secure-default evidence source. The values are
// safe marker names so tests can persist them directly when useful.
type Proof string

const (
	ProofStrictTargetSelection    Proof = "strict_target_selection"
	ProofMicroVMReadiness         Proof = "microvm_readiness"
	ProofWorkspaceIsolation       Proof = "workspace_isolation"
	ProofProxyFirewallEnforcement Proof = "proxy_firewall_enforcement"
	ProofCredentialDelivery       Proof = "credential_delivery"
	ProofTemplateTrust            Proof = "template_trust"
)

// ProofState records whether a fixture proof is complete, omitted, or
// intentionally downgraded.
type ProofState string

const (
	ProofStateComplete   ProofState = "complete"
	ProofStateOmitted    ProofState = "omitted"
	ProofStateDowngraded ProofState = "downgraded"
)

// Downgrade chooses the incomplete shape used by DowngradeProof.
type Downgrade string

const (
	DowngradeDefault        Downgrade = "default"
	DowngradeCompatibility  Downgrade = "compatibility"
	DowngradeMetadataOnly   Downgrade = "metadata_only"
	DowngradeUnsupported    Downgrade = "unsupported"
	DowngradeBlocked        Downgrade = "blocked"
	DowngradeWarningBearing Downgrade = "warning_bearing"
	DowngradeProxyOnly      Downgrade = "proxy_only"
	DowngradeFirewallOnly   Downgrade = "firewall_only"
	DowngradeBestEffort     Downgrade = "best_effort"
	DowngradeFailed         Downgrade = "failed"
	DowngradeAdvisory       Downgrade = "advisory"
	DowngradePartial        Downgrade = "partial"
	DowngradePlanned        Downgrade = "planned"
	DowngradeFakeOnly       Downgrade = "fake_only"
	DowngradeHistorical     Downgrade = "historical"
)

// Option customizes a fake secure-default evidence set.
type Option func(*builder)

// EvidenceSet contains reusable fake evidence projected through the same
// sanitized sandbox contracts that command and target-selection tests consume.
type EvidenceSet struct {
	GateMode              sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
	StrictTargetSelection bool
	ProofStates           map[Proof]ProofState
	Downgrades            map[Proof]Downgrade

	Requested             sandbox.SandboxSecurityCapabilityReadinessInput
	WorkerRuntime         sandbox.SandboxWorkerRuntimeCapabilityReadinessProjection
	PolicyProxyCredential sandbox.SandboxPolicyProxyCredentialCapabilityReadinessProjection
	Input                 sandbox.SandboxSecurityCapabilityReadinessInput
	Readiness             sandbox.SandboxSecurityCapabilityReadinessOutput
	Diagnostics           sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary
	Gate                  sandbox.SandboxSecurityCapabilityReadinessGateDecision
}

type builder struct {
	states     map[Proof]ProofState
	downgrades map[Proof]Downgrade
	gateMode   sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
}

// RequiredProofs returns the proof markers included in the complete fixture.
func RequiredProofs() []Proof {
	return []Proof{
		ProofStrictTargetSelection,
		ProofMicroVMReadiness,
		ProofWorkspaceIsolation,
		ProofProxyFirewallEnforcement,
		ProofCredentialDelivery,
		ProofTemplateTrust,
	}
}

// OmitProof leaves the requirement in place while removing the selected proof
// source. For ProofStrictTargetSelection, it switches the fixture gate mode off.
func OmitProof(proof Proof) Option {
	return func(b *builder) {
		if !knownProof(proof) {
			return
		}
		b.states[proof] = ProofStateOmitted
		if proof == ProofStrictTargetSelection {
			b.gateMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff
		}
	}
}

// DowngradeProof keeps the selected proof present but incomplete. When no
// downgrade is provided, a proof-specific incomplete default is used.
func DowngradeProof(proof Proof, downgrades ...Downgrade) Option {
	return func(b *builder) {
		if !knownProof(proof) {
			return
		}
		downgrade := DowngradeDefault
		if len(downgrades) > 0 && downgrades[0] != "" {
			downgrade = downgrades[0]
		}
		b.states[proof] = ProofStateDowngraded
		b.downgrades[proof] = downgrade
		if proof == ProofStrictTargetSelection {
			b.gateMode = targetSelectionGateModeForDowngrade(downgrade)
		}
	}
}

// WithGateMode overrides the decision policy used to derive EvidenceSet.Gate.
func WithGateMode(mode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode) Option {
	return func(b *builder) {
		switch mode {
		case sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
			sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
			sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff:
			b.gateMode = mode
		}
	}
}

// CompleteAcceptedEvidenceSet builds the accepted fake evidence set, then
// applies any requested omissions or downgrades independently.
func CompleteAcceptedEvidenceSet(opts ...Option) EvidenceSet {
	b := defaultBuilder()
	for _, opt := range opts {
		if opt != nil {
			opt(&b)
		}
	}

	requested := requestedSecureDefaultInput()
	workerRuntime := sandbox.SandboxWorkerRuntimeCapabilityReadinessProjection{}
	policyProxyCredential := sandbox.SandboxPolicyProxyCredentialCapabilityReadinessProjection{}

	switch b.state(ProofMicroVMReadiness) {
	case ProofStateComplete:
		workerRuntime.MicroVMIsolationProof = completeMicroVMProof()
	case ProofStateDowngraded:
		workerRuntime.MicroVMIsolationProof = downgradedMicroVMProof(b.downgrade(ProofMicroVMReadiness))
	}

	switch b.state(ProofWorkspaceIsolation) {
	case ProofStateComplete:
		workerRuntime.Workspace = isolatedWorkspace()
	case ProofStateDowngraded:
		workerRuntime.Workspace = downgradedWorkspace(b.downgrade(ProofWorkspaceIsolation))
	}

	switch b.state(ProofTemplateTrust) {
	case ProofStateComplete:
		workerRuntime.TemplateLock = trustedTemplateLock()
	case ProofStateDowngraded:
		workerRuntime.TemplateLock = downgradedTemplateLock(b.downgrade(ProofTemplateTrust))
	}

	switch b.state(ProofProxyFirewallEnforcement) {
	case ProofStateComplete:
		policyProxyCredential.NetworkEnforcementProof = completeNetworkProof()
	case ProofStateDowngraded:
		policyProxyCredential.NetworkEnforcementProof = downgradedNetworkProof(b.downgrade(ProofProxyFirewallEnforcement))
	}

	policyProxyCredential.CredentialProxyPlan = credentialProxyPlan()
	policyProxyCredential.CredentialProxySession = credentialProxySession()
	policyProxyCredential.CredentialProxyBindings = []sandbox.SandboxCredentialProxyBindingMetadata{credentialBinding()}
	switch b.state(ProofCredentialDelivery) {
	case ProofStateComplete:
		policyProxyCredential.CredentialDelivery = completeCredentialDeliveryStatus()
	case ProofStateDowngraded:
		if b.downgrade(ProofCredentialDelivery) == DowngradePartial {
			session := *policyProxyCredential.CredentialProxySession
			session.SecretBrokerSessionID = ""
			policyProxyCredential.CredentialProxySession = &session
		}
		policyProxyCredential.CredentialDelivery = downgradedCredentialDeliveryStatus(b.downgrade(ProofCredentialDelivery))
	}

	input := sandbox.MergeSandboxSecurityCapabilityReadinessInputs(
		requested,
		sandbox.ProjectSandboxWorkerRuntimeCapabilityReadinessInput(workerRuntime),
		sandbox.ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(policyProxyCredential),
	)
	readiness := sandbox.SandboxSecurityCapabilityReadinessOutput{}
	if output := sandbox.EvaluateProjectedSandboxSecurityCapabilityReadiness(input); output != nil {
		readiness = *output
	}
	diagnostics := sandbox.ProjectSandboxSecureDefaultReadinessDiagnostics(readiness)
	gate := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(b.gateMode, diagnostics)
	if b.state(ProofStrictTargetSelection) == ProofStateDowngraded {
		gate = downgradedTargetSelectionGate(gate, b.downgrade(ProofStrictTargetSelection))
	}
	strictTargetSelection := b.state(ProofStrictTargetSelection) == ProofStateComplete &&
		b.gateMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict &&
		gate.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed

	return EvidenceSet{
		GateMode:              b.gateMode,
		StrictTargetSelection: strictTargetSelection,
		ProofStates:           b.proofStates(),
		Downgrades:            b.proofDowngrades(),
		Requested:             sandbox.SanitizeSandboxSecurityCapabilityReadinessInput(requested),
		WorkerRuntime:         workerRuntime,
		PolicyProxyCredential: policyProxyCredential,
		Input:                 input,
		Readiness:             readiness,
		Diagnostics:           diagnostics,
		Gate:                  gate,
	}
}

// Security returns a sandbox security surface populated with sanitized
// readiness diagnostics and the evaluated gate decision.
func (set EvidenceSet) Security() *sandbox.SandboxSecurity {
	readiness := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(set.Readiness)
	diagnostics := sandbox.ProjectSandboxSecureDefaultReadinessDiagnostics(readiness)
	gate := sandbox.SanitizeSandboxSecurityCapabilityReadinessGateDecision(set.Gate)
	return &sandbox.SandboxSecurity{
		Network: &sandbox.SandboxNetworkSecurity{
			PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
			PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		},
		Secrets: &sandbox.SandboxSecretSecurity{
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
		},
		CapabilityReadiness:            &readiness,
		CapabilityReadinessDiagnostics: &diagnostics,
		SecurityReadinessGate:          &gate,
	}
}

// ReadinessPtr returns a sanitized copy of the projected readiness output.
func (set EvidenceSet) ReadinessPtr() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	readiness := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(set.Readiness)
	if len(readiness.Results) == 0 {
		return nil
	}
	return &readiness
}

func defaultBuilder() builder {
	states := make(map[Proof]ProofState)
	for _, proof := range RequiredProofs() {
		states[proof] = ProofStateComplete
	}
	return builder{
		states:     states,
		downgrades: make(map[Proof]Downgrade),
		gateMode:   sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}
}

func (b builder) state(proof Proof) ProofState {
	if state := b.states[proof]; state != "" {
		return state
	}
	return ProofStateComplete
}

func (b builder) downgrade(proof Proof) Downgrade {
	if downgrade := b.downgrades[proof]; downgrade != "" && downgrade != DowngradeDefault {
		return downgrade
	}
	switch proof {
	case ProofStrictTargetSelection:
		return DowngradeCompatibility
	case ProofMicroVMReadiness:
		return DowngradeUnsupported
	case ProofWorkspaceIsolation:
		return DowngradeBlocked
	case ProofProxyFirewallEnforcement:
		return DowngradeProxyOnly
	case ProofCredentialDelivery:
		return DowngradeMetadataOnly
	case ProofTemplateTrust:
		return DowngradeAdvisory
	default:
		return DowngradeMetadataOnly
	}
}

func (b builder) proofStates() map[Proof]ProofState {
	out := make(map[Proof]ProofState, len(b.states))
	for _, proof := range RequiredProofs() {
		out[proof] = b.state(proof)
	}
	return out
}

func (b builder) proofDowngrades() map[Proof]Downgrade {
	out := make(map[Proof]Downgrade, len(b.downgrades))
	for proof, downgrade := range b.downgrades {
		if knownProof(proof) {
			out[proof] = downgrade
		}
	}
	return out
}

func knownProof(proof Proof) bool {
	for _, known := range RequiredProofs() {
		if proof == known {
			return true
		}
	}
	return false
}

func targetSelectionGateModeForDowngrade(downgrade Downgrade) sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	switch downgrade {
	case DowngradeAdvisory:
		return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory
	case DowngradeWarningBearing:
		return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
	default:
		return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility
	}
}

func downgradedTargetSelectionGate(gate sandbox.SandboxSecurityCapabilityReadinessGateDecision, downgrade Downgrade) sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	if downgrade != DowngradeWarningBearing {
		return gate
	}
	return sandbox.SanitizeSandboxSecurityCapabilityReadinessGateDecision(sandbox.SandboxSecurityCapabilityReadinessGateDecision{
		Code:       sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked,
		Outcome:    sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		PolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     sandbox.SandboxSecurityCapabilityReadinessGateReasonCode(sandbox.SandboxSecurityCapabilityReasonWarningBearing),
		Counts: &sandbox.SandboxSecurityCapabilityReadinessGateCounts{
			Total:          1,
			Advisory:       1,
			Unsupported:    1,
			StrictBlocking: 1,
			ReasonCodeCounts: map[sandbox.SandboxSecurityCapabilityReasonCode]int{
				sandbox.SandboxSecurityCapabilityReasonWarningBearing: 1,
			},
		},
	})
}

func requestedSecureDefaultInput() sandbox.SandboxSecurityCapabilityReadinessInput {
	return sandbox.SandboxSecurityCapabilityReadinessInput{
		Requested: []sandbox.SandboxSecurityCapabilityMetadata{
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilyIsolation,
				Capability: sandbox.SandboxSecurityCapabilityIsolationMicroVM,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilyWorkspace,
				Capability: sandbox.SandboxSecurityCapabilityIsolatedWorkspace,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       sandbox.SandboxNetworkEnforcementModeProxyFirewall,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				Capability: sandbox.SandboxSecurityCapabilitySecretHTTPProxy,
				Mode:       sandbox.SandboxSecretModeHTTPProxy,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilyTemplate,
				Capability: sandbox.SandboxSecurityCapabilityTemplateLockDigest,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			{
				Family:     sandbox.SandboxSecurityCapabilityFamilyTemplate,
				Capability: sandbox.SandboxSecurityCapabilitySelectedTemplateTrust,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
		},
	}
}

func completeMicroVMProof() *sandbox.SandboxMicroVMIsolationProofMetadata {
	return &sandbox.SandboxMicroVMIsolationProofMetadata{
		RuntimeDriver:       sandbox.SandboxRuntimeDriverMicroVM,
		IsolationLevel:      sandbox.SandboxIsolationLevelVM,
		RuntimeStatus:       sandbox.StatusRunning,
		GuestReadinessState: "ready",
		ProcessLaunchState:  "accepted",
		ResultSupported:     true,
	}
}

func downgradedMicroVMProof(downgrade Downgrade) *sandbox.SandboxMicroVMIsolationProofMetadata {
	proof := *completeMicroVMProof()
	switch downgrade {
	case DowngradeBlocked, DowngradeUnsupported:
		proof.RuntimeDriver = sandbox.SandboxRuntimeDriverRootlessPodman
		proof.IsolationLevel = sandbox.SandboxIsolationLevelContainer
		proof.ResultSupported = false
	case DowngradeCompatibility:
		proof.RuntimeDriver = sandbox.SandboxRuntimeDriverSSHMachine
		proof.IsolationLevel = sandbox.SandboxIsolationLevelHost
		proof.ResultSupported = false
	case DowngradePlanned, DowngradeMetadataOnly:
		proof.RuntimeStatus = "planned"
	case DowngradeFakeOnly:
		proof.GuestReadinessState = "not_configured"
		proof.ProcessLaunchState = "boundary_available"
	case DowngradeHistorical:
		proof.ProcessLaunchState = "attempted"
	case DowngradeWarningBearing:
		proof.WarningCount = 1
	default:
		proof.RuntimeStatus = "planned"
	}
	return &proof
}

func isolatedWorkspace() *sandbox.SandboxWorkspace {
	return &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Branch:      "phase60-secure-default",
		SyncRef:     "sync-phase60-secure-default",
	}
}

func downgradedWorkspace(downgrade Downgrade) *sandbox.SandboxWorkspace {
	workspace := *isolatedWorkspace()
	switch downgrade {
	case DowngradeMetadataOnly, DowngradeUnsupported:
		workspace.Mode = ""
		workspace.InputSource = ""
	default:
		workspace.Mode = sandbox.SandboxWorkspaceModeDirect
		workspace.InputSource = sandbox.SandboxWorkspaceInputSourceCopy
		workspace.SyncRef = "direct-host-workspace"
	}
	return &workspace
}

func completeNetworkProof() *sandbox.SandboxNetworkEnforcementProofMetadata {
	return &sandbox.SandboxNetworkEnforcementProofMetadata{
		NetworkProxySessionID:       "network-proxy-session-proof",
		PolicySnapshotID:            "policy-snapshot-proof",
		NetworkEnforcementPlanID:    "network-enforcement-plan-proof",
		ProxyLifecycleStatus:        "active",
		ProxyLifecycleReasonCode:    "active",
		FirewallLifecycleStatus:     "active",
		FirewallLifecycleReasonCode: "active",
		ResultOutcome:               "success",
		ResultEnforcementMode:       sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		ResultSupported:             true,
	}
}

func downgradedNetworkProof(downgrade Downgrade) *sandbox.SandboxNetworkEnforcementProofMetadata {
	proof := *completeNetworkProof()
	switch downgrade {
	case DowngradeFirewallOnly:
		proof.ProxyLifecycleStatus = "planned"
		proof.ProxyLifecycleReasonCode = "prepared"
		proof.ResultEnforcementMode = sandbox.SandboxNetworkEnforcementModeFirewall
	case DowngradeBestEffort:
		proof.ResultOutcome = "best_effort"
		proof.ResultEnforcementMode = sandbox.SandboxNetworkEnforcementModeBestEffort
	case DowngradeUnsupported:
		proof.ResultOutcome = "unsupported"
		proof.ResultSupported = false
	case DowngradeFailed, DowngradeBlocked:
		proof.ProxyLifecycleStatus = "failed"
		proof.ProxyLifecycleReasonCode = "adapter_failed"
		proof.ResultOutcome = "failure"
		proof.ResultSupported = false
	case DowngradeWarningBearing:
		proof.WarningCount = 1
	default:
		proof.FirewallLifecycleStatus = "planned"
		proof.FirewallLifecycleReasonCode = "prepared"
		proof.ResultEnforcementMode = sandbox.SandboxNetworkEnforcementModeProxy
	}
	return &proof
}

func credentialBinding() sandbox.SandboxCredentialProxyBindingMetadata {
	return sandbox.SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-http-proxy",
		PlanID:              "credential-plan-http-proxy",
		SessionID:           "credential-session-http-proxy",
		SecretID:            "secret-service-ref",
		DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy,
		RequestCategory:     sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
		Outcome:             sandbox.SandboxCredentialProxyBindingOutcomeBound,
		Status:              sandbox.SandboxCredentialProxyStatusReady,
		ReasonCode:          sandbox.SandboxCredentialProxyReasonRequested,
	}
}

func credentialProxyPlan() *sandbox.SandboxCredentialProxyPlanMetadata {
	return &sandbox.SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-http-proxy",
		Source:                sandbox.SandboxCredentialProxySourceWorker,
		SecretBrokerSessionID: "secret-broker-session-proof",
		NetworkProxySessionID: "network-proxy-session-proof",
		Mode:                  sandbox.SandboxCredentialProxyModeBrokeredNetworkReference,
		Status:                sandbox.SandboxCredentialProxyStatusReady,
		BindingCount:          1,
	}
}

func credentialProxySession() *sandbox.SandboxCredentialProxySessionMetadata {
	return &sandbox.SandboxCredentialProxySessionMetadata{
		ID:                    "credential-session-http-proxy",
		PlanID:                "credential-plan-http-proxy",
		Source:                sandbox.SandboxCredentialProxySourceWorker,
		SecretBrokerSessionID: "secret-broker-session-proof",
		NetworkProxySessionID: "network-proxy-session-proof",
		Status:                sandbox.SandboxCredentialProxyStatusActive,
		ReasonCode:            sandbox.SandboxCredentialProxyReasonRequested,
	}
}

func completeCredentialDeliveryStatus() *sandbox.SandboxCredentialDeliveryStatusMetadata {
	return &sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-delivery-active",
		PlanID:         "credential-plan-http-proxy",
		ActivationID:   "credential-activation-http-proxy",
		RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
		ActiveProofs: []sandbox.SandboxCredentialDeliveryProofSummary{{
			ProofID:      "credential-proof-http-proxy",
			BindingID:    "credential-binding-http-proxy",
			DeliveryMode: sandbox.SandboxSecretModeHTTPProxy,
			Status:       "active",
			Source:       "broker",
		}},
		Status:     "active",
		ReasonCode: "requested",
	}
}

func downgradedCredentialDeliveryStatus(downgrade Downgrade) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	status := *completeCredentialDeliveryStatus()
	switch downgrade {
	case DowngradeAdvisory:
		status.Status = "ready"
		status.ActivationID = ""
		status.ActiveModes = nil
		status.ActiveProofs = nil
		status.ReasonCode = "requested"
	case DowngradeWarningBearing:
		status.WarningCount = 1
	case DowngradeFailed, DowngradeBlocked:
		status.Status = "failed"
		status.ErrorCount = 1
		status.ReasonCode = "missing_activation_proof"
	case DowngradeUnsupported:
		status.Status = "disabled"
		status.ActiveModes = nil
		status.ActiveProofs = nil
		status.ReasonCode = "unsupported_capability"
	case DowngradePartial:
		status.ReasonCode = "missing_activation_proof"
	default:
		status.Status = "planned"
		status.ActivationID = ""
		status.ActiveModes = nil
		status.ActiveProofs = nil
	}
	return &status
}

func trustedTemplateLock() *sandbox.SandboxTemplateLockMetadata {
	return sanitizeTemplateLock(&sandbox.SandboxTemplateLockMetadata{
		Document:          templateLockEntry(sandbox.SandboxTemplateLockSourceKindLocalFile, sandbox.SandboxTemplateLockReferenceKindLocal, sandbox.SandboxTemplateLockReasonDocumentDigest, "a"),
		TemplateReference: templateLockEntry(sandbox.SandboxTemplateLockSourceKindTemplateReference, sandbox.SandboxTemplateLockReferenceKindOCIArtifact, sandbox.SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
		RuntimeImage:      templateLockEntry(sandbox.SandboxTemplateLockSourceKindRuntimeImage, sandbox.SandboxTemplateLockReferenceKindOCIImage, sandbox.SandboxTemplateLockReasonRuntimeImageDigest, "c"),
		SourceArtifact:    templateLockEntry(sandbox.SandboxTemplateLockSourceKindSourceArtifact, sandbox.SandboxTemplateLockReferenceKindOCIArtifact, sandbox.SandboxTemplateLockReasonSourceArtifactDigest, "d"),
		TrustPolicy: &sandbox.SandboxTemplateTrustPolicyMetadata{
			Mode:            sandbox.SandboxTemplateTrustPolicyModeStrict,
			Decision:        sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
			SourceKind:      sandbox.SandboxTemplateLockSourceKindTemplateReference,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindOCIArtifact,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("e", 64),
		},
	})
}

func downgradedTemplateLock(downgrade Downgrade) *sandbox.SandboxTemplateLockMetadata {
	lock := trustedTemplateLock()
	switch downgrade {
	case DowngradeBlocked:
		lock.TrustPolicy.Decision = sandbox.SandboxTemplateTrustPolicyDecisionRejected
	case DowngradeUnsupported:
		lock.TrustPolicy.Decision = sandbox.SandboxTemplateTrustPolicyDecisionUnavailable
	case DowngradeWarningBearing:
		lock.TrustPolicy.WarningCodes = []string{sandbox.SandboxTemplateTrustPolicyCodeMissingDigestPin}
	case DowngradeMetadataOnly:
		lock.TemplateReference.DigestAlgorithm = ""
		lock.TemplateReference.DigestValue = ""
	default:
		lock.TrustPolicy.Mode = sandbox.SandboxTemplateTrustPolicyModeAdvisory
		lock.TrustPolicy.Decision = sandbox.SandboxTemplateTrustPolicyDecisionAdvisory
	}
	return sanitizeTemplateLock(lock)
}

func templateLockEntry(sourceKind, referenceKind, reasonCode, seed string) *sandbox.SandboxTemplateLockEntryMetadata {
	return &sandbox.SandboxTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          sandbox.SandboxTemplateLockStatusLocked,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(seed, 64),
		ReasonCode:      reasonCode,
	}
}

func sanitizeTemplateLock(lock *sandbox.SandboxTemplateLockMetadata) *sandbox.SandboxTemplateLockMetadata {
	return sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}
