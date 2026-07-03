package sandbox

import (
	"strings"
	"testing"
)

func TestProjectSecureDefaultReadinessInputAcceptsActiveSuccessProxyFirewallNetworkProof(t *testing.T) {
	output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
		secureDefaultProjectionRequestedNetworkInput(),
		ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(SandboxPolicyProxyCredentialCapabilityReadinessProjection{
			NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
				ResultOutcome:         "success",
				ResultEnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
				ResultSupported:       true,
			}),
		}),
	)

	result := requireSecureDefaultProjectionResult(t, output,
		SandboxSecurityCapabilityReadinessReady,
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
	)
	requireSecureDefaultProjectionResultMode(t, result, SandboxNetworkEnforcementModeProxyFirewall)
	requireSecureDefaultProjectionStrictGate(t, output,
		SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
	)
}

func TestProjectSecureDefaultReadinessInputRejectsIncompleteNetworkProofs(t *testing.T) {
	tests := []struct {
		name       string
		projection SandboxPolicyProxyCredentialCapabilityReadinessProjection
		wantReason SandboxSecurityCapabilityReasonCode
	}{
		{
			name:       "requested only",
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementMissing,
		},
		{
			name: "planned proxy firewall session metadata",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkProxySession: &SandboxNetworkProxySessionMetadata{
					ID:              "network-proxy-session-planned",
					Source:          SandboxNetworkPolicyDecisionSourceWorker,
					EnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
					PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
						ID:     "policy-snapshot-planned",
						Preset: SandboxNetworkPolicyPresetDenyByDefault,
					},
				},
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
		},
		{
			name: "metadata only effective policy result",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkPolicyResult: &SandboxNetworkPolicyResult{
					Requested:       SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetDenyByDefault},
					Effective:       SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetDenyByDefault},
					EnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
					Capability: SandboxNetworkPolicyEnforcementCapability{
						Supported:                  true,
						Modes:                      []string{SandboxNetworkEnforcementModeProxyFirewall},
						SupportsDefaultDenyPosture: true,
					},
				},
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
		},
		{
			name: "best effort proof",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
					ResultOutcome:         "best_effort",
					ResultEnforcementMode: SandboxNetworkEnforcementModeBestEffort,
					ResultSupported:       true,
				}),
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort,
		},
		{
			name: "unsupported proof",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
					ResultOutcome:         "unsupported",
					ResultEnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
					ResultSupported:       false,
				}),
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported,
		},
		{
			name: "partial active check proof",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
					ProxyLifecycleReasonCode: "active_check_failed",
					ResultOutcome:            "success",
					ResultEnforcementMode:    SandboxNetworkEnforcementModeProxyFirewall,
					ResultSupported:          true,
				}),
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementPartial,
		},
		{
			name: "failed proof",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
					ProxyLifecycleStatus:     "failed",
					ProxyLifecycleReasonCode: "adapter_failed",
					ResultOutcome:            "failure",
					ResultEnforcementMode:    SandboxNetworkEnforcementModeProxyFirewall,
					ResultSupported:          false,
				}),
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementFailed,
		},
		{
			name: "active success proxy only is not strict proof",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				NetworkEnforcementProof: secureDefaultProjectionNetworkProof(SandboxNetworkEnforcementProofMetadata{
					ResultOutcome:         "success",
					ResultEnforcementMode: SandboxNetworkEnforcementModeProxy,
					ResultSupported:       true,
				}),
			},
			wantReason: SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
				secureDefaultProjectionRequestedNetworkInput(),
				ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(tt.projection),
			)
			requireSecureDefaultProjectionStrictGate(t, output,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGateReasonCode(tt.wantReason),
				tt.wantReason,
			)
			requireSecureDefaultProjectionNoReadyResult(t, output,
				SandboxSecurityCapabilityFamilyNetworkPolicy,
				SandboxSecurityCapabilityNetworkDenyByDefault,
			)
		})
	}
}

func TestProjectSecureDefaultReadinessInputRequiresActiveCredentialActivationProof(t *testing.T) {
	output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
		secureDefaultProjectionRequestedSecretInput(SandboxSecretModeHTTPProxy),
		ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(SandboxPolicyProxyCredentialCapabilityReadinessProjection{
			CredentialDelivery: &SandboxCredentialDeliveryStatusMetadata{
				ID:             "credential-delivery-active",
				PlanID:         "credential-delivery-plan",
				ActivationID:   "credential-delivery-activation",
				RequestedModes: []string{SandboxSecretModeHTTPProxy},
				ActiveModes:    []string{SandboxSecretModeHTTPProxy},
				Status:         "active",
				ReasonCode:     "requested",
			},
		}),
	)

	result := requireSecureDefaultProjectionResult(t, output,
		SandboxSecurityCapabilityReadinessReady,
		SandboxSecurityCapabilityFamilySecretDelivery,
		SandboxSecurityCapabilitySecretHTTPProxy,
		SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
	)
	requireSecureDefaultProjectionResultMode(t, result, SandboxSecretModeHTTPProxy)
	requireSecureDefaultProjectionStrictGate(t, output,
		SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
	)
}

func TestProjectSecureDefaultReadinessInputRejectsCredentialPlanSessionBindingWithoutActivation(t *testing.T) {
	tests := []struct {
		name       string
		projection SandboxPolicyProxyCredentialCapabilityReadinessProjection
	}{
		{
			name: "credential proxy plan session binding only",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
					ID:           "credential-proxy-plan",
					Source:       SandboxCredentialProxySourceWorker,
					BindingCount: 1,
					Mode:         SandboxCredentialProxyModeBrokeredNetworkReference,
					Status:       SandboxCredentialProxyStatusReady,
				},
				CredentialProxySession: &SandboxCredentialProxySessionMetadata{
					ID:         "credential-proxy-session",
					PlanID:     "credential-proxy-plan",
					Source:     SandboxCredentialProxySourceWorker,
					Status:     SandboxCredentialProxyStatusActive,
					ReasonCode: SandboxCredentialProxyReasonRequested,
				},
				CredentialProxyBindings: []SandboxCredentialProxyBindingMetadata{{
					ID:           "credential-proxy-binding",
					PlanID:       "credential-proxy-plan",
					SessionID:    "credential-proxy-session",
					SecretID:     "env:GITHUB_TOKEN",
					DeliveryMode: SandboxCredentialProxyDeliveryModeHTTPProxy,
					Outcome:      SandboxCredentialProxyBindingOutcomeBound,
					Status:       SandboxCredentialProxyStatusReady,
					ReasonCode:   SandboxCredentialProxyReasonRequested,
				}},
			},
		},
		{
			name: "requested delivery status",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				CredentialDelivery: &SandboxCredentialDeliveryStatusMetadata{
					ID:             "credential-delivery-requested",
					PlanID:         "credential-delivery-plan",
					RequestedModes: []string{SandboxSecretModeHTTPProxy},
					Status:         "requested",
				},
			},
		},
		{
			name: "active status without activation identity",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				CredentialDelivery: &SandboxCredentialDeliveryStatusMetadata{
					ID:             "credential-delivery-active-no-identity",
					PlanID:         "credential-delivery-plan",
					RequestedModes: []string{SandboxSecretModeHTTPProxy},
					ActiveModes:    []string{SandboxSecretModeHTTPProxy},
					Status:         "active",
				},
			},
		},
		{
			name: "active status without active modes",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				CredentialDelivery: &SandboxCredentialDeliveryStatusMetadata{
					ID:             "credential-delivery-active-no-modes",
					PlanID:         "credential-delivery-plan",
					ActivationID:   "credential-delivery-activation",
					RequestedModes: []string{SandboxSecretModeHTTPProxy},
					Status:         "active",
				},
			},
		},
		{
			name: "unsafe activation identity sanitizes away",
			projection: SandboxPolicyProxyCredentialCapabilityReadinessProjection{
				CredentialDelivery: &SandboxCredentialDeliveryStatusMetadata{
					ID:             "credential-delivery-active-unsafe",
					PlanID:         "credential-delivery-plan",
					ActivationID:   "https://credentials.invalid/activation?token=raw",
					RequestedModes: []string{SandboxSecretModeHTTPProxy},
					ActiveModes:    []string{SandboxSecretModeHTTPProxy},
					Status:         "active",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
				secureDefaultProjectionRequestedSecretInput(SandboxSecretModeHTTPProxy),
				ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(tt.projection),
			)
			requireSecureDefaultProjectionStrictGate(t, output,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonCredentialActivationMissing),
				SandboxSecurityCapabilityReasonCredentialActivationMissing,
			)
			requireSecureDefaultProjectionNoReadyResult(t, output,
				SandboxSecurityCapabilityFamilySecretDelivery,
				SandboxSecurityCapabilitySecretHTTPProxy,
			)
		})
	}
}

func TestProjectSecureDefaultReadinessInputRequiresLockedTemplateDigestProof(t *testing.T) {
	output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
		secureDefaultProjectionRequestedTemplateInput(),
		ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
			TemplateLock: secureDefaultProjectionTemplateLock(
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindTemplateReference, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindRuntimeImage, SandboxTemplateLockReferenceKindOCIImage, SandboxTemplateLockReasonRuntimeImageDigest, "c"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindSourceArtifact, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonSourceArtifactDigest, "d"),
			),
		}),
	)

	requireSecureDefaultProjectionResult(t, output,
		SandboxSecurityCapabilityReadinessReady,
		SandboxSecurityCapabilityFamilyTemplate,
		SandboxSecurityCapabilityTemplateLockDigest,
		SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed,
	)
	requireSecureDefaultProjectionStrictGate(t, output,
		SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed,
	)
}

func TestProjectSecureDefaultReadinessInputRejectsMutableOrUnavailableTemplateLocks(t *testing.T) {
	tests := []struct {
		name string
		lock *SandboxTemplateLockMetadata
	}{
		{
			name: "missing required categories",
			lock: secureDefaultProjectionTemplateLock(
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
				nil,
				nil,
				nil,
			),
		},
		{
			name: "locked status without digest",
			lock: secureDefaultProjectionTemplateLock(
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
				&SandboxTemplateLockEntryMetadata{
					SourceKind:    SandboxTemplateLockSourceKindTemplateReference,
					ReferenceKind: SandboxTemplateLockReferenceKindOCIArtifact,
					Status:        SandboxTemplateLockStatusLocked,
					ReasonCode:    SandboxTemplateLockReasonTemplateReferenceDigest,
				},
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindRuntimeImage, SandboxTemplateLockReferenceKindOCIImage, SandboxTemplateLockReasonRuntimeImageDigest, "c"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindSourceArtifact, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonSourceArtifactDigest, "d"),
			),
		},
		{
			name: "unresolved mutable runtime image",
			lock: secureDefaultProjectionTemplateLock(
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindTemplateReference, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
				&SandboxTemplateLockEntryMetadata{
					SourceKind:    SandboxTemplateLockSourceKindRuntimeImage,
					ReferenceKind: SandboxTemplateLockReferenceKindOCIImage,
					Status:        SandboxTemplateLockStatusUnresolved,
					ReasonCode:    SandboxTemplateLockReasonUnresolvedMutableReference,
				},
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindSourceArtifact, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonSourceArtifactDigest, "d"),
			),
		},
		{
			name: "resolver unavailable source artifact",
			lock: secureDefaultProjectionTemplateLock(
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindTemplateReference, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
				secureDefaultProjectionLockedTemplateEntry(SandboxTemplateLockSourceKindRuntimeImage, SandboxTemplateLockReferenceKindOCIImage, SandboxTemplateLockReasonRuntimeImageDigest, "c"),
				&SandboxTemplateLockEntryMetadata{
					SourceKind:    SandboxTemplateLockSourceKindSourceArtifact,
					ReferenceKind: SandboxTemplateLockReferenceKindOCIArtifact,
					Status:        SandboxTemplateLockStatusUnresolved,
					ReasonCode:    SandboxTemplateLockReasonResolverUnavailable,
				},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
				secureDefaultProjectionRequestedTemplateInput(),
				ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
					TemplateLock: tt.lock,
				}),
			)
			requireSecureDefaultProjectionStrictGate(t, output,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonTemplateLockDigestMissing),
				SandboxSecurityCapabilityReasonTemplateLockDigestMissing,
			)
			requireSecureDefaultProjectionNoReadyResult(t, output,
				SandboxSecurityCapabilityFamilyTemplate,
				SandboxSecurityCapabilityTemplateLockDigest,
			)
		})
	}
}

func TestProjectSecureDefaultReadinessInputClassifiesIsolatedWorkspaceModes(t *testing.T) {
	tests := []struct {
		name      string
		workspace SandboxWorkspace
	}{
		{
			name: "clone remote ref",
			workspace: SandboxWorkspace{
				Mode:        SandboxWorkspaceModeClone,
				InputSource: SandboxWorkspaceInputSourceRemoteRef,
				Branch:      "feature/secure-default",
				SyncRef:     "main",
			},
		},
		{
			name: "clone git bundle",
			workspace: SandboxWorkspace{
				Mode:        SandboxWorkspaceModeClone,
				InputSource: SandboxWorkspaceInputSourceGitBundle,
				Branch:      "feature/secure-default",
				SyncRef:     "bundle-sync",
			},
		},
		{
			name: "copy",
			workspace: SandboxWorkspace{
				Mode:        SandboxWorkspaceModeCopy,
				InputSource: SandboxWorkspaceInputSourceCopy,
				Branch:      "feature/secure-default",
				SyncRef:     "copy-sync",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
				secureDefaultProjectionRequestedWorkspaceInput(),
				ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
					Workspace: &tt.workspace,
				}),
			)
			requireSecureDefaultProjectionResult(t, output,
				SandboxSecurityCapabilityReadinessReady,
				SandboxSecurityCapabilityFamilyWorkspace,
				SandboxSecurityCapabilityIsolatedWorkspace,
				SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed,
			)
			requireSecureDefaultProjectionStrictGate(t, output,
				SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
				SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
				SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed,
			)
		})
	}
}

func TestProjectSecureDefaultReadinessInputBlocksDirectWorkspaceMode(t *testing.T) {
	workspace := SandboxWorkspace{
		Mode:        SandboxWorkspaceModeDirect,
		InputSource: SandboxWorkspaceInputSourceCopy,
		Branch:      "feature/secure-default",
		SyncRef:     "direct-sync",
	}
	output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
		secureDefaultProjectionRequestedWorkspaceInput(),
		ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
			Workspace: &workspace,
		}),
	)

	requireSecureDefaultProjectionResult(t, output,
		SandboxSecurityCapabilityReadinessBlocked,
		SandboxSecurityCapabilityFamilyWorkspace,
		SandboxSecurityCapabilityIsolatedWorkspace,
		SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
	)
	requireSecureDefaultProjectionStrictGate(t, output,
		SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree),
		SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
	)
}

func secureDefaultProjectionRequestedNetworkInput() SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeProxyFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
	}
}

func secureDefaultProjectionRequestedSecretInput(mode string) SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretHTTPProxy,
			Mode:       mode,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
	}
}

func secureDefaultProjectionRequestedTemplateInput() SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyTemplate,
			Capability: SandboxSecurityCapabilityTemplateLockDigest,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
	}
}

func secureDefaultProjectionRequestedWorkspaceInput() SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyWorkspace,
			Capability: SandboxSecurityCapabilityIsolatedWorkspace,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
	}
}

func secureDefaultProjectionNetworkProof(overrides SandboxNetworkEnforcementProofMetadata) *SandboxNetworkEnforcementProofMetadata {
	proof := SandboxNetworkEnforcementProofMetadata{
		NetworkProxySessionID:    "network-proxy-session-proof",
		PolicySnapshotID:         "policy-snapshot-proof",
		NetworkEnforcementPlanID: "network-enforcement-plan-proof",
		ProxyLifecycleStatus:     "active",
		ProxyLifecycleReasonCode: "active",
		ResultOutcome:            "success",
		ResultEnforcementMode:    SandboxNetworkEnforcementModeProxyFirewall,
		ResultSupported:          true,
	}
	if overrides.NetworkProxySessionID != "" {
		proof.NetworkProxySessionID = overrides.NetworkProxySessionID
	}
	if overrides.PolicySnapshotID != "" {
		proof.PolicySnapshotID = overrides.PolicySnapshotID
	}
	if overrides.NetworkEnforcementPlanID != "" {
		proof.NetworkEnforcementPlanID = overrides.NetworkEnforcementPlanID
	}
	if overrides.ProxyLifecycleStatus != "" {
		proof.ProxyLifecycleStatus = overrides.ProxyLifecycleStatus
	}
	if overrides.ProxyLifecycleReasonCode != "" {
		proof.ProxyLifecycleReasonCode = overrides.ProxyLifecycleReasonCode
	}
	if overrides.ResultOutcome != "" {
		proof.ResultOutcome = overrides.ResultOutcome
	}
	if overrides.ResultEnforcementMode != "" {
		proof.ResultEnforcementMode = overrides.ResultEnforcementMode
	}
	proof.ResultSupported = overrides.ResultSupported
	return &proof
}

func secureDefaultProjectionTemplateLock(document, templateReference, runtimeImage, sourceArtifact *SandboxTemplateLockEntryMetadata) *SandboxTemplateLockMetadata {
	return SanitizeSandboxTemplateLockMetadata(&SandboxTemplateLockMetadata{
		Document:          document,
		TemplateReference: templateReference,
		RuntimeImage:      runtimeImage,
		SourceArtifact:    sourceArtifact,
	})
}

func secureDefaultProjectionLockedTemplateEntry(sourceKind, referenceKind, reasonCode, digestSeed string) *SandboxTemplateLockEntryMetadata {
	return &SandboxTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          SandboxTemplateLockStatusLocked,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(digestSeed, 64),
		LockedAt:        "2026-07-03T22:12:01Z",
		ReasonCode:      reasonCode,
	}
}

func requireSecureDefaultProjectionResult(t *testing.T, output *SandboxSecurityCapabilityReadinessOutput, state SandboxSecurityCapabilityReadinessState, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReadinessResult {
	t.Helper()
	if output == nil {
		t.Fatalf("projected readiness output = nil, want %s %s/%s with reason %s", state, family, capability, reason)
	}
	for _, result := range output.Results {
		context := secureDefaultProjectionResultContext(result)
		if context == nil || context.Family != family || context.Capability != capability {
			continue
		}
		if result.State != state {
			t.Fatalf("projected %s/%s state = %s, want %s: %#v", family, capability, result.State, state, result)
		}
		if result.ReasonCode != reason {
			t.Fatalf("projected %s/%s reason = %s, want %s: %#v", family, capability, result.ReasonCode, reason, result)
		}
		return result
	}
	t.Fatalf("projected readiness results = %#v, want %s %s/%s with reason %s", output.Results, state, family, capability, reason)
	return SandboxSecurityCapabilityReadinessResult{}
}

func requireSecureDefaultProjectionNoReadyResult(t *testing.T, output *SandboxSecurityCapabilityReadinessOutput, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName) {
	t.Helper()
	if output == nil {
		return
	}
	for _, result := range output.Results {
		context := secureDefaultProjectionResultContext(result)
		if context == nil || context.Family != family || context.Capability != capability {
			continue
		}
		if result.State == SandboxSecurityCapabilityReadinessReady {
			t.Fatalf("projected readiness result unexpectedly ready for %s/%s: %#v", family, capability, result)
		}
	}
}

func requireSecureDefaultProjectionResultMode(t *testing.T, result SandboxSecurityCapabilityReadinessResult, want string) {
	t.Helper()
	for _, context := range []*SandboxSecurityCapabilityMetadata{result.Requested, result.Ready, result.Metadata} {
		if context == nil {
			continue
		}
		if context.Mode == want {
			return
		}
	}
	t.Fatalf("projected readiness result mode missing %q: %#v", want, result)
}

func requireSecureDefaultProjectionStrictGate(t *testing.T, output *SandboxSecurityCapabilityReadinessOutput, outcome SandboxSecurityCapabilityReadinessGateOutcome, reason SandboxSecurityCapabilityReadinessGateReasonCode, countedReason SandboxSecurityCapabilityReasonCode) {
	t.Helper()
	var readiness SandboxSecurityCapabilityReadinessOutput
	if output != nil {
		readiness = *output
	}
	decision := EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, readiness)
	if decision.Outcome != outcome {
		t.Fatalf("strict readiness gate outcome = %s, want %s: decision=%#v output=%#v", decision.Outcome, outcome, decision, output)
	}
	if decision.Reason != reason {
		t.Fatalf("strict readiness gate reason = %s, want %s: decision=%#v output=%#v", decision.Reason, reason, decision, output)
	}
	if decision.Counts == nil || decision.Counts.ReasonCodeCounts[countedReason] == 0 {
		t.Fatalf("strict readiness gate reason counts = %#v, want count for %s", decision.Counts, countedReason)
	}
}

func secureDefaultProjectionResultContext(result SandboxSecurityCapabilityReadinessResult) *SandboxSecurityCapabilityMetadata {
	if result.Requested != nil {
		return result.Requested
	}
	if result.Metadata != nil {
		return result.Metadata
	}
	return result.Ready
}
