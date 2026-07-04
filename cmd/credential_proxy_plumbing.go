package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

type credentialDeliveryActivationResult = credentialdelivery.ActivationResult

func applyRunSandboxCredentialProxyMetadata(manifest *sandboxexecution.Manifest, req runSandboxRequest) {
	if manifest == nil {
		return
	}
	credentialProxy := sandboxManifestCredentialProxyProjection(req)
	manifest.CredentialProxyPlan = credentialProxy.Plan
	manifest.CredentialProxySession = credentialProxy.Session
	manifest.CredentialProxyBindings = credentialProxy.Bindings
	manifest.CredentialDelivery = sandboxManifestCredentialDeliveryStatus(credentialProxy, req.Security, req.CredentialDeliveryActivation)
}

func applyAutoSandboxCredentialProxyMetadata(manifest *sandboxexecution.Manifest, req autoSandboxRequest) {
	if manifest == nil {
		return
	}
	credentialProxy := autoSandboxManifestCredentialProxyProjection(req)
	manifest.CredentialProxyPlan = credentialProxy.Plan
	manifest.CredentialProxySession = credentialProxy.Session
	manifest.CredentialProxyBindings = credentialProxy.Bindings
	manifest.CredentialDelivery = sandboxManifestCredentialDeliveryStatus(credentialProxy, req.Security, req.CredentialDeliveryActivation)
}

func applyFactorySandboxCredentialProxyMetadata(metadata *factory.SandboxMetadata, req factorySandboxExecutorRequest, record factory.RunRecord, networkProxySession *sandbox.SandboxNetworkProxySessionMetadata) {
	if metadata == nil {
		return
	}
	credentialProxy := factorySandboxCredentialProxyProjection(req, record, networkProxySession)
	metadata.CredentialProxyPlan = credentialProxy.Plan
	metadata.CredentialProxySession = credentialProxy.Session
	metadata.CredentialProxyBindings = credentialProxy.Bindings
	metadata.CredentialDelivery = factorySandboxCredentialDeliveryActivationStatus(credentialProxy, req.Security, req.CredentialDeliveryActivation)
	factorySandboxSanitizeCredentialProxyMetadata(metadata)
}

func sandboxManifestCredentialProxyProjection(req runSandboxRequest) sandbox.SandboxCredentialProxyProjection {
	projection := sandbox.ProjectSandboxCredentialProxyMetadata(sandbox.SandboxCredentialProxyProjectionRequest{
		PlanID:               runSandboxCredentialProxyID(req.ExecutionID, "plan"),
		SessionID:            runSandboxCredentialProxyID(req.ExecutionID, "session"),
		BindingIDPrefix:      runSandboxCredentialProxyID(req.ExecutionID, "binding"),
		Source:               sandbox.SandboxCredentialProxySourceRun,
		SecretDeliveryIntent: sandboxManifestCredentialProxySecretDeliveryIntent(req.Security),
		NetworkProxySession:  req.NetworkProxySession,
		RequestCategory:      sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory:  sandbox.SandboxNetworkPolicyDestinationUnknown,
	})
	return sandboxManifestSanitizedCredentialProxyProjection(projection)
}

func runSandboxCredentialProxyID(executionID, suffix string) string {
	if strings.TrimSpace(executionID) == "" || strings.TrimSpace(suffix) == "" {
		return ""
	}
	return executionID + "-credential-proxy-" + suffix
}

func autoSandboxManifestCredentialProxyProjection(req autoSandboxRequest) sandbox.SandboxCredentialProxyProjection {
	projection := sandbox.ProjectSandboxCredentialProxyMetadata(sandbox.SandboxCredentialProxyProjectionRequest{
		PlanID:               autoSandboxCredentialProxyID(req.ExecutionID, "plan"),
		SessionID:            autoSandboxCredentialProxyID(req.ExecutionID, "session"),
		BindingIDPrefix:      autoSandboxCredentialProxyID(req.ExecutionID, "binding"),
		Source:               sandbox.SandboxCredentialProxySourceAuto,
		SecretDeliveryIntent: sandboxManifestCredentialProxySecretDeliveryIntent(req.Security),
		NetworkProxySession:  req.NetworkProxySession,
		RequestCategory:      sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory:  sandbox.SandboxNetworkPolicyDestinationUnknown,
	})
	return sandboxManifestSanitizedCredentialProxyProjection(projection)
}

func autoSandboxCredentialProxyID(executionID, suffix string) string {
	if strings.TrimSpace(executionID) == "" || strings.TrimSpace(suffix) == "" {
		return ""
	}
	return executionID + "-credential-proxy-" + suffix
}

func factorySandboxCredentialProxyProjection(req factorySandboxExecutorRequest, record factory.RunRecord, networkProxySession *sandbox.SandboxNetworkProxySessionMetadata) sandbox.SandboxCredentialProxyProjection {
	projection := factory.ProjectCredentialProxyMetadata(factory.CredentialProxyProjectionRequest{
		PlanID:               factorySandboxCredentialProxyID(record.RunID, "plan"),
		SessionID:            factorySandboxCredentialProxyID(record.RunID, "session"),
		BindingIDPrefix:      factorySandboxCredentialProxyID(record.RunID, "binding"),
		Source:               sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSession:  factorySandboxCredentialProxySecretBrokerSession(record),
		SecretDeliveryIntent: sandboxManifestCredentialProxySecretDeliveryIntent(req.Security),
		NetworkProxySession:  networkProxySession,
		RequestCategory:      sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory:  sandbox.SandboxNetworkPolicyDestinationUnknown,
	})
	return sandboxManifestSanitizedCredentialProxyProjection(projection)
}

func factorySandboxCredentialProxyID(runID, suffix string) string {
	if strings.TrimSpace(runID) == "" || strings.TrimSpace(suffix) == "" {
		return ""
	}
	return runID + "-credential-proxy-" + suffix
}

func factorySandboxCredentialProxySecretBrokerSession(record factory.RunRecord) *factory.SecretBrokerSessionMetadata {
	if len(record.Secrets) == 0 {
		return nil
	}
	session := factory.SecretBrokerSessionMetadata{
		ID: factorySandboxCredentialProxyID(record.RunID, "secret-broker-session"),
	}
	for _, secret := range record.Secrets {
		metadata, ok := factorySandboxCredentialProxySecretMetadata(secret)
		if !ok {
			continue
		}
		session.Secrets = append(session.Secrets, metadata)
	}
	if len(session.Secrets) == 0 {
		return nil
	}
	return &session
}

func factorySandboxCredentialProxySecretMetadata(secret factory.RunSecretMetadata) (factory.SecretBrokerSecretMetadata, bool) {
	if !secret.Present {
		return factory.SecretBrokerSecretMetadata{}, false
	}
	source := strings.TrimSpace(secret.Source)
	name := strings.TrimSpace(secret.Name)
	if source == "" || name == "" {
		return factory.SecretBrokerSecretMetadata{}, false
	}
	return factory.SecretBrokerSecretMetadata{
		ID:       source + ":" + name,
		Name:     name,
		Source:   source,
		Required: secret.Required,
		Present:  true,
	}, true
}

func sandboxManifestCredentialProxySecretDeliveryIntent(req sandbox.SecurityEvaluationRequest) *sandbox.SandboxSecretDeliveryIntent {
	requestedModes := append([]string(nil), req.RequestedSecretModes...)
	activeModes := append([]string(nil), req.ActiveSecretModes...)
	if req.CompatibilityAuthSync {
		requestedModes = append(requestedModes, sandbox.SandboxSecretModeLegacyAuthSync)
	}
	if len(requestedModes) == 0 && len(activeModes) == 0 {
		return nil
	}
	return &sandbox.SandboxSecretDeliveryIntent{
		RequestedModes: requestedModes,
		ActiveModes:    activeModes,
	}
}

func sandboxManifestCredentialDeliveryStatus(projection sandbox.SandboxCredentialProxyProjection, req sandbox.SecurityEvaluationRequest, activation credentialDeliveryActivationResult) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	planStatus := sandbox.ProjectSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusProjectionRequest{
		Plan:                  projection.Plan,
		Bindings:              projection.Bindings,
		RequestedModes:        req.RequestedSecretModes,
		CompatibilityAuthSync: req.CompatibilityAuthSync,
	})
	if activationStatus := sandboxManifestCredentialDeliveryActivationStatus(planStatus, activation); activationStatus != nil {
		return activationStatus
	}
	return planStatus
}

func factorySandboxCredentialDeliveryActivationStatus(projection sandbox.SandboxCredentialProxyProjection, req sandbox.SecurityEvaluationRequest, activation credentialDeliveryActivationResult) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	planStatus := sandbox.ProjectSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusProjectionRequest{
		Plan:                  projection.Plan,
		Bindings:              projection.Bindings,
		RequestedModes:        req.RequestedSecretModes,
		CompatibilityAuthSync: req.CompatibilityAuthSync,
	})
	return sandboxManifestCredentialDeliveryActivationStatus(planStatus, activation)
}

func sandboxManifestCredentialDeliveryActivationStatus(planStatus *sandbox.SandboxCredentialDeliveryStatusMetadata, activation credentialDeliveryActivationResult) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	if credentialdelivery.SanitizeActivationResultMetadata(activation).ID == "" {
		return nil
	}
	plan := sandboxCredentialDeliveryPlanFromStatus(planStatus)
	if plan.ID == "" {
		sanitizedActivation := credentialdelivery.SanitizeActivationResultMetadata(activation)
		plan.ID = sanitizedActivation.PlanID
		plan.RequestedModes = sanitizedActivation.RequestedModes
		plan.Status = credentialdelivery.StatusPlanned
	}
	status := credentialdelivery.StatusMetadataFromActivation(plan, activation)
	return sandboxCredentialDeliveryStatusFromCredentialDelivery(status)
}

func sandboxCredentialDeliveryActivationResultPresent(activation credentialDeliveryActivationResult) bool {
	return sandboxCommandJSONCredentialDeliveryStatus(sandboxManifestCredentialDeliveryActivationStatus(nil, activation)) != nil
}

func sandboxCredentialDeliveryPlanFromStatus(status *sandbox.SandboxCredentialDeliveryStatusMetadata) credentialdelivery.Plan {
	if status == nil {
		return credentialdelivery.Plan{}
	}
	sanitized := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(*status)
	if sanitized.ID == "" {
		return credentialdelivery.Plan{}
	}
	planID := sanitized.PlanID
	if planID == "" {
		planID = sanitized.ID
	}
	return credentialdelivery.Plan{
		ID:             planID,
		RequestID:      sanitized.RequestID,
		RequestedModes: sandboxCredentialDeliveryModesFromStrings(sanitized.RequestedModes),
		Status:         credentialdelivery.Status(sanitized.Status),
	}
}

func sandboxCredentialDeliveryStatusFromCredentialDelivery(status credentialdelivery.StatusMetadata) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	sanitized := credentialdelivery.SanitizeStatusMetadata(status)
	if sanitized.ID == "" {
		return nil
	}
	out := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             sanitized.ID,
		RequestID:      sanitized.RequestID,
		PlanID:         sanitized.PlanID,
		ActivationID:   sanitized.ActivationID,
		RequestedModes: sandboxCredentialDeliveryModeStrings(sanitized.RequestedModes),
		ActiveModes:    sandboxCredentialDeliveryModeStrings(sanitized.ActiveModes),
		Status:         string(sanitized.Status),
		ReasonCode:     string(sanitized.ReasonCode),
		WarningCount:   sanitized.WarningCount,
		ErrorCount:     sanitized.ErrorCount,
	})
	if out.ID == "" {
		return nil
	}
	return &out
}

func sandboxCredentialDeliveryModesFromStrings(modes []string) []credentialdelivery.Mode {
	if modes == nil {
		return nil
	}
	out := make([]credentialdelivery.Mode, 0, len(modes))
	for _, mode := range modes {
		out = append(out, credentialdelivery.Mode(mode))
	}
	return out
}

func sandboxCredentialDeliveryModeStrings(modes []credentialdelivery.Mode) []string {
	if modes == nil {
		return nil
	}
	out := make([]string, 0, len(modes))
	for _, mode := range modes {
		out = append(out, string(mode))
	}
	return out
}

func sandboxManifestSanitizedCredentialProxyProjection(projection sandbox.SandboxCredentialProxyProjection) sandbox.SandboxCredentialProxyProjection {
	var sanitized sandbox.SandboxCredentialProxyProjection
	if projection.Plan != nil {
		plan := sandbox.SanitizeSandboxCredentialProxyPlanMetadata(*projection.Plan)
		if plan.ID != "" {
			sanitized.Plan = &plan
		}
	}
	if projection.Session != nil {
		session := sandbox.SanitizeSandboxCredentialProxySessionMetadata(*projection.Session)
		if session.ID != "" {
			sanitized.Session = &session
		}
	}
	sanitized.Bindings = sandbox.SanitizeSandboxCredentialProxyBindingMetadataRecords(projection.Bindings)
	return sanitized
}

func factorySandboxSanitizeCredentialProxyMetadata(metadata *factory.SandboxMetadata) {
	if metadata == nil {
		return
	}
	if metadata.CredentialProxyPlan != nil {
		plan := sandbox.SanitizeSandboxCredentialProxyPlanMetadata(*metadata.CredentialProxyPlan)
		if plan.ID == "" {
			metadata.CredentialProxyPlan = nil
		} else {
			metadata.CredentialProxyPlan = &plan
		}
	}
	if metadata.CredentialProxySession != nil {
		session := sandbox.SanitizeSandboxCredentialProxySessionMetadata(*metadata.CredentialProxySession)
		if session.ID == "" {
			metadata.CredentialProxySession = nil
		} else {
			metadata.CredentialProxySession = &session
		}
	}
	metadata.CredentialProxyBindings = sandbox.SanitizeSandboxCredentialProxyBindingMetadataRecords(metadata.CredentialProxyBindings)
	if metadata.CredentialDelivery != nil {
		status := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(*metadata.CredentialDelivery)
		if status.ID == "" {
			metadata.CredentialDelivery = nil
		} else {
			metadata.CredentialDelivery = &status
		}
	}
}
