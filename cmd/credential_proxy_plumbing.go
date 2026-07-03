package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func applyRunSandboxCredentialProxyMetadata(manifest *sandboxexecution.Manifest, req runSandboxRequest) {
	if manifest == nil {
		return
	}
	credentialProxy := sandboxManifestCredentialProxyProjection(req)
	manifest.CredentialProxyPlan = credentialProxy.Plan
	manifest.CredentialProxySession = credentialProxy.Session
	manifest.CredentialProxyBindings = credentialProxy.Bindings
	manifest.CredentialDelivery = sandboxManifestCredentialDeliveryStatus(credentialProxy, req.Security)
}

func applyAutoSandboxCredentialProxyMetadata(manifest *sandboxexecution.Manifest, req autoSandboxRequest) {
	if manifest == nil {
		return
	}
	credentialProxy := autoSandboxManifestCredentialProxyProjection(req)
	manifest.CredentialProxyPlan = credentialProxy.Plan
	manifest.CredentialProxySession = credentialProxy.Session
	manifest.CredentialProxyBindings = credentialProxy.Bindings
	manifest.CredentialDelivery = sandboxManifestCredentialDeliveryStatus(credentialProxy, req.Security)
}

func applyFactorySandboxCredentialProxyMetadata(metadata *factory.SandboxMetadata, req factorySandboxExecutorRequest, record factory.RunRecord, networkProxySession *sandbox.SandboxNetworkProxySessionMetadata) {
	if metadata == nil {
		return
	}
	credentialProxy := factorySandboxCredentialProxyProjection(req, record, networkProxySession)
	metadata.CredentialProxyPlan = credentialProxy.Plan
	metadata.CredentialProxySession = credentialProxy.Session
	metadata.CredentialProxyBindings = credentialProxy.Bindings
	metadata.CredentialDelivery = sandboxManifestCredentialDeliveryStatus(credentialProxy, req.Security)
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
		activeModes = append(activeModes, sandbox.SandboxSecretModeLegacyAuthSync)
	}
	if len(requestedModes) == 0 && len(activeModes) == 0 {
		return nil
	}
	return &sandbox.SandboxSecretDeliveryIntent{
		RequestedModes: requestedModes,
		ActiveModes:    activeModes,
	}
}

func sandboxManifestCredentialDeliveryStatus(projection sandbox.SandboxCredentialProxyProjection, req sandbox.SecurityEvaluationRequest) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	if projection.Plan == nil {
		return nil
	}
	plan := credentialdelivery.Plan{
		ID:                    projection.Plan.ID,
		NetworkProxySessionID: projection.Plan.NetworkProxySessionID,
		RequestedModes:        sandboxCredentialDeliveryModes(req.RequestedSecretModes),
		Status:                credentialDeliveryStatusFromCredentialProxyStatus(projection.Plan.Status),
		BindingCount:          projection.Plan.BindingCount,
	}
	if plan.Status == "" {
		plan.Status = credentialdelivery.StatusPlanned
	}
	if req.CompatibilityAuthSync {
		plan.RequestedModes = append(plan.RequestedModes, credentialdelivery.ModeLegacyAuthSync)
	}
	if len(plan.RequestedModes) == 0 && len(projection.Bindings) > 0 {
		plan.RequestedModes = credentialDeliveryModesFromCredentialProxyBindings(projection.Bindings)
	}
	status := credentialdelivery.StatusMetadataFromPlan(plan)
	if status.ID == "" {
		return nil
	}
	return sandboxCredentialDeliveryStatusMetadata(status)
}

func sandboxCredentialDeliveryStatusMetadata(status credentialdelivery.StatusMetadata) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	sanitized := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             status.ID,
		RequestID:      status.RequestID,
		PlanID:         status.PlanID,
		ActivationID:   status.ActivationID,
		RequestedModes: credentialDeliveryModeStrings(status.RequestedModes),
		ActiveModes:    credentialDeliveryModeStrings(status.ActiveModes),
		Status:         string(status.Status),
		ReasonCode:     string(status.ReasonCode),
		WarningCount:   status.WarningCount,
		ErrorCount:     status.ErrorCount,
	})
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func credentialDeliveryModeStrings(modes []credentialdelivery.Mode) []string {
	if len(modes) == 0 {
		return nil
	}
	out := make([]string, 0, len(modes))
	for _, mode := range modes {
		if mode != "" {
			out = append(out, string(mode))
		}
	}
	return out
}

func sandboxCredentialDeliveryModes(modes []string) []credentialdelivery.Mode {
	if len(modes) == 0 {
		return nil
	}
	out := make([]credentialdelivery.Mode, 0, len(modes))
	for _, mode := range modes {
		if deliveryMode := sandboxCredentialDeliveryMode(mode); deliveryMode != "" && !credentialDeliveryModeContains(out, deliveryMode) {
			out = append(out, deliveryMode)
		}
	}
	return out
}

func credentialDeliveryModesFromCredentialProxyBindings(bindings []sandbox.SandboxCredentialProxyBindingMetadata) []credentialdelivery.Mode {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]credentialdelivery.Mode, 0, len(bindings))
	for _, binding := range sandbox.SanitizeSandboxCredentialProxyBindingMetadataRecords(bindings) {
		if deliveryMode := sandboxCredentialDeliveryMode(string(binding.DeliveryMode)); deliveryMode != "" && !credentialDeliveryModeContains(out, deliveryMode) {
			out = append(out, deliveryMode)
		}
	}
	return out
}

func sandboxCredentialDeliveryMode(mode string) credentialdelivery.Mode {
	switch strings.TrimSpace(mode) {
	case sandbox.SandboxSecretModeHTTPProxy:
		return credentialdelivery.ModeHTTPProxy
	case sandbox.SandboxSecretModeSSHAgent:
		return credentialdelivery.ModeSSHAgent
	case sandbox.SandboxSecretModeFileTmpfs:
		return credentialdelivery.ModeFileTmpfs
	case sandbox.SandboxSecretModeEnv:
		return credentialdelivery.ModeEnv
	case sandbox.SandboxSecretModeLegacyAuthSync:
		return credentialdelivery.ModeLegacyAuthSync
	default:
		return ""
	}
}

func credentialDeliveryModeContains(modes []credentialdelivery.Mode, mode credentialdelivery.Mode) bool {
	for _, existing := range modes {
		if existing == mode {
			return true
		}
	}
	return false
}

func credentialDeliveryStatusFromCredentialProxyStatus(status sandbox.SandboxCredentialProxyStatus) credentialdelivery.Status {
	switch status {
	case sandbox.SandboxCredentialProxyStatusPlanned:
		return credentialdelivery.StatusPlanned
	case sandbox.SandboxCredentialProxyStatusReady:
		return credentialdelivery.StatusReady
	case sandbox.SandboxCredentialProxyStatusActive:
		return credentialdelivery.StatusReady
	case sandbox.SandboxCredentialProxyStatusCompleted:
		return credentialdelivery.StatusCompleted
	case sandbox.SandboxCredentialProxyStatusSkipped:
		return credentialdelivery.StatusSkipped
	case sandbox.SandboxCredentialProxyStatusFailed:
		return credentialdelivery.StatusFailed
	case sandbox.SandboxCredentialProxyStatusDisabled:
		return credentialdelivery.StatusDisabled
	default:
		return ""
	}
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
