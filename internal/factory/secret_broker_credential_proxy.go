package factory

import "github.com/jywlabs/hal/internal/sandbox"

// SecretBrokerCredentialProxyPlanRequest adapts safe secret broker session
// metadata into a sandbox credential proxy plan reference.
type SecretBrokerCredentialProxyPlanRequest struct {
	ID      string
	Source  sandbox.SandboxCredentialProxySource
	Session SecretBrokerSessionMetadata
	Status  sandbox.SandboxCredentialProxyStatus
}

// SecretBrokerCredentialProxySessionRequest adapts safe secret broker session
// metadata into a sandbox credential proxy session reference.
type SecretBrokerCredentialProxySessionRequest struct {
	ID      string
	PlanID  string
	Source  sandbox.SandboxCredentialProxySource
	Session SecretBrokerSessionMetadata
	Status  sandbox.SandboxCredentialProxyStatus
}

// SecretBrokerCredentialProxyBindingRequest adapts one safe secret broker
// secret metadata record into a sandbox credential proxy binding reference.
type SecretBrokerCredentialProxyBindingRequest struct {
	ID                  string
	PlanID              string
	SessionID           string
	Secret              SecretBrokerSecretMetadata
	DeliveryMode        string
	RequestCategory     sandbox.SandboxCredentialProxyRequestCategory
	DestinationCategory sandbox.SandboxNetworkPolicyDestinationCategory
	Outcome             sandbox.SandboxCredentialProxyBindingOutcome
	Status              sandbox.SandboxCredentialProxyStatus
	ReasonCode          sandbox.SandboxCredentialProxyReasonCode
}

// CredentialProxyPlanMetadataFromSecretBrokerSession copies safe broker session
// identity into sanitized sandbox credential proxy plan metadata.
func CredentialProxyPlanMetadataFromSecretBrokerSession(request SecretBrokerCredentialProxyPlanRequest) sandbox.SandboxCredentialProxyPlanMetadata {
	return sandbox.SanitizeSandboxCredentialProxyPlanMetadata(sandbox.SandboxCredentialProxyPlanMetadata{
		ID:                    request.ID,
		Source:                request.Source,
		SecretBrokerSessionID: request.Session.ID,
		BindingCount:          len(request.Session.Secrets),
		Mode:                  sandbox.SandboxCredentialProxyModeSecretBrokerReference,
		Status:                request.Status,
	})
}

// CredentialProxySessionMetadataFromSecretBrokerSession copies safe broker
// session identity into sanitized sandbox credential proxy session metadata.
func CredentialProxySessionMetadataFromSecretBrokerSession(request SecretBrokerCredentialProxySessionRequest) sandbox.SandboxCredentialProxySessionMetadata {
	return sandbox.SanitizeSandboxCredentialProxySessionMetadata(sandbox.SandboxCredentialProxySessionMetadata{
		ID:                    request.ID,
		PlanID:                request.PlanID,
		Source:                request.Source,
		SecretBrokerSessionID: request.Session.ID,
		Status:                request.Status,
	})
}

// CredentialProxyBindingMetadataFromSecretBrokerSecret copies safe broker
// secret identity into sanitized sandbox credential proxy binding metadata.
func CredentialProxyBindingMetadataFromSecretBrokerSecret(request SecretBrokerCredentialProxyBindingRequest) sandbox.SandboxCredentialProxyBindingMetadata {
	return sandbox.SanitizeSandboxCredentialProxyBindingMetadata(sandbox.SandboxCredentialProxyBindingMetadata{
		ID:                  request.ID,
		PlanID:              request.PlanID,
		SessionID:           request.SessionID,
		SecretID:            request.Secret.ID,
		DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryMode(request.DeliveryMode),
		RequestCategory:     request.RequestCategory,
		DestinationCategory: request.DestinationCategory,
		Outcome:             request.Outcome,
		Status:              request.Status,
		ReasonCode:          request.ReasonCode,
	})
}
