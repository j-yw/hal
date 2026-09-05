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

// CredentialProxyProjectionRequest adapts already-safe factory and sandbox
// metadata into durable credential proxy plan, session, and binding records.
type CredentialProxyProjectionRequest struct {
	PlanID               string
	SessionID            string
	BindingIDPrefix      string
	Source               sandbox.SandboxCredentialProxySource
	SecretBrokerSession  *SecretBrokerSessionMetadata
	SecretDeliveryIntent *sandbox.SandboxSecretDeliveryIntent
	NetworkProxySession  *sandbox.SandboxNetworkProxySessionMetadata
	RequestCategory      sandbox.SandboxCredentialProxyRequestCategory
	DestinationCategory  sandbox.SandboxNetworkPolicyDestinationCategory
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

// ProjectCredentialProxyMetadata copies only safe broker IDs, delivery mode
// labels, and sandbox proxy metadata into durable credential proxy records.
func ProjectCredentialProxyMetadata(request CredentialProxyProjectionRequest) sandbox.SandboxCredentialProxyProjection {
	return sandbox.ProjectSandboxCredentialProxyMetadata(sandbox.SandboxCredentialProxyProjectionRequest{
		PlanID:                request.PlanID,
		SessionID:             request.SessionID,
		BindingIDPrefix:       request.BindingIDPrefix,
		Source:                request.Source,
		SecretBrokerSessionID: credentialProxySecretBrokerSessionID(request.SecretBrokerSession),
		SecretIDs:             credentialProxySecretBrokerSecretIDs(request.SecretBrokerSession),
		SecretDeliveryIntent:  credentialProxySecretDeliveryIntent(request.SecretDeliveryIntent, request.SecretBrokerSession),
		NetworkProxySession:   request.NetworkProxySession,
		RequestCategory:       request.RequestCategory,
		DestinationCategory:   request.DestinationCategory,
	})
}

func credentialProxySecretBrokerSessionID(session *SecretBrokerSessionMetadata) string {
	if session == nil {
		return ""
	}
	return session.ID
}

func credentialProxySecretBrokerSecretIDs(session *SecretBrokerSessionMetadata) []string {
	if session == nil || session.Secrets == nil {
		return nil
	}
	secretIDs := make([]string, len(session.Secrets))
	for i, secret := range session.Secrets {
		secretIDs[i] = secret.ID
	}
	return secretIDs
}

func credentialProxySecretDeliveryIntent(intent *sandbox.SandboxSecretDeliveryIntent, session *SecretBrokerSessionMetadata) *sandbox.SandboxSecretDeliveryIntent {
	if intent != nil {
		return &sandbox.SandboxSecretDeliveryIntent{
			RequestedModes: cloneCredentialProxyDeliveryModes(intent.RequestedModes),
			ActiveModes:    cloneCredentialProxyDeliveryModes(intent.ActiveModes),
		}
	}
	if session == nil || session.DeliveryModes == nil {
		return nil
	}
	return &sandbox.SandboxSecretDeliveryIntent{
		RequestedModes: cloneCredentialProxyDeliveryModes(session.DeliveryModes.RequestedModes),
		ActiveModes:    cloneCredentialProxyDeliveryModes(session.DeliveryModes.ActiveModes),
	}
}

func cloneCredentialProxyDeliveryModes(modes []string) []string {
	if modes == nil {
		return nil
	}
	return append([]string{}, modes...)
}
