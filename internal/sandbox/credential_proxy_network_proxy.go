package sandbox

// NetworkProxyCredentialProxyPlanRequest adapts safe network proxy session
// metadata into a sandbox credential proxy plan reference.
type NetworkProxyCredentialProxyPlanRequest struct {
	ID      string
	Source  SandboxCredentialProxySource
	Session SandboxNetworkProxySessionMetadata
	Status  SandboxCredentialProxyStatus
}

// NetworkProxyCredentialProxySessionRequest adapts safe network proxy session
// metadata into a sandbox credential proxy session reference.
type NetworkProxyCredentialProxySessionRequest struct {
	ID      string
	PlanID  string
	Source  SandboxCredentialProxySource
	Session SandboxNetworkProxySessionMetadata
	Status  SandboxCredentialProxyStatus
}

// CredentialProxyPlanMetadataFromNetworkProxySession copies safe proxy session
// identity into sanitized sandbox credential proxy plan metadata.
func CredentialProxyPlanMetadataFromNetworkProxySession(request NetworkProxyCredentialProxyPlanRequest) SandboxCredentialProxyPlanMetadata {
	return SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    request.ID,
		Source:                request.Source,
		NetworkProxySessionID: request.Session.ID,
		PolicySnapshot:        request.Session.PolicySnapshot,
		Mode:                  SandboxCredentialProxyModeNetworkProxyReference,
		Status:                request.Status,
	})
}

// CredentialProxySessionMetadataFromNetworkProxySession copies safe proxy
// session identity into sanitized sandbox credential proxy session metadata.
func CredentialProxySessionMetadataFromNetworkProxySession(request NetworkProxyCredentialProxySessionRequest) SandboxCredentialProxySessionMetadata {
	return SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    request.ID,
		PlanID:                request.PlanID,
		Source:                request.Source,
		NetworkProxySessionID: request.Session.ID,
		PolicySnapshot:        request.Session.PolicySnapshot,
		Status:                request.Status,
	})
}
