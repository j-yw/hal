//go:build l8_production_credential_delivery_live

// Package fixturetest owns the single build-tagged D3 service catalog used by
// prepared Linux verification. It is unavailable to default production builds.
package fixturetest

import "github.com/jywlabs/hal/internal/credentialproxy"

const ownedAzureResponsesAuthority = "owned-azure-responses.local"

// NewOwnedAzureResponsesCatalog returns the sole test-owned Azure Responses
// catalog. Callers may select safe generation/deployment/version identities,
// but cannot supply or replace its authority, port, TLS name, or policy.
func NewOwnedAzureResponsesCatalog(generation, deployment, apiVersion string) (*credentialproxy.StaticServiceCatalog, error) {
	definition, err := credentialproxy.NewAzureOpenAIResponsesV1Definition(
		ownedAzureResponsesAuthority,
		443,
		ownedAzureResponsesAuthority,
		credentialproxy.TLSRootPolicySystem,
		deployment,
		apiVersion,
	)
	if err != nil {
		return nil, err
	}
	return credentialproxy.NewStaticServiceCatalog(
		generation,
		credentialproxy.CatalogOwnerHostAdmin,
		definition,
	)
}
