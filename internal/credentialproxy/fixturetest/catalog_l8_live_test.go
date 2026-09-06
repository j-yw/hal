//go:build l8_production_credential_delivery_live

package fixturetest

import (
	"testing"

	"github.com/jywlabs/hal/internal/credentialproxy"
)

func TestL8D3OwnedAzureResponsesCatalogIsExact(t *testing.T) {
	catalog, err := NewOwnedAzureResponsesCatalog("catalog-generation-01", "deployment-one", "2026-06-01")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := catalog.Lookup(credentialproxy.ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatal(err)
	}
	if definition.SealedAuthority() != ownedAzureResponsesAuthority || definition.SealedPort() != 443 ||
		definition.SealedTLS().ServerName() != ownedAzureResponsesAuthority {
		t.Fatal("owned fixture catalog did not retain its sealed endpoint")
	}
}
