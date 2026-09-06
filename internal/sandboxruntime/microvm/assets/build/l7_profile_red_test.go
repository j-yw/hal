package build

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL7DistributionProfileIsDistinctAndCorrelated(t *testing.T) {
	manifest := validL5DistributionManifest()
	manifest.ImageProfile = ImageProfileL7Network
	manifest.GuestNetwork = &GuestNetwork{
		Mode:     GuestNetworkModeStaticProxy,
		Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"},
	}
	if err := ValidateDistributionManifest(manifest); err != nil {
		t.Fatalf("ValidateDistributionManifest(L7) error = %v", err)
	}
	provenance := validL5Provenance(manifest)
	provenance.ImageProfile = manifest.ImageProfile
	provenance.GuestNetwork = manifest.GuestNetwork
	if err := ValidateProvenanceAgainstManifest(provenance, manifest); err != nil {
		t.Fatalf("ValidateProvenanceAgainstManifest(L7) error = %v", err)
	}

	provenance.GuestNetwork = nil
	if err := ValidateProvenanceAgainstManifest(provenance, manifest); err == nil {
		t.Fatal("L7 provenance without network profile was accepted")
	}
}

func TestL5DistributionProfileFieldsRemainOmitted(t *testing.T) {
	manifest := validL5DistributionManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"imageProfile", "guestNetwork"} {
		if strings.Contains(string(encoded), field) {
			t.Fatalf("legacy L5 manifest gained %q: %s", field, encoded)
		}
	}
}

func TestL7DistributionProfileRejectsFeatureOrModeDrift(t *testing.T) {
	for _, network := range []*GuestNetwork{
		nil,
		{Mode: "dhcp", Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"}},
		{Mode: GuestNetworkModeStaticProxy, Features: []string{"ipv4", "ipv6", "virtio_net"}},
		{Mode: GuestNetworkModeStaticProxy, Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net", "dns"}},
	} {
		manifest := validL5DistributionManifest()
		manifest.ImageProfile = ImageProfileL7Network
		manifest.GuestNetwork = network
		if err := ValidateDistributionManifest(manifest); err == nil {
			t.Fatalf("ValidateDistributionManifest(%#v) error = nil, want fail closed", network)
		}
	}
}
