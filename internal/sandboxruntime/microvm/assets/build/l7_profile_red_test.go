package build

import "testing"

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
