package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

func TestResolveProviderConfig_FallsBackToLegacyConfigWhenGlobalPathUnavailable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	config := []byte(`sandbox:
  provider: lightsail
  lightsail:
    region: us-west-2
    availabilityZone: us-west-2a
    bundle: medium_2_0
    keyPairName: legacy-key
`)
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), config, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	providerName, provCfg, err := resolveProviderConfig(dir)
	if err != nil {
		t.Fatalf("resolveProviderConfig() error = %v", err)
	}
	if providerName != "lightsail" {
		t.Fatalf("providerName = %q, want %q", providerName, "lightsail")
	}
	if provCfg.LightsailRegion != "us-west-2" {
		t.Fatalf("LightsailRegion = %q, want %q", provCfg.LightsailRegion, "us-west-2")
	}
	if provCfg.LightsailAvailabilityZone != "us-west-2a" {
		t.Fatalf("LightsailAvailabilityZone = %q, want %q", provCfg.LightsailAvailabilityZone, "us-west-2a")
	}
	if provCfg.LightsailBundle != "medium_2_0" {
		t.Fatalf("LightsailBundle = %q, want %q", provCfg.LightsailBundle, "medium_2_0")
	}
	if provCfg.LightsailKeyPairName != "legacy-key" {
		t.Fatalf("LightsailKeyPairName = %q, want %q", provCfg.LightsailKeyPairName, "legacy-key")
	}
}

func TestResolveProviderConfig_UsesDefaultsWhenGlobalPathUnavailableAndLegacyMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	providerName, provCfg, err := resolveProviderConfig(dir)
	if err != nil {
		t.Fatalf("resolveProviderConfig() error = %v", err)
	}
	if providerName != "daytona" {
		t.Fatalf("providerName = %q, want %q", providerName, "daytona")
	}
	if provCfg != (sandbox.ProviderConfig{}) {
		t.Fatalf("ProviderConfig = %#v, want zero-value config", provCfg)
	}
}
