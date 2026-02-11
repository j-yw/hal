//go:build integration
// +build integration

package cmd

import "testing"

const (
	cloudLifecycleIntegrationPackageName = "cmd"
	cloudLifecycleIntegrationPackagePath = "./cmd"
	cloudLifecycleIntegrationBuildTag    = "integration"
	cloudLifecycleRunIDPlaceholder       = "<run-id>"
)

type cloudLifecycleCommand struct {
	Name         string
	Args         []string
	SupportsJSON bool
}

// cloudLifecycleCommandSurface is the canonical lifecycle command order used by
// cloud lifecycle integration scenarios.
var cloudLifecycleCommandSurface = []cloudLifecycleCommand{
	{Name: "setup", Args: []string{"cloud", "setup"}, SupportsJSON: false},
	{Name: "run", Args: []string{"run", "--cloud"}, SupportsJSON: true},
	{Name: "auto", Args: []string{"auto", "--cloud"}, SupportsJSON: true},
	{Name: "review", Args: []string{"review", "--cloud"}, SupportsJSON: true},
	{Name: "status", Args: []string{"cloud", "status", cloudLifecycleRunIDPlaceholder}, SupportsJSON: true},
	{Name: "logs", Args: []string{"cloud", "logs", cloudLifecycleRunIDPlaceholder}, SupportsJSON: true},
	{Name: "pull", Args: []string{"cloud", "pull", cloudLifecycleRunIDPlaceholder}, SupportsJSON: true},
	{Name: "cancel", Args: []string{"cloud", "cancel", cloudLifecycleRunIDPlaceholder}, SupportsJSON: true},
}

func TestCloudLifecycleIntegrationScaffoldMetadata(t *testing.T) {
	if cloudLifecycleIntegrationPackageName != "cmd" {
		t.Fatalf("cloudLifecycleIntegrationPackageName = %q, want %q", cloudLifecycleIntegrationPackageName, "cmd")
	}
	if cloudLifecycleIntegrationPackagePath == "" {
		t.Fatal("cloudLifecycleIntegrationPackagePath must not be empty")
	}
	if cloudLifecycleIntegrationBuildTag != "integration" {
		t.Fatalf("cloudLifecycleIntegrationBuildTag = %q, want %q", cloudLifecycleIntegrationBuildTag, "integration")
	}
	if len(cloudLifecycleCommandSurface) == 0 {
		t.Fatal("cloudLifecycleCommandSurface must not be empty")
	}
}

func TestCloudLifecycleCommandSurfaceOrder(t *testing.T) {
	want := []string{"setup", "run", "auto", "review", "status", "logs", "pull", "cancel"}

	if len(cloudLifecycleCommandSurface) != len(want) {
		t.Fatalf("cloudLifecycleCommandSurface length = %d, want %d", len(cloudLifecycleCommandSurface), len(want))
	}

	for i, command := range cloudLifecycleCommandSurface {
		if command.Name != want[i] {
			t.Errorf("command %d name = %q, want %q", i, command.Name, want[i])
		}
		if len(command.Args) == 0 {
			t.Errorf("command %q must define args", command.Name)
		}
	}
}
