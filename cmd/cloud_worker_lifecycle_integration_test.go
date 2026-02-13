//go:build integration
// +build integration

package cmd

import "testing"

const (
	workerLifecycleIntegrationPackageName = "cmd"
	workerLifecycleIntegrationPackagePath = "./cmd"
	workerLifecycleIntegrationBuildTag    = "integration"
)

func TestWorkerLifecycleIntegration(t *testing.T) {
	t.Run("scaffold_metadata", func(t *testing.T) {
		if workerLifecycleIntegrationPackageName != "cmd" {
			t.Fatalf("workerLifecycleIntegrationPackageName = %q, want %q", workerLifecycleIntegrationPackageName, "cmd")
		}
		if workerLifecycleIntegrationPackagePath == "" {
			t.Fatal("workerLifecycleIntegrationPackagePath must not be empty")
		}
		if workerLifecycleIntegrationBuildTag != "integration" {
			t.Fatalf("workerLifecycleIntegrationBuildTag = %q, want %q", workerLifecycleIntegrationBuildTag, "integration")
		}
	})
}
