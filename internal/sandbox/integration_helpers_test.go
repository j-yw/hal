//go:build integration

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/jywlabs/hal/internal/template"
)

// requireDaytonaEnv reads DAYTONA_API_KEY and DAYTONA_SERVER_URL from
// environment variables and skips the test when credentials are unavailable.
// Returns the API key and server URL for use by the caller.
func requireDaytonaEnv(t *testing.T) (apiKey, serverURL string) {
	t.Helper()

	apiKey = os.Getenv("DAYTONA_API_KEY")
	if apiKey == "" {
		t.Skip("DAYTONA_API_KEY not set — skipping integration test (set it to run against a live Daytona environment)")
	}

	serverURL = os.Getenv("DAYTONA_SERVER_URL")
	return apiKey, serverURL
}

// newIntegrationClient returns a configured *daytona.Client using env vars.
// Calls requireDaytonaEnv to skip the test when credentials are unavailable.
func newIntegrationClient(t *testing.T) *daytona.Client {
	t.Helper()

	apiKey, serverURL := requireDaytonaEnv(t)

	client, err := NewClient(apiKey, serverURL)
	if err != nil {
		t.Fatalf("failed to create Daytona client: %v", err)
	}
	return client
}

// integrationHalDir returns a temporary .hal directory path for state file
// isolation in integration tests. The directory is automatically cleaned up.
func integrationHalDir(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), template.HalDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create integration .hal dir: %v", err)
	}
	return dir
}
