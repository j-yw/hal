//go:build integration
// +build integration

package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func assertLifecycleOutputRedacted(t *testing.T, output string, secrets ...string) {
	t.Helper()

	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(output, secret) {
			t.Fatalf("output contains unredacted secret %q\noutput:\n%s", secret, output)
		}
	}

	if len(secrets) > 0 && !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected output to contain [REDACTED] placeholder\noutput:\n%s", output)
	}
}

func assertLifecycleJSONOutputRedacted(t *testing.T, output string, secrets ...string) map[string]interface{} {
	t.Helper()

	payload := mustDecodeLifecycleJSONOutput(t, output)
	assertLifecycleJSONPayloadRedacted(t, payload, secrets...)
	return payload
}

func assertLifecycleJSONPayloadRedacted(t *testing.T, payload map[string]interface{}, secrets ...string) {
	t.Helper()

	serialized, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal JSON payload for redaction assertion: %v", err)
	}
	assertLifecycleOutputRedacted(t, string(serialized), secrets...)
}
