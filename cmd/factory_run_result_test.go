package cmd

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
)

func TestNewFactoryRunFailureSanitizesFailureDetails(t *testing.T) {
	credential := "ghp_factory_result_secret_12345"
	record := factory.RunRecord{
		RunID: "run-result-secret",
		Failure: &factory.FailureSummary{
			Category:         factory.FailureCategoryRun,
			Message:          "clone failed for https://x:" + credential + "@github.com/org/repo.git token=" + credential,
			SuggestedCommand: "retry --remote https://x:" + credential + "@github.com/org/repo.git --token=" + credential,
		},
	}

	failure := newFactoryRunFailure(record)
	if failure == nil {
		t.Fatal("newFactoryRunFailure() = nil, want failure")
	}
	for name, value := range map[string]string{
		"errorMessage":     failure.ErrorMessage,
		"suggestedCommand": failure.SuggestedCommand,
	} {
		if strings.Contains(value, credential) || strings.Contains(value, "https://x:") {
			t.Fatalf("%s leaked credentialed failure text: %q", name, value)
		}
		if !strings.Contains(strings.ToLower(value), "redacted") {
			t.Fatalf("%s = %q, want redaction marker", name, value)
		}
	}
}
