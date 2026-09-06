package sandbox_test

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSandboxCIFeatureIntegrationTriggers(t *testing.T) {
	payload, err := os.ReadFile("../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On map[string]struct {
			Branches []string `yaml:"branches"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(payload, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"push", "pull_request"} {
		for _, branch := range []string{
			"main", "develop", "sandbox*", "hal/sandbox*", "compound/sandbox*",
			"feature/sandbox-runtime-secure-default-v2",
		} {
			if !slices.Contains(workflow.On[event].Branches, branch) {
				t.Errorf("CI %s branch filters omit %q", event, branch)
			}
		}
	}
}
