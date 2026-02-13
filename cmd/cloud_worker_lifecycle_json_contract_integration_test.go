//go:build integration
// +build integration

package cmd

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type workerLifecycleJSONContractCheckpoint string

const (
	workerLifecycleJSONContractCheckpointStatus workerLifecycleJSONContractCheckpoint = "status"
	workerLifecycleJSONContractCheckpointLogs   workerLifecycleJSONContractCheckpoint = "logs"
	workerLifecycleJSONContractCheckpointPull   workerLifecycleJSONContractCheckpoint = "pull"
)

type workerLifecycleJSONContractFixture struct {
	RequiredJSONKeys []string
}

// workerLifecycleJSONContractFixtures centralizes worker lifecycle --json
// required-key contracts for status/logs/pull assertions.
var workerLifecycleJSONContractFixtures = map[workerLifecycleJSONContractCheckpoint]workerLifecycleJSONContractFixture{
	workerLifecycleJSONContractCheckpointStatus: {
		RequiredJSONKeys: []string{
			cloudLifecycleJSONKeyRunID,
			cloudLifecycleJSONKeyWorkflowKind,
			cloudLifecycleJSONKeyStatus,
			cloudLifecycleJSONKeyAttemptCount,
			cloudLifecycleJSONKeyMaxAttempts,
			cloudLifecycleJSONKeyCreatedAt,
			cloudLifecycleJSONKeyUpdatedAt,
		},
	},
	workerLifecycleJSONContractCheckpointLogs: {
		RequiredJSONKeys: []string{
			cloudLifecycleJSONKeyRunID,
			cloudLifecycleJSONKeyStatus,
			cloudLifecycleJSONKeyEvents,
		},
	},
	workerLifecycleJSONContractCheckpointPull: {
		RequiredJSONKeys: []string{
			cloudLifecycleJSONKeyRunID,
			cloudLifecycleJSONKeySnapshotVersion,
			cloudLifecycleJSONKeySHA256,
			cloudLifecycleJSONKeyArtifacts,
			cloudLifecycleJSONKeyFilesRestored,
		},
	},
}

func mustWorkerLifecycleJSONContractFixture(t *testing.T, checkpoint workerLifecycleJSONContractCheckpoint) workerLifecycleJSONContractFixture {
	t.Helper()

	fixture, ok := workerLifecycleJSONContractFixtures[checkpoint]
	if !ok {
		t.Fatalf("worker lifecycle JSON fixture %q not found", checkpoint)
	}

	return workerLifecycleJSONContractFixture{
		RequiredJSONKeys: append([]string(nil), fixture.RequiredJSONKeys...),
	}
}

func decodeWorkerLifecycleJSONOutput(output string) (map[string]interface{}, error) {
	return decodeLifecycleJSONOutput(output)
}

func mustDecodeWorkerLifecycleJSONOutput(t *testing.T, output string) map[string]interface{} {
	t.Helper()

	payload, err := decodeWorkerLifecycleJSONOutput(output)
	if err != nil {
		t.Fatalf("failed to decode worker lifecycle JSON output: %v\noutput: %s", err, output)
	}
	return payload
}

func assertWorkerLifecycleCheckpointJSONContract(t *testing.T, payload map[string]interface{}, checkpoint workerLifecycleJSONContractCheckpoint) {
	t.Helper()
	fixture := mustWorkerLifecycleJSONContractFixture(t, checkpoint)
	assertLifecycleRequiredJSONKeys(t, payload, fixture.RequiredJSONKeys)
}

func assertWorkerLifecycleCanonicalJSONContract(t *testing.T, payload map[string]interface{}, requiredCanonicalKeys []string) {
	t.Helper()
	assertLifecycleRequiredJSONKeys(t, payload, requiredCanonicalKeys)

	aliases := workerLifecycleSnakeCaseAliasesForCanonicalKeys(requiredCanonicalKeys)
	presentAliases := workerLifecyclePresentJSONKeys(payload, aliases)
	if len(presentAliases) > 0 {
		t.Fatalf(
			"JSON payload contains forbidden snake_case keys %v for canonical keys %v: %v",
			presentAliases,
			requiredCanonicalKeys,
			payload,
		)
	}
}

func workerLifecycleSnakeCaseAliasesForCanonicalKeys(requiredCanonicalKeys []string) []string {
	aliases := make([]string, 0, len(requiredCanonicalKeys))
	seen := make(map[string]bool, len(requiredCanonicalKeys))
	for _, key := range requiredCanonicalKeys {
		alias, ok := cloudLifecycleJSONLegacyAliases[key]
		if !ok || alias == "" || seen[alias] {
			continue
		}
		aliases = append(aliases, alias)
		seen[alias] = true
	}
	return aliases
}

func workerLifecyclePresentJSONKeys(payload map[string]interface{}, keys []string) []string {
	present := make([]string, 0, len(keys))
	for _, key := range keys {
		if _, ok := payload[key]; ok {
			present = append(present, key)
		}
	}
	return present
}

func TestWorkerLifecycleJSONContractFixtures(t *testing.T) {
	tests := []struct {
		name           string
		checkpoint     workerLifecycleJSONContractCheckpoint
		requiredSubset []string
	}{
		{
			name:       "status fixture uses canonical keys",
			checkpoint: workerLifecycleJSONContractCheckpointStatus,
			requiredSubset: []string{
				cloudLifecycleJSONKeyRunID,
				cloudLifecycleJSONKeyWorkflowKind,
				cloudLifecycleJSONKeyStatus,
			},
		},
		{
			name:       "logs fixture uses canonical keys",
			checkpoint: workerLifecycleJSONContractCheckpointLogs,
			requiredSubset: []string{
				cloudLifecycleJSONKeyRunID,
				cloudLifecycleJSONKeyStatus,
				cloudLifecycleJSONKeyEvents,
			},
		},
		{
			name:       "pull fixture uses canonical keys",
			checkpoint: workerLifecycleJSONContractCheckpointPull,
			requiredSubset: []string{
				cloudLifecycleJSONKeyRunID,
				cloudLifecycleJSONKeyArtifacts,
				cloudLifecycleJSONKeyFilesRestored,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := mustWorkerLifecycleJSONContractFixture(t, tt.checkpoint)
			if len(fixture.RequiredJSONKeys) == 0 {
				t.Fatalf("fixture %q must define required keys", tt.checkpoint)
			}

			for _, key := range tt.requiredSubset {
				if !slices.Contains(fixture.RequiredJSONKeys, key) {
					t.Fatalf("fixture %q missing required key %q", tt.checkpoint, key)
				}
			}

			for _, key := range fixture.RequiredJSONKeys {
				if !isCamelCaseJSONKey(key) {
					t.Fatalf("fixture %q contains non-camelCase key %q", tt.checkpoint, key)
				}
				if !slices.Contains(cloudLifecycleJSONContractKeys, key) {
					t.Fatalf("fixture %q contains unknown lifecycle contract key %q", tt.checkpoint, key)
				}
			}
		})
	}
}

func TestDecodeWorkerLifecycleJSONOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantErr    string
		checkValue func(t *testing.T, payload map[string]interface{})
	}{
		{
			name:   "decodes valid json payload",
			output: "{\"runId\":\"run-001\",\"attemptCount\":1}",
			checkValue: func(t *testing.T, payload map[string]interface{}) {
				t.Helper()
				runID, ok := lifecycleJSONStringField(payload, cloudLifecycleJSONKeyRunID)
				if !ok || runID != "run-001" {
					t.Fatalf("run ID = %q, want %q", runID, "run-001")
				}
				attemptCount, ok := payload[cloudLifecycleJSONKeyAttemptCount].(json.Number)
				if !ok || attemptCount.String() != "1" {
					t.Fatalf("attemptCount = %#v, want json.Number(1)", payload[cloudLifecycleJSONKeyAttemptCount])
				}
			},
		},
		{
			name:    "rejects empty output",
			output:  "\n\t",
			wantErr: "json output is empty",
		},
		{
			name:    "rejects invalid json",
			output:  "{runId}",
			wantErr: "decode json output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := decodeWorkerLifecycleJSONOutput(tt.output)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkValue != nil {
				tt.checkValue(t, payload)
			}
		})
	}
}

func TestWorkerLifecycleSnakeCaseAliasesForCanonicalKeys(t *testing.T) {
	aliases := workerLifecycleSnakeCaseAliasesForCanonicalKeys([]string{
		cloudLifecycleJSONKeyRunID,
		cloudLifecycleJSONKeyWorkflowKind,
		cloudLifecycleJSONKeyStatus,
		cloudLifecycleJSONKeyRunID, // duplicate should not duplicate alias output
	})

	if !slices.Equal(aliases, []string{"run_id", "workflow_kind"}) {
		t.Fatalf("aliases = %v, want %v", aliases, []string{"run_id", "workflow_kind"})
	}
}

func TestWorkerLifecyclePresentJSONKeys(t *testing.T) {
	payload := map[string]interface{}{
		cloudLifecycleJSONKeyRunID: "run-001",
		"run_id":                   "legacy-run-001",
		"status":                   "queued",
	}

	present := workerLifecyclePresentJSONKeys(payload, []string{"run_id", "workflow_kind", "status"})
	if !slices.Equal(present, []string{"run_id", "status"}) {
		t.Fatalf("present keys = %v, want %v", present, []string{"run_id", "status"})
	}
}
