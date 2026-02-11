//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/template"
)

const cloudLifecycleSecuritySecret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

func TestCloudLifecycleSecurity_WorkflowCommandsRedactSecrets(t *testing.T) {
	tests := []struct {
		name         string
		command      string
		overrideIDFn func(runID string)
	}{
		{
			name:    "run",
			command: "run",
			overrideIDFn: func(runID string) {
				runCloudConfigFactory = func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return runID }}
				}
			},
		},
		{
			name:    "auto",
			command: "auto",
			overrideIDFn: func(runID string) {
				autoCloudConfigFactory = func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return runID }}
				}
			},
		},
		{
			name:    "review",
			command: "review",
			overrideIDFn: func(runID string) {
				reviewCloudConfigFactory = func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return runID }}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := setupCloudLifecycleIntegrationHarness(t)

			runID := fmt.Sprintf("%s-security-%s", tt.command, cloudLifecycleSecuritySecret)
			tt.overrideIDFn(runID)

			runner := newCloudLifecycleCommandRunner(h)
			fixture := mustLifecycleWorkflowFixtureForCommand(t, tt.command)

			humanResult := runner.Run(cloudLifecycleCommandInvocation{
				Args: lifecycleCommandArgs(t, fixture.CommandName),
			})
			if humanResult.Err != nil {
				t.Fatalf("%s --cloud (human) failed: %v\noutput:\n%s", tt.command, humanResult.Err, humanResult.Output)
			}
			assertLifecycleOutputRedacted(t, humanResult.Output, cloudLifecycleSecuritySecret)

			jsonResult := runner.Run(cloudLifecycleCommandInvocation{
				Args: lifecycleCommandArgs(t, fixture.CommandName),
				JSON: true,
			})
			if jsonResult.Err != nil {
				t.Fatalf("%s --cloud --json failed: %v\noutput:\n%s", tt.command, jsonResult.Err, jsonResult.Output)
			}

			payload := assertLifecycleJSONOutputRedacted(t, jsonResult.Output, cloudLifecycleSecuritySecret)
			assertLifecycleRequiredJSONKeys(t, payload, fixture.RequiredJSONKeys)
		})
	}
}

func TestCloudLifecycleSecurity_CloudCommandsRedactSecrets(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint cloudLifecycleCheckpoint
		seed       func(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string)
	}{
		{
			name:       "status",
			checkpoint: cloudLifecycleCheckpointStatus,
			seed: func(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
				t.Helper()
				seedLifecycleSecurityRun(t, h, runID, cloud.RunStatusRunning)
			},
		},
		{
			name:       "logs",
			checkpoint: cloudLifecycleCheckpointLogs,
			seed: func(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
				t.Helper()
				seedLifecycleSecurityRun(t, h, runID, cloud.RunStatusRunning)

				payload := fmt.Sprintf(`{"runId":"%s","token":"%s"}`, runID, cloudLifecycleSecuritySecret)
				if err := h.Store.InsertEvent(context.Background(), &cloud.Event{
					ID:          runID + "-secret-event",
					RunID:       runID,
					EventType:   "secret_event",
					PayloadJSON: &payload,
					CreatedAt:   time.Now().UTC(),
				}); err != nil {
					t.Fatalf("failed to seed log event: %v", err)
				}
			},
		},
		{
			name:       "cancel",
			checkpoint: cloudLifecycleCheckpointCancel,
			seed: func(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
				t.Helper()
				seedLifecycleSecurityRun(t, h, runID, cloud.RunStatusRunning)
			},
		},
		{
			name:       "pull",
			checkpoint: cloudLifecycleCheckpointPull,
			seed: func(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
				t.Helper()
				seedLifecycleSecurityRun(t, h, runID, cloud.RunStatusSucceeded)

				bundlePath := filepath.ToSlash(filepath.Join(template.HalDir, "reports", "security-"+cloudLifecycleSecuritySecret+".md"))
				h.Store.snapshots[runID] = makeBundleSnapshot(t, runID, 1, map[string]string{
					bundlePath: "redaction coverage",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := setupCloudLifecycleIntegrationHarness(t)
			runner := newCloudLifecycleCommandRunner(h)
			fixture := mustLifecycleCheckpointFixture(t, tt.checkpoint)

			runID := fmt.Sprintf("%s-security-%s", tt.name, cloudLifecycleSecuritySecret)
			tt.seed(t, h, runID)

			humanResult := runner.Run(cloudLifecycleCommandInvocation{
				Args:  lifecycleCommandArgs(t, fixture.CommandName),
				RunID: runID,
			})
			if humanResult.Err != nil {
				t.Fatalf("cloud %s (human) failed: %v\noutput:\n%s", tt.name, humanResult.Err, humanResult.Output)
			}
			assertLifecycleOutputRedacted(t, humanResult.Output, cloudLifecycleSecuritySecret)

			jsonResult := runner.Run(cloudLifecycleCommandInvocation{
				Args:  lifecycleCommandArgs(t, fixture.CommandName),
				RunID: runID,
				JSON:  true,
			})
			if jsonResult.Err != nil {
				t.Fatalf("cloud %s --json failed: %v\noutput:\n%s", tt.name, jsonResult.Err, jsonResult.Output)
			}

			payload := assertLifecycleJSONOutputRedacted(t, jsonResult.Output, cloudLifecycleSecuritySecret)
			assertLifecycleRequiredJSONKeys(t, payload, fixture.RequiredJSONKeys)
		})
	}
}

func TestCloudLifecycleSecurity_AuthJSONCamelCaseContract(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	storeFactory := func() (cloud.Store, error) { return h.Store, nil }

	profile := h.Store.profiles[h.defaultAuthID]
	if profile == nil {
		t.Fatalf("expected seeded auth profile %q", h.defaultAuthID)
	}
	secretRef := "encrypted:integration"
	profile.SecretRef = &secretRef
	h.Store.profiles[h.defaultAuthID] = profile

	var statusOut bytes.Buffer
	if err := runCloudAuthStatus(h.defaultAuthID, true, storeFactory, &statusOut); err != nil {
		t.Fatalf("cloud auth status --json failed: %v", err)
	}
	statusPayload := mustDecodeLifecycleJSONOutput(t, statusOut.String())
	assertLifecycleJSONCamelCaseKeys(t, statusPayload,
		[]string{cloudLifecycleJSONKeyProfileID, cloudLifecycleJSONKeyStatus},
		[]string{"profile_id", "last_validated_at"},
	)

	var validateOut bytes.Buffer
	if err := runCloudAuthValidate(h.defaultAuthID, true, storeFactory, &validateOut); err != nil {
		t.Fatalf("cloud auth validate --json failed: %v", err)
	}
	validatePayload := mustDecodeLifecycleJSONOutput(t, validateOut.String())
	assertLifecycleJSONCamelCaseKeys(t, validatePayload,
		[]string{cloudLifecycleJSONKeyProfileID, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyValidatedAt},
		[]string{"profile_id", "validated_at"},
	)

	var revokeOut bytes.Buffer
	if err := runCloudAuthRevoke(h.defaultAuthID, true, storeFactory, &revokeOut); err != nil {
		t.Fatalf("cloud auth revoke --json failed: %v", err)
	}
	revokePayload := mustDecodeLifecycleJSONOutput(t, revokeOut.String())
	assertLifecycleJSONCamelCaseKeys(t, revokePayload,
		[]string{cloudLifecycleJSONKeyProfileID, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyRevokedAt},
		[]string{"profile_id", "revoked_at"},
	)
}

func TestCloudLifecycleSecurity_AuthStatusRedactsSecretProfileID(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	storeFactory := func() (cloud.Store, error) { return h.Store, nil }

	secretProfileID := "missing-" + cloudLifecycleSecuritySecret

	var humanOut bytes.Buffer
	if err := runCloudAuthStatus(secretProfileID, false, storeFactory, &humanOut); err != nil {
		t.Fatalf("cloud auth status (human) failed: %v", err)
	}
	assertLifecycleOutputRedacted(t, humanOut.String(), cloudLifecycleSecuritySecret)

	var jsonOut bytes.Buffer
	if err := runCloudAuthStatus(secretProfileID, true, storeFactory, &jsonOut); err != nil {
		t.Fatalf("cloud auth status --json failed: %v", err)
	}
	assertLifecycleJSONOutputRedacted(t, jsonOut.String(), cloudLifecycleSecuritySecret)
}

func seedLifecycleSecurityRun(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string, status cloud.RunStatus) {
	t.Helper()

	now := time.Now().UTC()
	deadline := now.Add(30 * time.Minute)
	run := &cloud.Run{
		ID:            runID,
		WorkflowKind:  cloud.WorkflowKindRun,
		Status:        status,
		AttemptCount:  1,
		MaxAttempts:   3,
		Repo:          "acme/hal",
		BaseBranch:    "main",
		Engine:        "claude",
		AuthProfileID: h.defaultAuthID,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := h.Store.EnqueueRun(context.Background(), run); err != nil {
		t.Fatalf("failed to seed run: %v", err)
	}
	h.Store.runsByID[runID] = run
	h.Store.activeAttempts[runID] = &cloud.Attempt{
		ID:            runID + "-attempt-1",
		RunID:         runID,
		AttemptNumber: 1,
		HeartbeatAt:   now,
	}
}

func assertLifecycleJSONCamelCaseKeys(t *testing.T, payload map[string]interface{}, requiredCamelCase []string, forbiddenSnakeCase []string) {
	t.Helper()

	for _, key := range requiredCamelCase {
		value, ok := payload[key]
		if !ok {
			t.Fatalf("JSON payload missing required camelCase key %q: %v", key, payload)
		}
		if str, ok := value.(string); ok && strings.TrimSpace(str) == "" {
			t.Fatalf("JSON key %q must not be empty", key)
		}
	}

	for _, key := range forbiddenSnakeCase {
		if _, ok := payload[key]; ok {
			t.Fatalf("JSON payload contains forbidden snake_case key %q: %v", key, payload)
		}
	}
}
