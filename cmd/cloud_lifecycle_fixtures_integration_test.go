//go:build integration
// +build integration

package cmd

import (
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/jywlabs/hal/internal/cloud"
)

type cloudLifecycleCheckpoint string

const (
	cloudLifecycleCheckpointSetup  cloudLifecycleCheckpoint = "setup"
	cloudLifecycleCheckpointRun    cloudLifecycleCheckpoint = "run"
	cloudLifecycleCheckpointStatus cloudLifecycleCheckpoint = "status"
	cloudLifecycleCheckpointLogs   cloudLifecycleCheckpoint = "logs"
	cloudLifecycleCheckpointPull   cloudLifecycleCheckpoint = "pull"
	cloudLifecycleCheckpointCancel cloudLifecycleCheckpoint = "cancel"
)

// Canonical camelCase JSON contract keys for lifecycle integration assertions.
const (
	cloudLifecycleJSONKeyRunID                = "runId"
	cloudLifecycleJSONKeyWorkflowKind         = "workflowKind"
	cloudLifecycleJSONKeyStatus               = "status"
	cloudLifecycleJSONKeyAttemptCount         = "attemptCount"
	cloudLifecycleJSONKeyMaxAttempts          = "maxAttempts"
	cloudLifecycleJSONKeyCurrentAttempt       = "currentAttempt"
	cloudLifecycleJSONKeyLastHeartbeatAgeSecs = "lastHeartbeatAgeSeconds"
	cloudLifecycleJSONKeyDeadlineAt           = "deadlineAt"
	cloudLifecycleJSONKeyEngine               = "engine"
	cloudLifecycleJSONKeyAuthProfileID        = "authProfileId"
	cloudLifecycleJSONKeyCreatedAt            = "createdAt"
	cloudLifecycleJSONKeyUpdatedAt            = "updatedAt"
	cloudLifecycleJSONKeyEvents               = "events"
	cloudLifecycleJSONKeyCancelRequested      = "cancelRequested"
	cloudLifecycleJSONKeyTerminalStatus       = "terminalStatus"
	cloudLifecycleJSONKeyCanceledAt           = "canceledAt"
	cloudLifecycleJSONKeySnapshotVersion      = "snapshotVersion"
	cloudLifecycleJSONKeySHA256               = "sha256"
	cloudLifecycleJSONKeyArtifacts            = "artifacts"
	cloudLifecycleJSONKeyFilesRestored        = "filesRestored"
	cloudLifecycleJSONKeyError                = "error"
	cloudLifecycleJSONKeyErrorCode            = "errorCode"
)

var cloudLifecycleJSONContractKeys = []string{
	cloudLifecycleJSONKeyRunID,
	cloudLifecycleJSONKeyWorkflowKind,
	cloudLifecycleJSONKeyStatus,
	cloudLifecycleJSONKeyAttemptCount,
	cloudLifecycleJSONKeyMaxAttempts,
	cloudLifecycleJSONKeyCurrentAttempt,
	cloudLifecycleJSONKeyLastHeartbeatAgeSecs,
	cloudLifecycleJSONKeyDeadlineAt,
	cloudLifecycleJSONKeyEngine,
	cloudLifecycleJSONKeyAuthProfileID,
	cloudLifecycleJSONKeyCreatedAt,
	cloudLifecycleJSONKeyUpdatedAt,
	cloudLifecycleJSONKeyEvents,
	cloudLifecycleJSONKeyCancelRequested,
	cloudLifecycleJSONKeyTerminalStatus,
	cloudLifecycleJSONKeyCanceledAt,
	cloudLifecycleJSONKeySnapshotVersion,
	cloudLifecycleJSONKeySHA256,
	cloudLifecycleJSONKeyArtifacts,
	cloudLifecycleJSONKeyFilesRestored,
	cloudLifecycleJSONKeyError,
	cloudLifecycleJSONKeyErrorCode,
}

type cloudLifecycleCheckpointFixture struct {
	CommandName      string
	RequiresRunID    bool
	SupportsJSON     bool
	RequiredJSONKeys []string
}

// cloudLifecycleCheckpointFixtures is the shared fixture table used by
// setup/run/status/logs/pull/cancel lifecycle scenarios.
var cloudLifecycleCheckpointFixtures = map[cloudLifecycleCheckpoint]cloudLifecycleCheckpointFixture{
	cloudLifecycleCheckpointSetup: {
		CommandName:   "setup",
		RequiresRunID: false,
		SupportsJSON:  false,
	},
	cloudLifecycleCheckpointRun: {
		CommandName:      "run",
		RequiresRunID:    false,
		SupportsJSON:     true,
		RequiredJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus},
	},
	cloudLifecycleCheckpointStatus: {
		CommandName:   "status",
		RequiresRunID: true,
		SupportsJSON:  true,
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
	cloudLifecycleCheckpointLogs: {
		CommandName:      "logs",
		RequiresRunID:    true,
		SupportsJSON:     true,
		RequiredJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyEvents},
	},
	cloudLifecycleCheckpointPull: {
		CommandName:   "pull",
		RequiresRunID: true,
		SupportsJSON:  true,
		RequiredJSONKeys: []string{
			cloudLifecycleJSONKeyRunID,
			cloudLifecycleJSONKeySnapshotVersion,
			cloudLifecycleJSONKeySHA256,
			cloudLifecycleJSONKeyArtifacts,
			cloudLifecycleJSONKeyFilesRestored,
		},
	},
	cloudLifecycleCheckpointCancel: {
		CommandName:   "cancel",
		RequiresRunID: true,
		SupportsJSON:  true,
		RequiredJSONKeys: []string{
			cloudLifecycleJSONKeyRunID,
			cloudLifecycleJSONKeyCancelRequested,
			cloudLifecycleJSONKeyStatus,
			cloudLifecycleJSONKeyCanceledAt,
		},
	},
}

type cloudLifecycleWorkflowFixture struct {
	CommandName          string
	ExpectedWorkflowKind cloud.WorkflowKind
	RequiredJSONKeys     []string
}

// cloudLifecycleWorkflowFixtures defines expected workflow kinds for all
// cloud-capable workflow commands.
var cloudLifecycleWorkflowFixtures = []cloudLifecycleWorkflowFixture{
	{
		CommandName:          "run",
		ExpectedWorkflowKind: cloud.WorkflowKindRun,
		RequiredJSONKeys:     []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus},
	},
	{
		CommandName:          "auto",
		ExpectedWorkflowKind: cloud.WorkflowKindAuto,
		RequiredJSONKeys:     []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus},
	},
	{
		CommandName:          "review",
		ExpectedWorkflowKind: cloud.WorkflowKindReview,
		RequiredJSONKeys:     []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus},
	},
}

func TestCloudLifecycleCheckpointFixtures(t *testing.T) {
	availableCommands := make(map[string]bool, len(cloudLifecycleCommandSurface))
	for _, cmd := range cloudLifecycleCommandSurface {
		availableCommands[cmd.Name] = true
	}

	tests := []struct {
		name         string
		checkpoint   cloudLifecycleCheckpoint
		wantCommand  string
		wantRunID    bool
		wantJSON     bool
		wantJSONKeys []string
		wantKeyCount int
	}{
		{
			name:         "setup fixture",
			checkpoint:   cloudLifecycleCheckpointSetup,
			wantCommand:  "setup",
			wantRunID:    false,
			wantJSON:     false,
			wantKeyCount: 0,
		},
		{
			name:         "run fixture",
			checkpoint:   cloudLifecycleCheckpointRun,
			wantCommand:  "run",
			wantRunID:    false,
			wantJSON:     true,
			wantJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus},
		},
		{
			name:         "status fixture",
			checkpoint:   cloudLifecycleCheckpointStatus,
			wantCommand:  "status",
			wantRunID:    true,
			wantJSON:     true,
			wantJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyCreatedAt, cloudLifecycleJSONKeyUpdatedAt},
		},
		{
			name:         "logs fixture",
			checkpoint:   cloudLifecycleCheckpointLogs,
			wantCommand:  "logs",
			wantRunID:    true,
			wantJSON:     true,
			wantJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyEvents},
		},
		{
			name:         "pull fixture",
			checkpoint:   cloudLifecycleCheckpointPull,
			wantCommand:  "pull",
			wantRunID:    true,
			wantJSON:     true,
			wantJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyArtifacts, cloudLifecycleJSONKeyFilesRestored, cloudLifecycleJSONKeySnapshotVersion},
		},
		{
			name:         "cancel fixture",
			checkpoint:   cloudLifecycleCheckpointCancel,
			wantCommand:  "cancel",
			wantRunID:    true,
			wantJSON:     true,
			wantJSONKeys: []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyCancelRequested, cloudLifecycleJSONKeyStatus, cloudLifecycleJSONKeyCanceledAt},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture, ok := cloudLifecycleCheckpointFixtures[tt.checkpoint]
			if !ok {
				t.Fatalf("fixture for checkpoint %q not found", tt.checkpoint)
			}
			if fixture.CommandName != tt.wantCommand {
				t.Fatalf("CommandName = %q, want %q", fixture.CommandName, tt.wantCommand)
			}
			if !availableCommands[fixture.CommandName] {
				t.Fatalf("fixture command %q not found in cloudLifecycleCommandSurface", fixture.CommandName)
			}
			if fixture.RequiresRunID != tt.wantRunID {
				t.Fatalf("RequiresRunID = %v, want %v", fixture.RequiresRunID, tt.wantRunID)
			}
			if fixture.SupportsJSON != tt.wantJSON {
				t.Fatalf("SupportsJSON = %v, want %v", fixture.SupportsJSON, tt.wantJSON)
			}

			if tt.wantJSON {
				for _, wantKey := range tt.wantJSONKeys {
					if !slices.Contains(fixture.RequiredJSONKeys, wantKey) {
						t.Errorf("RequiredJSONKeys for %q missing %q", tt.checkpoint, wantKey)
					}
				}
				for _, key := range fixture.RequiredJSONKeys {
					if !slices.Contains(cloudLifecycleJSONContractKeys, key) {
						t.Errorf("RequiredJSONKeys for %q contains unknown key %q", tt.checkpoint, key)
					}
				}
			}

			if tt.wantKeyCount > 0 && len(fixture.RequiredJSONKeys) != tt.wantKeyCount {
				t.Fatalf("len(RequiredJSONKeys) = %d, want %d", len(fixture.RequiredJSONKeys), tt.wantKeyCount)
			}
		})
	}
}

func TestCloudLifecycleWorkflowFixtures(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    cloud.WorkflowKind
	}{
		{name: "run workflow kind", command: "run", want: cloud.WorkflowKindRun},
		{name: "auto workflow kind", command: "auto", want: cloud.WorkflowKindAuto},
		{name: "review workflow kind", command: "review", want: cloud.WorkflowKindReview},
	}

	fixturesByCommand := make(map[string]cloudLifecycleWorkflowFixture, len(cloudLifecycleWorkflowFixtures))
	for _, fixture := range cloudLifecycleWorkflowFixtures {
		fixturesByCommand[fixture.CommandName] = fixture
	}

	if len(fixturesByCommand) != len(tests) {
		t.Fatalf("workflow fixture count = %d, want %d", len(fixturesByCommand), len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture, ok := fixturesByCommand[tt.command]
			if !ok {
				t.Fatalf("workflow fixture for command %q not found", tt.command)
			}
			if fixture.ExpectedWorkflowKind != tt.want {
				t.Fatalf("ExpectedWorkflowKind = %q, want %q", fixture.ExpectedWorkflowKind, tt.want)
			}
			if !fixture.ExpectedWorkflowKind.IsValid() {
				t.Fatalf("ExpectedWorkflowKind %q must be valid", fixture.ExpectedWorkflowKind)
			}

			for _, wantKey := range []string{cloudLifecycleJSONKeyRunID, cloudLifecycleJSONKeyWorkflowKind, cloudLifecycleJSONKeyStatus} {
				if !slices.Contains(fixture.RequiredJSONKeys, wantKey) {
					t.Errorf("RequiredJSONKeys for %q missing %q", tt.command, wantKey)
				}
			}
		})
	}
}

func TestCloudLifecycleJSONContractKeysCamelCase(t *testing.T) {
	seen := make(map[string]bool, len(cloudLifecycleJSONContractKeys))
	for _, key := range cloudLifecycleJSONContractKeys {
		if seen[key] {
			t.Fatalf("duplicate JSON contract key %q", key)
		}
		seen[key] = true

		if !isCamelCaseJSONKey(key) {
			t.Errorf("JSON contract key %q must be camelCase", key)
		}
	}
}

func isCamelCaseJSONKey(key string) bool {
	if key == "" {
		return false
	}
	if strings.ContainsAny(key, "_-") {
		return false
	}

	runes := []rune(key)
	if len(runes) == 0 || !unicode.IsLower(runes[0]) {
		return false
	}

	for _, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
