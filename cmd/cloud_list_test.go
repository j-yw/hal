package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestRunCloudList(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name       string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		notOutput  []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name: "successful list with human output",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runs = []*cloud.Run{
					{
						ID:           "run-001",
						WorkflowKind: cloud.WorkflowKindRun,
						Status:       cloud.RunStatusRunning,
						UpdatedAt:    now,
					},
					{
						ID:           "run-002",
						WorkflowKind: cloud.WorkflowKindAuto,
						Status:       cloud.RunStatusSucceeded,
						UpdatedAt:    now.Add(-time.Hour),
					},
				}
				return s
			},
			wantOutput: []string{
				"Recent cloud runs:",
				"run-001",
				"run",
				"running",
				"run-002",
				"auto",
				"succeeded",
			},
		},
		{
			name:       "successful list with JSON output",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runs = []*cloud.Run{
					{
						ID:           "run-001",
						WorkflowKind: cloud.WorkflowKindRun,
						Status:       cloud.RunStatusRunning,
						UpdatedAt:    now,
					},
					{
						ID:           "run-002",
						WorkflowKind: cloud.WorkflowKindReview,
						Status:       cloud.RunStatusQueued,
						UpdatedAt:    now.Add(-time.Minute),
					},
				}
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudListResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if len(resp.Runs) != 2 {
					t.Fatalf("expected 2 runs, got %d", len(resp.Runs))
				}
				if resp.Runs[0].RunID != "run-001" {
					t.Errorf("runs[0].run_id = %q, want %q", resp.Runs[0].RunID, "run-001")
				}
				if resp.Runs[0].WorkflowKind != "run" {
					t.Errorf("runs[0].workflow_kind = %q, want %q", resp.Runs[0].WorkflowKind, "run")
				}
				if resp.Runs[0].Status != "running" {
					t.Errorf("runs[0].status = %q, want %q", resp.Runs[0].Status, "running")
				}
				if resp.Runs[0].UpdatedAt == "" {
					t.Error("runs[0].updated_at should not be empty")
				}
				if resp.Runs[1].RunID != "run-002" {
					t.Errorf("runs[1].run_id = %q, want %q", resp.Runs[1].RunID, "run-002")
				}
				if resp.Runs[1].WorkflowKind != "review" {
					t.Errorf("runs[1].workflow_kind = %q, want %q", resp.Runs[1].WorkflowKind, "review")
				}
			},
		},
		{
			name: "empty list with human output",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{"No cloud runs found."},
		},
		{
			name:       "empty list with JSON output is valid JSON",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudListResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.Runs == nil {
					t.Error("runs should be empty array, not null")
				}
				if len(resp.Runs) != 0 {
					t.Errorf("expected 0 runs, got %d", len(resp.Runs))
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			jsonOutput: true,
			store:      nil,
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:    "nil store factory returns error in human output",
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:       "store factory error in JSON",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return nil // signals store factory error
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name: "store factory error in human output",
			store: func() *cloudMockStore {
				return nil
			},
			wantErr: "failed to connect to store",
		},
		{
			name:       "store error on ListRuns in JSON",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.listRunsErr = fmt.Errorf("db connection failed")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "store_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "store_error")
				}
			},
		},
		{
			name: "store error on ListRuns in human output",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.listRunsErr = fmt.Errorf("db connection failed")
				return s
			},
			wantErr: "failed to list runs",
		},
		{
			name:       "JSON output contains required fields for each run",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runs = []*cloud.Run{
					{
						ID:           "run-check",
						WorkflowKind: cloud.WorkflowKindAuto,
						Status:       cloud.RunStatusFailed,
						UpdatedAt:    now,
					},
				}
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(output), &raw); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				runsRaw, ok := raw["runs"]
				if !ok {
					t.Fatal("missing 'runs' key in JSON")
				}
				runsArr, ok := runsRaw.([]interface{})
				if !ok {
					t.Fatal("'runs' is not an array")
				}
				if len(runsArr) != 1 {
					t.Fatalf("expected 1 run, got %d", len(runsArr))
				}
				entry := runsArr[0].(map[string]interface{})
				requiredKeys := []string{"run_id", "workflow_kind", "status", "updated_at"}
				for _, key := range requiredKeys {
					if _, ok := entry[key]; !ok {
						t.Errorf("missing required JSON key %q in run entry", key)
					}
				}
			},
		},
		{
			name:       "JSON output with no mixed plain-text lines",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runs = []*cloud.Run{
					{
						ID:           "run-json",
						WorkflowKind: cloud.WorkflowKindRun,
						Status:       cloud.RunStatusQueued,
						UpdatedAt:    now,
					},
				}
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				// The entire output should be valid JSON with no extra lines.
				trimmed := strings.TrimSpace(output)
				if !strings.HasPrefix(trimmed, "{") {
					t.Errorf("JSON output should start with '{', got %q", trimmed[:10])
				}
				var resp cloudListResponse
				if err := json.Unmarshal([]byte(trimmed), &resp); err != nil {
					t.Fatalf("output is not valid JSON: %v\noutput: %s", err, trimmed)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var out bytes.Buffer
			err := runCloudList(
				tt.jsonOutput,
				storeFactory,
				&out,
			)

			output := out.String()

			// For JSON error cases, check JSON first then error.
			if tt.checkJSON != nil && output != "" {
				tt.checkJSON(t, strings.TrimSpace(output))
			}

			if tt.wantErr != "" {
				if err == nil {
					if !strings.Contains(output, tt.wantErr) {
						t.Fatalf("expected error containing %q, got nil error and output %q", tt.wantErr, output)
					}
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output does not contain %q\noutput: %s", want, output)
				}
			}

			for _, notWant := range tt.notOutput {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q but does", notWant)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

func TestCloudListDefaultFactory(t *testing.T) {
	if cloudListStoreFactory == nil {
		t.Fatal("cloudListStoreFactory should be initialized")
	}
}
