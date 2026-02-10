package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestRunCloudAuthLink(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		profile    string
		secret     string
		owner      string
		mode       string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:     "successful link with human output",
			provider: "anthropic",
			profile:  "prof-001",
			secret:   "encrypted:abc123",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile linked successfully.",
				"profile_id: prof-001",
				"provider:   anthropic",
				"status:     linked",
				"linked_at:",
			},
		},
		{
			name:       "successful link with JSON output",
			provider:   "anthropic",
			profile:    "prof-001",
			secret:     "encrypted:abc123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthLinkResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-001" {
					t.Errorf("profile_id = %q, want %q", resp.ProfileID, "prof-001")
				}
				if resp.Provider != "anthropic" {
					t.Errorf("provider = %q, want %q", resp.Provider, "anthropic")
				}
				if resp.Status != "linked" {
					t.Errorf("status = %q, want %q", resp.Status, "linked")
				}
				if resp.LinkedAt == "" {
					t.Error("linked_at should not be empty")
				}
			},
		},
		{
			name:     "missing provider returns validation error in human output",
			provider: "",
			profile:  "prof-001",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth link failed",
		},
		{
			name:       "missing provider returns validation error in JSON",
			provider:   "",
			profile:    "prof-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "validation_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "validation_error")
				}
			},
		},
		{
			name:     "missing profile returns validation error in human output",
			provider: "anthropic",
			profile:  "",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth link failed",
		},
		{
			name:       "missing profile returns validation error in JSON",
			provider:   "anthropic",
			profile:    "",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "validation_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "validation_error")
				}
			},
		},
		{
			name:       "duplicate profile returns duplicate_profile in JSON",
			provider:   "anthropic",
			profile:    "prof-001",
			secret:     "encrypted:abc",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "duplicate_profile" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "duplicate_profile")
				}
			},
		},
		{
			name:     "duplicate profile returns error in human output",
			provider: "anthropic",
			profile:  "prof-001",
			secret:   "encrypted:abc",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			wantErr: "already exists",
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			provider:   "anthropic",
			profile:    "prof-001",
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
			name:     "nil store factory returns error in human output",
			provider: "anthropic",
			profile:  "prof-001",
			store:    nil,
			wantErr:  "store not configured",
		},
		{
			name:       "store factory error in JSON",
			provider:   "anthropic",
			profile:    "prof-001",
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
			name:     "stores encrypted secret reference",
			provider: "anthropic",
			profile:  "prof-002",
			secret:   "encrypted:secret-data",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile linked successfully.",
				"prof-002",
				"anthropic",
				"linked",
			},
		},
		{
			name:     "emits audit event with provider and profile ID",
			provider: "openai",
			profile:  "prof-003",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile linked successfully.",
				"prof-003",
				"openai",
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
			err := runCloudAuthLink(
				tt.provider, tt.profile, tt.secret, tt.owner, tt.mode,
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

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

func TestClassifyAuthLinkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "nil error", err: nil, wantCode: ""},
		{name: "validation error", err: fmt.Errorf("validation failed: provider must not be empty"), wantCode: "validation_error"},
		{name: "must not be empty", err: fmt.Errorf("profile must not be empty"), wantCode: "validation_error"},
		{name: "already exists", err: fmt.Errorf("auth profile \"p1\" already exists"), wantCode: "duplicate_profile"},
		{name: "failed to create", err: fmt.Errorf("failed to create auth profile: db error"), wantCode: "store_error"},
		{name: "unknown error", err: fmt.Errorf("something unexpected"), wantCode: "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAuthLinkError(tt.err)
			if got != tt.wantCode {
				t.Errorf("classifyAuthLinkError(%v) = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}
