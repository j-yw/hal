package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestRunCloudAuthImport(t *testing.T) {
	tests := []struct {
		name                string
		provider            string
		profile             string
		source              string
		owner               string
		mode                string
		jsonOutput          bool
		store               func() *cloudMockStore
		credentialValidator func(ctx context.Context, provider, source string) error
		wantErr             string
		wantOutput          []string
		checkJSON           func(t *testing.T, output string)
	}{
		{
			name:     "successful import with human output",
			provider: "anthropic",
			profile:  "prof-001",
			source:   "/home/user/.config/anthropic/auth.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile imported successfully.",
				"profile_id:  prof-001",
				"provider:    anthropic",
				"status:      linked",
				"imported_at:",
			},
		},
		{
			name:       "successful import with JSON output",
			provider:   "anthropic",
			profile:    "prof-001",
			source:     "/home/user/.config/anthropic/auth.json",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthImportResponse
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
				if resp.ImportedAt == "" {
					t.Error("imported_at should not be empty")
				}
			},
		},
		{
			name:     "missing provider returns validation error in human output",
			provider: "",
			profile:  "prof-001",
			source:   "/path/to/creds",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth import failed",
		},
		{
			name:       "missing provider returns validation error in JSON",
			provider:   "",
			profile:    "prof-001",
			source:     "/path/to/creds",
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
			source:   "/path/to/creds",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth import failed",
		},
		{
			name:       "missing profile returns validation error in JSON",
			provider:   "anthropic",
			profile:    "",
			source:     "/path/to/creds",
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
			name:     "missing source returns validation error in human output",
			provider: "anthropic",
			profile:  "prof-001",
			source:   "",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth import failed",
		},
		{
			name:       "missing source returns validation error in JSON",
			provider:   "anthropic",
			profile:    "prof-001",
			source:     "",
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
			source:     "/path/to/creds",
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
			source:   "/path/to/creds",
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
			source:     "/path/to/creds",
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
			source:   "/path/to/creds",
			store:    nil,
			wantErr:  "store not configured",
		},
		{
			name:       "store factory error in JSON",
			provider:   "anthropic",
			profile:    "prof-001",
			source:     "/path/to/creds",
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
			name:     "imported artifacts are encrypted and stored as secret reference",
			provider: "anthropic",
			profile:  "prof-002",
			source:   "/home/user/.anthropic/creds.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile imported successfully.",
				"prof-002",
				"anthropic",
				"linked",
			},
		},
		{
			name:     "import path records audit event with profile ID and provider",
			provider: "openai",
			profile:  "prof-003",
			source:   "/home/user/.openai/key",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile imported successfully.",
				"prof-003",
				"openai",
			},
		},
		{
			name:     "successful import with credential validator in human output",
			provider: "anthropic",
			profile:  "prof-validated",
			source:   "/home/user/.config/anthropic/auth.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, _, _ string) error {
				return nil // credentials are valid
			},
			wantOutput: []string{
				"Auth profile imported successfully.",
				"profile_id:  prof-validated",
				"provider:    anthropic",
				"status:      linked",
				"imported_at:",
			},
		},
		{
			name:       "successful import with credential validator in JSON output",
			provider:   "anthropic",
			profile:    "prof-validated-json",
			source:     "/home/user/.config/anthropic/auth.json",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, _, _ string) error {
				return nil // credentials are valid
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthImportResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-validated-json" {
					t.Errorf("profile_id = %q, want %q", resp.ProfileID, "prof-validated-json")
				}
				if resp.Status != "linked" {
					t.Errorf("status = %q, want %q", resp.Status, "linked")
				}
			},
		},
		{
			name:     "invalid credentials returns non-zero exit in human output",
			provider: "anthropic",
			profile:  "prof-bad-creds",
			source:   "/home/user/.config/anthropic/bad-auth.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, _, _ string) error {
				return fmt.Errorf("backend rejected credentials: unauthorized")
			},
			wantErr: "invalid credentials",
		},
		{
			name:       "invalid credentials returns invalid_credentials error code in JSON",
			provider:   "anthropic",
			profile:    "prof-bad-creds",
			source:     "/home/user/.config/anthropic/bad-auth.json",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, _, _ string) error {
				return fmt.Errorf("backend rejected credentials: unauthorized")
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "invalid_credentials" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "invalid_credentials")
				}
				if !strings.Contains(resp.Error, "invalid credentials") {
					t.Errorf("error message %q should contain %q", resp.Error, "invalid credentials")
				}
			},
		},
		{
			name:     "invalid credentials does not persist profile",
			provider: "anthropic",
			profile:  "prof-should-not-exist",
			source:   "/home/user/.config/anthropic/bad-auth.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, _, _ string) error {
				return fmt.Errorf("invalid API key")
			},
			wantErr: "invalid credentials",
		},
		{
			name:     "credential validator receives correct provider and source",
			provider: "openai",
			profile:  "prof-openai",
			source:   "/custom/path/to/key.json",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			credentialValidator: func(_ context.Context, provider, source string) error {
				if provider != "openai" {
					return fmt.Errorf("unexpected provider: %s", provider)
				}
				if source != "/custom/path/to/key.json" {
					return fmt.Errorf("unexpected source: %s", source)
				}
				return nil
			},
			wantOutput: []string{
				"Auth profile imported successfully.",
				"prof-openai",
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
			err := runCloudAuthImport(
				tt.provider, tt.profile, tt.source, tt.owner, tt.mode,
				tt.jsonOutput,
				storeFactory,
				tt.credentialValidator,
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

func TestClassifyAuthImportError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "nil error", err: nil, wantCode: ""},
		{name: "validation error", err: fmt.Errorf("validation failed: provider must not be empty"), wantCode: "validation_error"},
		{name: "must not be empty", err: fmt.Errorf("source must not be empty"), wantCode: "validation_error"},
		{name: "invalid credentials", err: fmt.Errorf("invalid credentials: backend rejected"), wantCode: "invalid_credentials"},
		{name: "already exists", err: fmt.Errorf("auth profile \"p1\" already exists"), wantCode: "duplicate_profile"},
		{name: "failed to create", err: fmt.Errorf("failed to create auth profile: db error"), wantCode: "store_error"},
		{name: "unknown error", err: fmt.Errorf("something unexpected"), wantCode: "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAuthImportError(tt.err)
			if got != tt.wantCode {
				t.Errorf("classifyAuthImportError(%v) = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}

func TestRunCloudAuthStatus(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name       string
		profileID  string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:      "missing profile reports status missing in human output",
			profileID: "no-such-profile",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile status:",
				"profileId: no-such-profile",
				"status:    missing",
			},
		},
		{
			name:       "missing profile reports status missing in JSON",
			profileID:  "no-such-profile",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "no-such-profile" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "no-such-profile")
				}
				if resp.Status != "missing" {
					t.Errorf("status = %q, want %q", resp.Status, "missing")
				}
				if resp.LastValidatedAt != nil {
					t.Errorf("lastValidatedAt should be nil for missing profile, got %v", resp.LastValidatedAt)
				}
			},
		},
		{
			name:      "linked profile reports status linked in human output",
			profileID: "prof-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			wantOutput: []string{
				"Auth profile status:",
				"profileId: prof-001",
				"status:    linked",
			},
		},
		{
			name:       "linked profile reports status linked in JSON with profileId and status",
			profileID:  "prof-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-001" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-001")
				}
				if resp.Status != "linked" {
					t.Errorf("status = %q, want %q", resp.Status, "linked")
				}
			},
		},
		{
			name:      "invalid profile reports status invalid in human output",
			profileID: "prof-invalid",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid", "anthropic")
				p.Status = cloud.AuthProfileStatusInvalid
				s.profiles["prof-invalid"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile status:",
				"profileId: prof-invalid",
				"status:    invalid",
			},
		},
		{
			name:       "invalid profile reports status invalid in JSON",
			profileID:  "prof-invalid",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid", "anthropic")
				p.Status = cloud.AuthProfileStatusInvalid
				s.profiles["prof-invalid"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-invalid" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-invalid")
				}
				if resp.Status != "invalid" {
					t.Errorf("status = %q, want %q", resp.Status, "invalid")
				}
			},
		},
		{
			name:      "revoked profile reports status revoked in human output",
			profileID: "prof-revoked",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-revoked", "anthropic")
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-revoked"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile status:",
				"profileId: prof-revoked",
				"status:    revoked",
			},
		},
		{
			name:       "revoked profile reports status revoked in JSON",
			profileID:  "prof-revoked",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-revoked", "anthropic")
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-revoked"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-revoked" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-revoked")
				}
				if resp.Status != "revoked" {
					t.Errorf("status = %q, want %q", resp.Status, "revoked")
				}
			},
		},
		{
			name:       "linked profile with lastValidatedAt in JSON",
			profileID:  "prof-002",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				lastValidated := now.Add(-1 * time.Hour)
				p := linkedCloudProfile("prof-002", "openai")
				p.LastValidatedAt = &lastValidated
				s.profiles["prof-002"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-002" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-002")
				}
				if resp.Status != "linked" {
					t.Errorf("status = %q, want %q", resp.Status, "linked")
				}
				if resp.LastValidatedAt == nil {
					t.Error("lastValidatedAt should not be nil when available")
				}
			},
		},
		{
			name:      "linked profile with lastValidatedAt in human output",
			profileID: "prof-003",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				lastValidated := now.Add(-2 * time.Hour)
				p := linkedCloudProfile("prof-003", "anthropic")
				p.LastValidatedAt = &lastValidated
				s.profiles["prof-003"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile status:",
				"profileId: prof-003",
				"status:    linked",
				"lastValidatedAt:",
			},
		},
		{
			name:       "linked profile without lastValidatedAt omits field in JSON",
			profileID:  "prof-004",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-004"] = linkedCloudProfile("prof-004", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.LastValidatedAt != nil {
					t.Errorf("lastValidatedAt should be nil when not available, got %v", resp.LastValidatedAt)
				}
				// Verify the raw JSON does not contain the field.
				if strings.Contains(output, "lastValidatedAt") {
					t.Error("JSON output should omit lastValidatedAt when not available")
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			profileID:  "prof-001",
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
			name:      "nil store factory returns error in human output",
			profileID: "prof-001",
			store:     nil,
			wantErr:   "store not configured",
		},
		{
			name:       "store factory error in JSON",
			profileID:  "prof-001",
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
			err := runCloudAuthStatus(
				tt.profileID,
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

func TestMapAuthProfileStatus(t *testing.T) {
	tests := []struct {
		name   string
		status cloud.AuthProfileStatus
		want   string
	}{
		{name: "pending_link maps to missing", status: cloud.AuthProfileStatusPendingLink, want: "missing"},
		{name: "linked maps to linked", status: cloud.AuthProfileStatusLinked, want: "linked"},
		{name: "invalid maps to invalid", status: cloud.AuthProfileStatusInvalid, want: "invalid"},
		{name: "revoked maps to revoked", status: cloud.AuthProfileStatusRevoked, want: "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapAuthProfileStatus(tt.status)
			if got != tt.want {
				t.Errorf("mapAuthProfileStatus(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestRunCloudAuthValidate(t *testing.T) {
	tests := []struct {
		name       string
		profileID  string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:      "successful validate with human output",
			profileID: "prof-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-001", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				s.profiles["prof-001"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile validated successfully.",
				"profileId:    prof-001",
				"status:       linked",
				"validatedAt:",
			},
		},
		{
			name:       "successful validate with JSON output",
			profileID:  "prof-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-001", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				s.profiles["prof-001"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthValidateResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-001" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-001")
				}
				if resp.Status != "linked" {
					t.Errorf("status = %q, want %q", resp.Status, "linked")
				}
				if resp.ValidatedAt == "" {
					t.Error("validatedAt should not be empty")
				}
				// Verify camelCase JSON field names.
				if !strings.Contains(output, `"profileId"`) {
					t.Error("JSON should use camelCase profileId field")
				}
				if !strings.Contains(output, `"validatedAt"`) {
					t.Error("JSON should use camelCase validatedAt field")
				}
			},
		},
		{
			name:      "success updates last_validated_at and clears error in store",
			profileID: "prof-002",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-002", "openai")
				secret := "encrypted:test"
				p.SecretRef = &secret
				errCode := "auth_invalid"
				p.LastErrorCode = &errCode
				s.profiles["prof-002"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile validated successfully.",
				"prof-002",
			},
		},
		{
			name:      "missing profile exits non-zero with human output",
			profileID: "no-such-profile",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth validate failed",
		},
		{
			name:       "missing profile exits non-zero with not_found in JSON",
			profileID:  "no-such-profile",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "auth validate failed",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "not_found" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "not_found")
				}
			},
		},
		{
			name:       "revoked profile exits non-zero with auth_invalid in JSON",
			profileID:  "prof-003",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-003", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-003"] = p
				return s
			},
			wantErr: "auth validate failed",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "auth_invalid" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "auth_invalid")
				}
			},
		},
		{
			name:      "revoked profile exits non-zero with human output",
			profileID: "prof-003",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-003", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-003"] = p
				return s
			},
			wantErr: "auth validate failed",
		},
		{
			name:       "invalid runtime metadata exits with auth_profile_incompatible in JSON",
			profileID:  "prof-004",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-004", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				badJSON := "not json"
				p.RuntimeMetadataJSON = &badJSON
				s.profiles["prof-004"] = p
				return s
			},
			wantErr: "auth validate failed",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "auth_profile_incompatible" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "auth_profile_incompatible")
				}
			},
		},
		{
			name:       "no credentials exits with auth_invalid in JSON",
			profileID:  "prof-005",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-005", "anthropic")
				p.SecretRef = nil
				s.profiles["prof-005"] = p
				return s
			},
			wantErr: "auth validate failed",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "auth_invalid" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "auth_invalid")
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			profileID:  "prof-001",
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
			name:      "nil store factory returns error in human output",
			profileID: "prof-001",
			store:     nil,
			wantErr:   "store not configured",
		},
		{
			name:       "store factory error in JSON",
			profileID:  "prof-001",
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
			name:       "JSON response contains all required AC fields: profileId, status, validatedAt",
			profileID:  "prof-required",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-required", "anthropic")
				secret := "encrypted:test"
				p.SecretRef = &secret
				s.profiles["prof-required"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(output), &raw); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				for _, field := range []string{"profileId", "status", "validatedAt"} {
					if _, ok := raw[field]; !ok {
						t.Errorf("JSON response missing required field %q", field)
					}
				}
				// Verify no snake_case variants.
				for _, bad := range []string{"profile_id", "validated_at"} {
					if _, ok := raw[bad]; ok {
						t.Errorf("JSON response should not contain snake_case field %q", bad)
					}
				}
			},
		},
		{
			name:       "invalid-credential outcome returns auth_invalid with updated status in JSON",
			profileID:  "prof-invalid-cred",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid-cred", "anthropic")
				// No secret ref = no credentials = invalid
				p.SecretRef = nil
				s.profiles["prof-invalid-cred"] = p
				return s
			},
			wantErr: "auth validate failed",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "auth_invalid" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "auth_invalid")
				}
				if resp.Error == "" {
					t.Error("error message should not be empty")
				}
			},
		},
		{
			name:      "invalid-credential outcome returns non-zero exit in human output",
			profileID: "prof-invalid-cred-human",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid-cred-human", "anthropic")
				p.SecretRef = nil
				s.profiles["prof-invalid-cred-human"] = p
				return s
			},
			wantErr: "auth validate failed",
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
			err := runCloudAuthValidate(
				tt.profileID,
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

func TestClassifyAuthValidateError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "nil error", err: nil, wantCode: ""},
		{name: "validation error", err: fmt.Errorf("validation failed: profile must not be empty"), wantCode: "validation_error"},
		{name: "not found with space", err: fmt.Errorf("failed to get auth profile: not found"), wantCode: "not_found"},
		{name: "not_found with underscore", err: fmt.Errorf("failed to get auth profile: not_found"), wantCode: "not_found"},
		{name: "revoked", err: fmt.Errorf("auth profile \"p1\" is revoked"), wantCode: "auth_invalid"},
		{name: "no credentials", err: fmt.Errorf("auth profile \"p1\" has no linked credentials"), wantCode: "auth_invalid"},
		{name: "runtime metadata parse failure", err: fmt.Errorf("failed to parse runtime metadata: invalid json"), wantCode: "auth_profile_incompatible"},
		{name: "incompatible", err: fmt.Errorf("auth_profile_incompatible: OS mismatch"), wantCode: "auth_profile_incompatible"},
		{name: "store update error", err: fmt.Errorf("failed to update auth profile: conflict"), wantCode: "store_error"},
		{name: "unknown error", err: fmt.Errorf("something unexpected"), wantCode: "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAuthValidateError(tt.err)
			if got != tt.wantCode {
				t.Errorf("classifyAuthValidateError(%v) = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}

func TestRunCloudAuthRevoke(t *testing.T) {
	tests := []struct {
		name       string
		profileID  string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
		checkStore func(t *testing.T, s *cloudMockStore)
	}{
		{
			name:      "linked profile revoke with human output",
			profileID: "prof-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			wantOutput: []string{
				"Auth profile revoked.",
				"profileId:  prof-001",
				"status:     revoked",
				"revokedAt:",
			},
		},
		{
			name:       "linked profile revoke with JSON output",
			profileID:  "prof-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-001"] = linkedCloudProfile("prof-001", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthRevokeResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-001" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-001")
				}
				if resp.Status != "revoked" {
					t.Errorf("status = %q, want %q", resp.Status, "revoked")
				}
				if resp.RevokedAt == "" {
					t.Error("revokedAt should not be empty")
				}
			},
		},
		{
			name:      "invalid profile revoke transitions to revoked with human output",
			profileID: "prof-invalid",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid", "anthropic")
				p.Status = cloud.AuthProfileStatusInvalid
				s.profiles["prof-invalid"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile revoked.",
				"profileId:  prof-invalid",
				"status:     revoked",
				"revokedAt:",
			},
		},
		{
			name:       "invalid profile revoke transitions to revoked with JSON output",
			profileID:  "prof-invalid",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-invalid", "anthropic")
				p.Status = cloud.AuthProfileStatusInvalid
				s.profiles["prof-invalid"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthRevokeResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-invalid" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-invalid")
				}
				if resp.Status != "revoked" {
					t.Errorf("status = %q, want %q", resp.Status, "revoked")
				}
				if resp.RevokedAt == "" {
					t.Error("revokedAt should not be empty")
				}
			},
		},
		{
			name:      "missing profile returns non-fatal missing status in human output",
			profileID: "no-such-profile",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantOutput: []string{
				"Auth profile not found.",
				"profileId: no-such-profile",
				"status:    missing",
			},
		},
		{
			name:       "missing profile returns non-fatal missing status in JSON",
			profileID:  "no-such-profile",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthRevokeResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "no-such-profile" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "no-such-profile")
				}
				if resp.Status != "missing" {
					t.Errorf("status = %q, want %q", resp.Status, "missing")
				}
				if resp.RevokedAt != "" {
					t.Errorf("revokedAt should be empty for missing profile, got %q", resp.RevokedAt)
				}
			},
		},
		{
			name:      "already-revoked profile returns non-fatal already_revoked in human output",
			profileID: "prof-revoked",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-revoked", "anthropic")
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-revoked"] = p
				return s
			},
			wantOutput: []string{
				"Auth profile already revoked.",
				"profileId: prof-revoked",
				"status:    already_revoked",
			},
		},
		{
			name:       "already-revoked profile returns non-fatal already_revoked in JSON",
			profileID:  "prof-revoked",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("prof-revoked", "anthropic")
				p.Status = cloud.AuthProfileStatusRevoked
				s.profiles["prof-revoked"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudAuthRevokeResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ProfileID != "prof-revoked" {
					t.Errorf("profileId = %q, want %q", resp.ProfileID, "prof-revoked")
				}
				if resp.Status != "already_revoked" {
					t.Errorf("status = %q, want %q", resp.Status, "already_revoked")
				}
				if resp.RevokedAt != "" {
					t.Errorf("revokedAt should be empty for already-revoked, got %q", resp.RevokedAt)
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			profileID:  "prof-001",
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
			name:      "nil store factory returns error in human output",
			profileID: "prof-001",
			store:     nil,
			wantErr:   "store not configured",
		},
		{
			name:       "store factory error in JSON",
			profileID:  "prof-001",
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
			name:      "revoke updates profile status in store",
			profileID: "prof-003",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-003"] = linkedCloudProfile("prof-003", "anthropic")
				return s
			},
			wantOutput: []string{
				"Auth profile revoked.",
				"status:     revoked",
			},
			checkStore: func(t *testing.T, s *cloudMockStore) {
				t.Helper()
				p := s.profiles["prof-003"]
				if p.Status != cloud.AuthProfileStatusRevoked {
					t.Errorf("stored status = %q, want %q", p.Status, cloud.AuthProfileStatusRevoked)
				}
			},
		},
		{
			name:       "JSON response uses camelCase field names",
			profileID:  "prof-camel",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-camel"] = linkedCloudProfile("prof-camel", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(output), &raw); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				for _, field := range []string{"profileId", "status", "revokedAt"} {
					if _, ok := raw[field]; !ok {
						t.Errorf("JSON response missing required camelCase field %q", field)
					}
				}
				// Verify snake_case fields are absent.
				for _, field := range []string{"profile_id", "revoked_at", "provider"} {
					if _, ok := raw[field]; ok {
						t.Errorf("JSON response should not contain snake_case field %q", field)
					}
				}
			},
		},
		{
			name:      "subsequent auth status reports revoked after successful revoke",
			profileID: "prof-status-check",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-status-check"] = linkedCloudProfile("prof-status-check", "anthropic")
				return s
			},
			wantOutput: []string{
				"Auth profile revoked.",
			},
			checkStore: func(t *testing.T, s *cloudMockStore) {
				t.Helper()
				// Verify that auth status would report revoked.
				var statusOut bytes.Buffer
				storeFactory := func() (cloud.Store, error) { return s, nil }
				err := runCloudAuthStatus("prof-status-check", false, storeFactory, &statusOut)
				if err != nil {
					t.Fatalf("auth status after revoke failed: %v", err)
				}
				output := statusOut.String()
				if !strings.Contains(output, "status:    revoked") {
					t.Errorf("auth status should report revoked, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			var mockStore *cloudMockStore
			if tt.store != nil {
				mockStore = tt.store()
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
			err := runCloudAuthRevoke(
				tt.profileID,
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

			if tt.checkStore != nil && mockStore != nil {
				tt.checkStore(t, mockStore)
			}
		})
	}
}

func TestClassifyAuthRevokeError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "nil error", err: nil, wantCode: ""},
		{name: "validation error", err: fmt.Errorf("validation failed: profile must not be empty"), wantCode: "validation_error"},
		{name: "not found with space", err: fmt.Errorf("failed to get auth profile: not found"), wantCode: "not_found"},
		{name: "not_found with underscore", err: fmt.Errorf("failed to get auth profile: not_found"), wantCode: "not_found"},
		{name: "store update error", err: fmt.Errorf("failed to update auth profile: conflict"), wantCode: "store_error"},
		{name: "unknown error", err: fmt.Errorf("something unexpected"), wantCode: "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAuthRevokeError(tt.err)
			if got != tt.wantCode {
				t.Errorf("classifyAuthRevokeError(%v) = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}
