package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
)

// mockHTTPClient implements httpDoer for testing.
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

// writeCloudYAML is a test helper that writes a cloud.yaml file.
func writeCloudYAML(t *testing.T, halDir, content string) {
	t.Helper()
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(halDir, template.CloudConfigFile), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRunCloudDoctor(t *testing.T) {
	validYAML := `defaultProfile: default
profiles:
  default:
    mode: until_complete
    endpoint: http://localhost:8080
    repo: owner/repo
    base: main
    engine: claude
    authProfile: my-profile
    scope: prd-001
    pullPolicy: all
`

	tests := []struct {
		name        string
		setup       func(t *testing.T, halDir string)
		profileFlag string
		jsonOutput  bool
		client      httpDoer
		wantErr     bool
		check       func(t *testing.T, output string)
	}{
		{
			name: "all checks pass",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, validYAML)
			},
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 200, Body: http.NoBody},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[PASS] profile_resolution") {
					t.Error("expected PASS for profile_resolution")
				}
				if !strings.Contains(output, "[PASS] endpoint_reachability") {
					t.Error("expected PASS for endpoint_reachability")
				}
				if !strings.Contains(output, "[PASS] auth_profile_validity") {
					t.Error("expected PASS for auth_profile_validity")
				}
				if !strings.Contains(output, "Result: PASS") {
					t.Error("expected overall PASS result")
				}
			},
		},
		{
			name:    "missing cloud.yaml fails config check",
			setup:   func(t *testing.T, halDir string) {},
			client:  &mockHTTPClient{},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] profile_resolution") {
					t.Error("expected FAIL for profile_resolution")
				}
				if !strings.Contains(output, "hal cloud setup") {
					t.Error("expected next-step guidance mentioning hal cloud setup")
				}
				if !strings.Contains(output, "Result: FAIL") {
					t.Error("expected overall FAIL result")
				}
			},
		},
		{
			name: "invalid cloud.yaml fails config check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: invalid_mode
`)
			},
			client:  &mockHTTPClient{},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] profile_resolution") {
					t.Error("expected FAIL for profile_resolution")
				}
			},
		},
		{
			name: "unknown profile fails config check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: until_complete
`)
			},
			profileFlag: "nonexistent",
			client:      &mockHTTPClient{},
			wantErr:     true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] profile_resolution") {
					t.Error("expected FAIL for profile_resolution")
				}
				if !strings.Contains(output, "nonexistent") {
					t.Error("expected profile name in error message")
				}
			},
		},
		{
			name: "no endpoint configured fails reachability check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: until_complete
    authProfile: my-profile
`)
			},
			client:  &mockHTTPClient{},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] endpoint_reachability") {
					t.Error("expected FAIL for endpoint_reachability")
				}
				if !strings.Contains(output, "No endpoint configured") {
					t.Error("expected 'No endpoint configured' message")
				}
			},
		},
		{
			name: "unreachable endpoint fails reachability check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    endpoint: http://unreachable.invalid:9999
    authProfile: my-profile
`)
			},
			client: &mockHTTPClient{
				err: fmt.Errorf("connection refused"),
			},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] endpoint_reachability") {
					t.Error("expected FAIL for endpoint_reachability")
				}
				if !strings.Contains(output, "not reachable") {
					t.Error("expected 'not reachable' message")
				}
				if !strings.Contains(output, "rerun hal cloud doctor") {
					t.Error("expected next-step guidance mentioning rerun")
				}
			},
		},
		{
			name: "endpoint 500 fails reachability check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    endpoint: http://localhost:8080
    authProfile: my-profile
`)
			},
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 500, Body: http.NoBody},
			},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] endpoint_reachability") {
					t.Error("expected FAIL for endpoint_reachability")
				}
				if !strings.Contains(output, "server error") {
					t.Error("expected 'server error' message")
				}
			},
		},
		{
			name: "no auth profile configured fails auth check",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: until_complete
    endpoint: http://localhost:8080
`)
			},
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 200, Body: http.NoBody},
			},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[FAIL] auth_profile_validity") {
					t.Error("expected FAIL for auth_profile_validity")
				}
				if !strings.Contains(output, "No auth profile configured") {
					t.Error("expected 'No auth profile configured' message")
				}
				if !strings.Contains(output, "hal cloud auth link") {
					t.Error("expected next-step guidance mentioning hal cloud auth link")
				}
			},
		},
		{
			name: "json output is valid JSON with all checks pass",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, validYAML)
			},
			jsonOutput: true,
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 200, Body: http.NoBody},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				var resp cloudDoctorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
				if resp.Overall != "pass" {
					t.Errorf("expected overall=pass, got %q", resp.Overall)
				}
				if len(resp.Checks) != 3 {
					t.Fatalf("expected 3 checks, got %d", len(resp.Checks))
				}
				for _, c := range resp.Checks {
					if c.Status != "pass" {
						t.Errorf("check %q: expected pass, got %q", c.Name, c.Status)
					}
				}
			},
		},
		{
			name: "json output is valid JSON with failures",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: until_complete
`)
			},
			jsonOutput: true,
			client:     &mockHTTPClient{},
			wantErr:    true,
			check: func(t *testing.T, output string) {
				var resp cloudDoctorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("invalid JSON: %v\noutput: %s", err, output)
				}
				if resp.Overall != "fail" {
					t.Errorf("expected overall=fail, got %q", resp.Overall)
				}
				// Should have failures for endpoint and auth.
				failCount := 0
				for _, c := range resp.Checks {
					if c.Status == "fail" {
						failCount++
						if c.NextStep == "" {
							t.Errorf("check %q: expected next_step for failure", c.Name)
						}
					}
				}
				if failCount == 0 {
					t.Error("expected at least one failing check")
				}
			},
		},
		{
			name: "non-zero exit code for blocking failures",
			setup: func(t *testing.T, halDir string) {
				// No cloud.yaml at all.
			},
			client:  &mockHTTPClient{},
			wantErr: true,
			check: func(t *testing.T, output string) {
				// Error returned = non-zero exit.
				if !strings.Contains(output, "FAIL") {
					t.Error("expected FAIL in output")
				}
			},
		},
		{
			name: "config next-step says rerun hal cloud setup",
			setup: func(t *testing.T, halDir string) {
				// No cloud.yaml.
			},
			client:  &mockHTTPClient{},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "hal cloud setup") {
					t.Error("expected config failure next-step to mention 'hal cloud setup'")
				}
			},
		},
		{
			name: "auth next-step says link/import credentials",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    endpoint: http://localhost:8080
`)
			},
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 200, Body: http.NoBody},
			},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "hal cloud auth link") {
					t.Error("expected auth failure next-step to mention 'hal cloud auth link'")
				}
			},
		},
		{
			name: "connectivity next-step says verify endpoint and rerun",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    endpoint: http://localhost:9999
    authProfile: my-profile
`)
			},
			client: &mockHTTPClient{
				err: fmt.Errorf("dial tcp: connection refused"),
			},
			wantErr: true,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "Verify the endpoint") {
					t.Error("expected connectivity failure next-step to mention verifying endpoint")
				}
				if !strings.Contains(output, "rerun hal cloud doctor") {
					t.Error("expected connectivity failure next-step to mention rerunning doctor")
				}
			},
		},
		{
			name: "endpoint 4xx is still a pass",
			setup: func(t *testing.T, halDir string) {
				writeCloudYAML(t, halDir, validYAML)
			},
			client: &mockHTTPClient{
				response: &http.Response{StatusCode: 401, Body: http.NoBody},
			},
			wantErr: false,
			check: func(t *testing.T, output string) {
				if !strings.Contains(output, "[PASS] endpoint_reachability") {
					t.Error("expected PASS for endpoint_reachability on 4xx (endpoint is reachable)")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			var buf bytes.Buffer
			err := runCloudDoctor(halDir, tt.profileFlag, tt.jsonOutput, tt.client, &buf)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.check != nil {
				tt.check(t, buf.String())
			}
		})
	}
}

func TestCheckProfileResolution(t *testing.T) {
	t.Run("returns resolved config on success", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		writeCloudYAML(t, halDir, `defaultProfile: default
profiles:
  default:
    mode: until_complete
    endpoint: http://example.com
    authProfile: test-auth
`)
		result, resolved, profile := checkProfileResolution(halDir, "")
		if result.Status != "pass" {
			t.Errorf("expected pass, got %q: %s", result.Status, result.Message)
		}
		if resolved == nil {
			t.Fatal("expected non-nil resolved config")
		}
		if resolved.Mode != "until_complete" {
			t.Errorf("expected mode until_complete, got %q", resolved.Mode)
		}
		if profile == nil {
			t.Fatal("expected non-nil profile")
		}
	})

	t.Run("returns nil config on missing file", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		result, resolved, _ := checkProfileResolution(halDir, "")
		if result.Status != "fail" {
			t.Errorf("expected fail, got %q", result.Status)
		}
		if resolved != nil {
			t.Error("expected nil resolved config")
		}
	})
}

func TestCheckEndpointReachability(t *testing.T) {
	t.Run("pass on 200", func(t *testing.T) {
		resolved := &config.ResolvedConfig{Endpoint: "http://example.com"}
		client := &mockHTTPClient{
			response: &http.Response{StatusCode: 200, Body: http.NoBody},
		}
		result := checkEndpointReachability(resolved, client)
		if result.Status != "pass" {
			t.Errorf("expected pass, got %q", result.Status)
		}
	})

	t.Run("fail on nil resolved", func(t *testing.T) {
		result := checkEndpointReachability(nil, &mockHTTPClient{})
		if result.Status != "fail" {
			t.Errorf("expected fail, got %q", result.Status)
		}
	})

	t.Run("fail on empty endpoint", func(t *testing.T) {
		resolved := &config.ResolvedConfig{}
		result := checkEndpointReachability(resolved, &mockHTTPClient{})
		if result.Status != "fail" {
			t.Errorf("expected fail, got %q", result.Status)
		}
	})
}

func TestCheckAuthProfileValidity(t *testing.T) {
	t.Run("pass when auth profile configured", func(t *testing.T) {
		resolved := &config.ResolvedConfig{AuthProfile: "my-auth"}
		result := checkAuthProfileValidity(resolved, nil)
		if result.Status != "pass" {
			t.Errorf("expected pass, got %q", result.Status)
		}
	})

	t.Run("fail when no auth profile", func(t *testing.T) {
		resolved := &config.ResolvedConfig{}
		result := checkAuthProfileValidity(resolved, nil)
		if result.Status != "fail" {
			t.Errorf("expected fail, got %q", result.Status)
		}
	})

	t.Run("fail on nil resolved", func(t *testing.T) {
		result := checkAuthProfileValidity(nil, nil)
		if result.Status != "fail" {
			t.Errorf("expected fail, got %q", result.Status)
		}
	})
}
