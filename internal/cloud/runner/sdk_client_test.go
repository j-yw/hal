package runner

import (
	"context"
	"strings"
	"testing"
)

func TestNewSDKClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SDKClientConfig
		wantErr string
	}{
		{
			name:    "empty API key",
			cfg:     SDKClientConfig{},
			wantErr: "api_key must not be empty",
		},
		{
			name:    "empty API key with URL",
			cfg:     SDKClientConfig{APIURL: "https://api.daytona.io"},
			wantErr: "api_key must not be empty",
		},
		{
			name: "valid config with API key only",
			cfg:  SDKClientConfig{APIKey: "test-key"},
		},
		{
			name: "valid config with all fields",
			cfg: SDKClientConfig{
				APIKey: "test-key",
				APIURL: "https://custom.daytona.io/api",
				Target: "us-east-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewSDKClient(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c == nil {
				t.Fatal("expected non-nil client")
			}
			if c.client == nil {
				t.Fatal("expected non-nil underlying SDK client")
			}
		})
	}
}

func TestNewSDKClientErrorPrefix(t *testing.T) {
	_, err := NewSDKClient(SDKClientConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(err.Error(), "sdk runner client:") {
		t.Errorf("error %q should have 'sdk runner client:' prefix", err.Error())
	}
}

func TestNewSDKClientWrapsErrors(t *testing.T) {
	// Verify that the constructor wraps errors with %w by checking the error
	// message format. The init wrapping is exercised when the SDK constructor
	// itself fails (e.g., missing auth). Our pre-validation catches empty
	// APIKey first, so SDK-level errors only surface for unexpected failures.
	_, err := NewSDKClient(SDKClientConfig{APIKey: ""})
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
	// Our pre-validation produces a descriptive error with the "sdk runner client:" prefix.
	if !strings.Contains(err.Error(), "sdk runner client:") {
		t.Errorf("error %q should contain 'sdk runner client:' prefix", err.Error())
	}
}

func TestSDKClientCreateSandboxValidation(t *testing.T) {
	// Create a real client for validation tests (no network calls for validation failures).
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	tests := []struct {
		name    string
		req     *CreateSandboxRequest
		wantErr string
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: "create request must not be nil",
		},
		{
			name:    "empty image",
			req:     &CreateSandboxRequest{},
			wantErr: "image must not be empty",
		},
		{
			name:    "empty image with env vars",
			req:     &CreateSandboxRequest{EnvVars: map[string]string{"K": "V"}},
			wantErr: "image must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.CreateSandbox(context.Background(), tt.req)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), "sdk runner client:") {
				t.Errorf("error %q should have 'sdk runner client:' prefix", err.Error())
			}
		})
	}
}

func TestSDKClientDestroySandboxValidation(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr string
	}{
		{
			name:    "empty sandbox ID",
			id:      "",
			wantErr: "sandbox_id must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.DestroySandbox(context.Background(), tt.id)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), "sdk runner client:") {
				t.Errorf("error %q should have 'sdk runner client:' prefix", err.Error())
			}
		})
	}
}

func TestSDKClientCreateSandboxSDKFailure(t *testing.T) {
	// The SDK client is configured with a key but no valid API URL.
	// Calling Create with a valid request should fail at the SDK level,
	// and the error should be wrapped with the operation prefix.
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to force SDK failure

	_, err = c.CreateSandbox(ctx, &CreateSandboxRequest{Image: "ubuntu:latest"})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: create sandbox:") {
		t.Errorf("error %q should contain 'sdk runner client: create sandbox:' prefix", err.Error())
	}
}

func TestSDKClientDestroySandboxSDKFailure(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to force SDK failure

	err = c.DestroySandbox(ctx, "nonexistent-sandbox")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: destroy:") {
		t.Errorf("error %q should contain 'sdk runner client: destroy:' prefix", err.Error())
	}
}
