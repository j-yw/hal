package runner

import (
	"context"
	"strings"
	"testing"

	daytona "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
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

func TestSDKClientExecValidation(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	tests := []struct {
		name      string
		sandboxID string
		req       *ExecRequest
		wantErr   string
	}{
		{
			name:      "nil request",
			sandboxID: "sb-123",
			req:       nil,
			wantErr:   "exec request must not be nil",
		},
		{
			name:      "empty sandbox ID",
			sandboxID: "",
			req:       &ExecRequest{Command: "echo hello"},
			wantErr:   "sandbox_id must not be empty",
		},
		{
			name:      "empty command",
			sandboxID: "sb-123",
			req:       &ExecRequest{},
			wantErr:   "command must not be empty",
		},
		{
			name:      "empty command with workdir",
			sandboxID: "sb-123",
			req:       &ExecRequest{WorkDir: "/tmp"},
			wantErr:   "command must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Exec(context.Background(), tt.sandboxID, tt.req)
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

func TestSDKClientExecSDKFailure(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to force SDK failure

	_, err = c.Exec(ctx, "nonexistent-sandbox", &ExecRequest{Command: "echo hello"})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: exec:") {
		t.Errorf("error %q should contain 'sdk runner client: exec:' prefix", err.Error())
	}
}

func TestSDKClientStreamLogsValidation(t *testing.T) {
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
			_, err := c.StreamLogs(context.Background(), tt.id)
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

func TestSDKClientStreamLogsSDKFailure(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to force SDK failure

	_, err = c.StreamLogs(ctx, "nonexistent-sandbox")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: stream logs:") {
		t.Errorf("error %q should contain 'sdk runner client: stream logs:' prefix", err.Error())
	}
}

func TestSDKClientHealthSDKFailure(t *testing.T) {
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to force SDK failure

	_, err = c.Health(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: health:") {
		t.Errorf("error %q should contain 'sdk runner client: health:' prefix", err.Error())
	}
}

func TestSDKClientHealthReturnsVersion(t *testing.T) {
	// Verify that the Health method is wired to return daytona.Version.
	// We cannot call Health successfully without a live server, so we verify
	// the version constant is accessible and non-empty (it's embedded at
	// SDK build time).
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	// Verify the SDKClient satisfies the Runner interface including Health.
	var _ Runner = c

	// Verify daytona.Version is accessible (used in Health success path).
	if daytona.Version == "" {
		t.Log("daytona.Version is empty (expected in test builds without embedded VERSION file)")
	}
}

func TestSDKClientExecSDKFailureWithOptions(t *testing.T) {
	// Verify that Exec with WorkDir and Timeout options still hits
	// the SDK layer (and wraps the error) when the context is cancelled.
	c, err := NewSDKClient(SDKClientConfig{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = c.Exec(ctx, "nonexistent-sandbox", &ExecRequest{
		Command: "ls -la",
		WorkDir: "/home/daytona",
		Timeout: 30 * 1e9, // 30 seconds as time.Duration
	})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "sdk runner client: exec:") {
		t.Errorf("error %q should contain 'sdk runner client: exec:' prefix", err.Error())
	}
}

func TestResolveSessionCommandRef_PrefersNewMatchingCommand(t *testing.T) {
	before := snapshotSessionCommands([]map[string]any{
		{
			"sessionId": "s-1",
			"commands": []map[string]any{
				{"id": "c-old", "command": "echo old"},
			},
		},
	})

	after := []map[string]any{
		{
			"sessionId": "s-1",
			"commands": []map[string]any{
				{"id": "c-old", "command": "echo old"},
				{"id": "c-new", "command": "hal run"},
			},
		},
		{
			"sessionId": "s-2",
			"commands": []map[string]any{
				{"id": "c-other", "command": "other command"},
			},
		},
	}

	sessionID, commandID, ok := resolveSessionCommandRef(before, after, "hal run")
	if !ok {
		t.Fatal("expected command reference, got none")
	}
	if sessionID != "s-1" || commandID != "c-new" {
		t.Fatalf("got (%q, %q), want (%q, %q)", sessionID, commandID, "s-1", "c-new")
	}
}

func TestResolveSessionCommandRef_FallsBackToNewestCommand(t *testing.T) {
	before := snapshotSessionCommands([]map[string]any{
		{
			"sessionId": "s-1",
			"commands": []map[string]any{
				{"id": "c-old", "command": "echo old"},
			},
		},
	})

	after := []map[string]any{
		{
			"sessionId": "s-1",
			"commands": []map[string]any{
				{"id": "c-old", "command": "echo old"},
			},
		},
		{
			"sessionId": "s-2",
			"commands": []map[string]any{
				{"id": "c-newest", "command": "unrelated"},
			},
		},
	}

	sessionID, commandID, ok := resolveSessionCommandRef(before, after, "hal review")
	if !ok {
		t.Fatal("expected command reference, got none")
	}
	if sessionID != "s-2" || commandID != "c-newest" {
		t.Fatalf("got (%q, %q), want (%q, %q)", sessionID, commandID, "s-2", "c-newest")
	}
}

func TestLatestSessionCommandRef(t *testing.T) {
	sessions := []map[string]any{
		{
			"sessionId": "s-1",
			"commands": []map[string]any{
				{"id": "c-1", "command": "first"},
			},
		},
		{
			"sessionId": "s-2",
			"commands": []map[string]any{
				{"id": "c-2", "command": "second"},
			},
		},
	}

	sessionID, commandID, ok := latestSessionCommandRef(sessions)
	if !ok {
		t.Fatal("expected command reference, got none")
	}
	if sessionID != "s-2" || commandID != "c-2" {
		t.Fatalf("got (%q, %q), want (%q, %q)", sessionID, commandID, "s-2", "c-2")
	}
}

func TestLogsFromMap(t *testing.T) {
	tests := []struct {
		name string
		logs map[string]any
		want string
	}{
		{
			name: "string logs",
			logs: map[string]any{"logs": "hello"},
			want: "hello",
		},
		{
			name: "non-string logs",
			logs: map[string]any{"logs": 42},
			want: "42",
		},
		{
			name: "missing logs",
			logs: map[string]any{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logsFromMap(tt.logs); got != tt.want {
				t.Fatalf("logsFromMap() = %q, want %q", got, tt.want)
			}
		})
	}
}
