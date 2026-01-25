package claude

import (
	"context"
	"testing"
	"time"
)

func TestParseResponse_Success(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantSucc bool
		wantOut  string
		wantErr  bool
	}{
		{
			name:     "successful response",
			input:    `{"type":"result","subtype":"success","is_error":false,"result":"Task completed successfully"}`,
			wantSucc: true,
			wantOut:  "Task completed successfully",
			wantErr:  false,
		},
		{
			name:     "error subtype",
			input:    `{"type":"result","subtype":"error_max_budget_usd","is_error":false,"result":""}`,
			wantSucc: false,
			wantOut:  "",
			wantErr:  true,
		},
		{
			name:     "is_error true",
			input:    `{"type":"result","subtype":"success","is_error":true,"result":"Something went wrong"}`,
			wantSucc: false,
			wantOut:  "Something went wrong",
			wantErr:  true,
		},
		{
			name:     "error with result message",
			input:    `{"type":"result","subtype":"error_api","is_error":true,"result":"API rate limit exceeded"}`,
			wantSucc: false,
			wantOut:  "API rate limit exceeded",
			wantErr:  true,
		},
		{
			name:     "invalid json",
			input:    `not valid json`,
			wantSucc: false,
			wantOut:  "not valid json",
			wantErr:  true,
		},
		{
			name:     "empty response",
			input:    `{}`,
			wantSucc: false,
			wantOut:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseResponse([]byte(tt.input))

			if result.Success != tt.wantSucc {
				t.Errorf("Success = %v, want %v", result.Success, tt.wantSucc)
			}
			if result.Output != tt.wantOut {
				t.Errorf("Output = %q, want %q", result.Output, tt.wantOut)
			}
			if (result.Error != nil) != tt.wantErr {
				t.Errorf("Error = %v, wantErr %v", result.Error, tt.wantErr)
			}
		})
	}
}

func TestNewEngine(t *testing.T) {
	engine := NewEngine()

	if engine.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", engine.Timeout, DefaultTimeout)
	}
}

func TestDefaultTimeout(t *testing.T) {
	if DefaultTimeout != 10*time.Minute {
		t.Errorf("DefaultTimeout = %v, want %v", DefaultTimeout, 10*time.Minute)
	}
}

func TestEngine_ExecuteWithContext_Timeout(t *testing.T) {
	// Create a context that's already canceled to test timeout handling
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := &Engine{Timeout: 1 * time.Millisecond}

	// This should fail due to context cancellation, not actually run claude
	result := engine.ExecuteWithContext(ctx, "test prompt")

	// The result should indicate failure (either due to canceled context or command failure)
	if result.Success {
		t.Error("Expected failure for canceled context")
	}
	if result.Error == nil {
		t.Error("Expected error for canceled context")
	}
}

func TestResult_Fields(t *testing.T) {
	// Test that Result struct has the expected fields
	r := Result{
		Success: true,
		Output:  "test output",
		Error:   nil,
	}

	if !r.Success {
		t.Error("Success field not set correctly")
	}
	if r.Output != "test output" {
		t.Error("Output field not set correctly")
	}
	if r.Error != nil {
		t.Error("Error field not set correctly")
	}
}
