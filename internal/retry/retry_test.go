package retry

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		// Retryable errors
		{
			name:     "rate limit error",
			err:      errors.New("API rate limit exceeded"),
			expected: true,
		},
		{
			name:     "rate_limit subtype",
			err:      errors.New("error_rate_limit: too many requests"),
			expected: true,
		},
		{
			name:     "timeout error",
			err:      errors.New("execution timed out"),
			expected: true,
		},
		{
			name:     "deadline exceeded",
			err:      errors.New("context deadline exceeded"),
			expected: true,
		},
		{
			name:     "network error",
			err:      errors.New("network connection failed"),
			expected: true,
		},
		{
			name:     "connection refused",
			err:      errors.New("dial tcp: connection refused"),
			expected: true,
		},
		{
			name:     "connection reset",
			err:      errors.New("connection reset by peer"),
			expected: true,
		},
		{
			name:     "service unavailable 503",
			err:      errors.New("server returned 503"),
			expected: true,
		},
		{
			name:     "too many requests 429",
			err:      errors.New("HTTP 429 Too Many Requests"),
			expected: true,
		},
		{
			name:     "overloaded",
			err:      errors.New("server overloaded, try again later"),
			expected: true,
		},

		// Non-retryable errors
		{
			name:     "syntax error",
			err:      errors.New("syntax error in prompt"),
			expected: false,
		},
		{
			name:     "invalid config",
			err:      errors.New("invalid configuration"),
			expected: false,
		},
		{
			name:     "not found",
			err:      errors.New("file not found"),
			expected: false,
		},
		{
			name:     "unauthorized",
			err:      errors.New("unauthorized: invalid API key"),
			expected: false,
		},
		{
			name:     "forbidden",
			err:      errors.New("forbidden: access denied"),
			expected: false,
		},
		{
			name:     "authentication failure",
			err:      errors.New("authentication failed"),
			expected: false,
		},
		{
			name:     "permission denied",
			err:      errors.New("permission denied for operation"),
			expected: false,
		},
		{
			name:     "bad request 400",
			err:      errors.New("HTTP 400 Bad Request"),
			expected: false,
		},
		{
			name:     "unauthorized 401",
			err:      errors.New("HTTP 401"),
			expected: false,
		},
		{
			name:     "forbidden 403",
			err:      errors.New("HTTP 403"),
			expected: false,
		},
		{
			name:     "not found 404",
			err:      errors.New("HTTP 404"),
			expected: false,
		},

		// Edge cases
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "unknown error",
			err:      errors.New("something went wrong"),
			expected: false, // Conservative: don't retry unknown errors
		},
		{
			name:     "case insensitive rate limit",
			err:      errors.New("RATE LIMIT hit"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestCalculateDelay(t *testing.T) {
	tests := []struct {
		name             string
		base             time.Duration
		attempt          int
		maxJitterPercent int
		expectedMin      time.Duration
		expectedMax      time.Duration
	}{
		{
			name:             "first attempt (5s base)",
			base:             5 * time.Second,
			attempt:          0,
			maxJitterPercent: 0, // No jitter for predictable test
			expectedMin:      5 * time.Second,
			expectedMax:      5 * time.Second,
		},
		{
			name:             "second attempt (5s base, 2^1 = 10s)",
			base:             5 * time.Second,
			attempt:          1,
			maxJitterPercent: 0,
			expectedMin:      10 * time.Second,
			expectedMax:      10 * time.Second,
		},
		{
			name:             "third attempt (5s base, 2^2 = 20s)",
			base:             5 * time.Second,
			attempt:          2,
			maxJitterPercent: 0,
			expectedMin:      20 * time.Second,
			expectedMax:      20 * time.Second,
		},
		{
			name:             "with 25% jitter",
			base:             5 * time.Second,
			attempt:          0,
			maxJitterPercent: 25,
			expectedMin:      5 * time.Second,              // base with no jitter
			expectedMax:      5*time.Second + 1250*time.Millisecond, // base + 25%
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := CalculateDelay(tt.base, tt.attempt, tt.maxJitterPercent)

			if delay < tt.expectedMin || delay > tt.expectedMax {
				t.Errorf("CalculateDelay(%v, %d, %d) = %v, want between %v and %v",
					tt.base, tt.attempt, tt.maxJitterPercent, delay, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestCalculateDelay_JitterRange(t *testing.T) {
	// Run multiple times to verify jitter is within bounds
	base := 10 * time.Second
	maxJitter := 25

	for i := 0; i < 100; i++ {
		delay := CalculateDelay(base, 0, maxJitter)

		minExpected := base
		maxExpected := base + time.Duration(float64(base)*float64(maxJitter)/100.0)

		if delay < minExpected || delay > maxExpected {
			t.Errorf("Iteration %d: delay %v outside range [%v, %v]",
				i, delay, minExpected, maxExpected)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, DefaultMaxRetries)
	}
	if cfg.BaseDelay != DefaultBaseDelay {
		t.Errorf("BaseDelay = %v, want %v", cfg.BaseDelay, DefaultBaseDelay)
	}
	if cfg.MaxJitterPercent != DefaultMaxJitterPercent {
		t.Errorf("MaxJitterPercent = %d, want %d", cfg.MaxJitterPercent, DefaultMaxJitterPercent)
	}
	if cfg.Logger != nil {
		t.Error("Logger should be nil by default")
	}
}

func TestExecute_SuccessOnFirstAttempt(t *testing.T) {
	attempts := 0
	op := func() Result {
		attempts++
		return Result{Success: true, Output: "done"}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
	}

	result := Execute(context.Background(), cfg, op)

	if !result.Success {
		t.Error("Expected success")
	}
	if result.Output != "done" {
		t.Errorf("Output = %q, want %q", result.Output, "done")
	}
	if attempts != 1 {
		t.Errorf("Attempts = %d, want 1", attempts)
	}
}

func TestExecute_SuccessAfterRetries(t *testing.T) {
	attempts := 0
	op := func() Result {
		attempts++
		if attempts < 3 {
			return Result{Success: false, Error: errors.New("rate limit exceeded")}
		}
		return Result{Success: true, Output: "done after retries"}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
	}

	result := Execute(context.Background(), cfg, op)

	if !result.Success {
		t.Errorf("Expected success, got error: %v", result.Error)
	}
	if attempts != 3 {
		t.Errorf("Attempts = %d, want 3", attempts)
	}
}

func TestExecute_NonRetryableError(t *testing.T) {
	attempts := 0
	op := func() Result {
		attempts++
		return Result{Success: false, Error: errors.New("syntax error in prompt")}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
	}

	result := Execute(context.Background(), cfg, op)

	if result.Success {
		t.Error("Expected failure")
	}
	if attempts != 1 {
		t.Errorf("Attempts = %d, want 1 (no retries for non-retryable)", attempts)
	}
}

func TestExecute_ExhaustedRetries(t *testing.T) {
	attempts := 0
	op := func() Result {
		attempts++
		return Result{Success: false, Error: errors.New("rate limit exceeded")}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
	}

	result := Execute(context.Background(), cfg, op)

	if result.Success {
		t.Error("Expected failure after exhausted retries")
	}
	// Initial attempt + 3 retries = 4 total
	if attempts != 4 {
		t.Errorf("Attempts = %d, want 4 (initial + 3 retries)", attempts)
	}
}

func TestExecute_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	op := func() Result {
		attempts++
		if attempts == 1 {
			cancel() // Cancel after first attempt
		}
		return Result{Success: false, Error: errors.New("rate limit exceeded")}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
	}

	result := Execute(ctx, cfg, op)

	if result.Success {
		t.Error("Expected failure due to context cancellation")
	}
	if !errors.Is(result.Error, context.Canceled) {
		t.Errorf("Error = %v, want context.Canceled", result.Error)
	}
}

func TestExecute_Logging(t *testing.T) {
	var logBuf bytes.Buffer
	attempts := 0
	op := func() Result {
		attempts++
		if attempts < 2 {
			return Result{Success: false, Error: errors.New("rate limit exceeded")}
		}
		return Result{Success: true, Output: "done"}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
		Logger:     &logBuf,
	}

	result := Execute(context.Background(), cfg, op)

	if !result.Success {
		t.Error("Expected success")
	}

	log := logBuf.String()
	if !strings.Contains(log, "Retrying") {
		t.Errorf("Log should contain 'Retrying', got: %q", log)
	}
	if !strings.Contains(log, "attempt 1/3") {
		t.Errorf("Log should contain 'attempt 1/3', got: %q", log)
	}
}

func TestExecute_LogsNonRetryable(t *testing.T) {
	var logBuf bytes.Buffer
	op := func() Result {
		return Result{Success: false, Error: errors.New("syntax error")}
	}

	cfg := Config{
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
		Logger:     &logBuf,
	}

	Execute(context.Background(), cfg, op)

	log := logBuf.String()
	if !strings.Contains(log, "Non-retryable error") {
		t.Errorf("Log should contain 'Non-retryable error', got: %q", log)
	}
}

func TestExecute_DefaultValues(t *testing.T) {
	// Test that Execute handles zero/negative config values gracefully
	attempts := 0
	op := func() Result {
		attempts++
		return Result{Success: true, Output: "done"}
	}

	cfg := Config{
		MaxRetries:       0, // Should use default
		BaseDelay:        0, // Should use default
		MaxJitterPercent: -1, // Should use default
	}

	result := Execute(context.Background(), cfg, op)

	if !result.Success {
		t.Error("Expected success")
	}
}

func TestConstants(t *testing.T) {
	if DefaultMaxRetries != 3 {
		t.Errorf("DefaultMaxRetries = %d, want 3", DefaultMaxRetries)
	}
	if DefaultBaseDelay != 5*time.Second {
		t.Errorf("DefaultBaseDelay = %v, want 5s", DefaultBaseDelay)
	}
	if DefaultMaxJitterPercent != 25 {
		t.Errorf("DefaultMaxJitterPercent = %d, want 25", DefaultMaxJitterPercent)
	}
}
