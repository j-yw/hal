package retry

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"
)

const (
	// DefaultMaxRetries is the default number of retry attempts.
	DefaultMaxRetries = 3
	// DefaultBaseDelay is the base delay for exponential backoff.
	DefaultBaseDelay = 5 * time.Second
	// DefaultMaxJitterPercent is the maximum jitter percentage (0-25%).
	DefaultMaxJitterPercent = 25
)

// Config holds retry configuration.
type Config struct {
	MaxRetries       int
	BaseDelay        time.Duration
	MaxJitterPercent int
	Logger           io.Writer                           // Where to write retry logs (nil for no logging)
	OnRetry          func(delaySeconds, attempt, max int) // Optional callback for retry notifications
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		MaxRetries:       DefaultMaxRetries,
		BaseDelay:        DefaultBaseDelay,
		MaxJitterPercent: DefaultMaxJitterPercent,
		Logger:           nil,
	}
}

// Result represents the outcome of an operation that can be retried.
type Result struct {
	Success bool
	Output  string
	Error   error
}

// Operation is a function that can be retried.
type Operation func() Result

// Execute runs an operation with retry logic.
// It retries on retryable errors with exponential backoff and jitter.
// Returns the final result after all attempts.
func Execute(ctx context.Context, cfg Config, op Operation) Result {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = DefaultBaseDelay
	}
	if cfg.MaxJitterPercent < 0 || cfg.MaxJitterPercent > 100 {
		cfg.MaxJitterPercent = DefaultMaxJitterPercent
	}

	var lastResult Result

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		lastResult = op()

		// Success - return immediately
		if lastResult.Success {
			return lastResult
		}

		// Check if the error is retryable
		if !IsRetryable(lastResult.Error) {
			if cfg.Logger != nil {
				fmt.Fprintf(cfg.Logger, "Non-retryable error, stopping: %v\n", lastResult.Error)
			}
			return lastResult
		}

		// Check if we've exhausted retries
		if attempt >= cfg.MaxRetries {
			if cfg.Logger != nil {
				fmt.Fprintf(cfg.Logger, "All %d retry attempts exhausted\n", cfg.MaxRetries)
			}
			return lastResult
		}

		// Calculate delay with exponential backoff and jitter
		delay := CalculateDelay(cfg.BaseDelay, attempt, cfg.MaxJitterPercent)
		delaySecs := int(delay.Seconds())
		if delaySecs < 1 {
			delaySecs = 1
		}

		// Use OnRetry callback if provided, otherwise use Logger
		if cfg.OnRetry != nil {
			cfg.OnRetry(delaySecs, attempt+1, cfg.MaxRetries)
		} else if cfg.Logger != nil {
			fmt.Fprintf(cfg.Logger, "Retrying in %ds... (attempt %d/%d)\n",
				delaySecs, attempt+1, cfg.MaxRetries)
		}

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return Result{
				Success: false,
				Output:  lastResult.Output,
				Error:   ctx.Err(),
			}
		case <-time.After(delay):
			// Continue to next retry
		}
	}

	return lastResult
}

// CalculateDelay returns the delay for a given attempt using exponential backoff with jitter.
// Formula: base * 2^attempt + jitter (0-maxJitterPercent% of calculated delay)
func CalculateDelay(base time.Duration, attempt int, maxJitterPercent int) time.Duration {
	// Calculate exponential backoff: base * 2^attempt
	multiplier := 1 << attempt // 2^attempt (1, 2, 4, 8, ...)
	delay := base * time.Duration(multiplier)

	// Add jitter (0-maxJitterPercent% of delay)
	if maxJitterPercent > 0 {
		jitterRange := float64(delay) * float64(maxJitterPercent) / 100.0
		jitter := time.Duration(rand.Float64() * jitterRange)
		delay += jitter
	}

	return delay
}

// retryablePatterns contains error message patterns that indicate retryable errors.
var retryablePatterns = []string{
	"rate limit",
	"rate_limit",
	"timeout",
	"timed out",
	"deadline exceeded",
	"network",
	"connection refused",
	"connection reset",
	"temporary failure",
	"service unavailable",
	"503",
	"502",
	"429",
	"overloaded",
	"too many requests",
}

// nonRetryablePatterns contains error message patterns that indicate non-retryable errors.
var nonRetryablePatterns = []string{
	"syntax error",
	"invalid",
	"not found",
	"unauthorized",
	"forbidden",
	"authentication",
	"permission denied",
	"bad request",
	"400",
	"401",
	"403",
	"404",
}

// IsRetryable determines if an error is retryable.
// Rate limit, timeout, and network errors are retryable.
// Syntax errors, invalid config, and auth errors are not.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// First check if it's explicitly non-retryable
	for _, pattern := range nonRetryablePatterns {
		if strings.Contains(errStr, pattern) {
			return false
		}
	}

	// Then check if it matches a retryable pattern
	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Default: don't retry unknown errors (conservative approach)
	return false
}
