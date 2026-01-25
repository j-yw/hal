package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// DefaultTimeout is the default execution timeout for Claude commands.
const DefaultTimeout = 10 * time.Minute

// Result represents the outcome of a Claude execution.
type Result struct {
	Success bool   // Whether the execution succeeded
	Output  string // The result text from Claude
	Error   error  // Any error that occurred
}

// claudeResponse represents the JSON response from Claude CLI.
type claudeResponse struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
}

// Engine executes prompts using the Claude CLI.
type Engine struct {
	Timeout time.Duration
}

// NewEngine creates a new Engine with the default timeout.
func NewEngine() *Engine {
	return &Engine{
		Timeout: DefaultTimeout,
	}
}

// Execute runs a prompt through Claude and returns the result.
// It spawns a claude process with the --print flag and parses the JSON output.
func (e *Engine) Execute(prompt string) Result {
	return e.ExecuteWithContext(context.Background(), prompt)
}

// ExecuteWithContext runs a prompt through Claude with the given context.
// The context can be used to cancel the execution or set a custom deadline.
func (e *Engine) ExecuteWithContext(ctx context.Context, prompt string) Result {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return executeCommand(ctx, prompt)
}

// executeCommand runs the claude command and parses the output.
func executeCommand(ctx context.Context, prompt string) Result {
	cmd := exec.CommandContext(ctx, "claude", "-p", "--output-format", "json", prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return Result{
				Success: false,
				Output:  "",
				Error:   fmt.Errorf("execution timed out: %w", ctx.Err()),
			}
		}
		// Include stderr in error if available
		if stderr.Len() > 0 {
			return Result{
				Success: false,
				Output:  stdout.String(),
				Error:   fmt.Errorf("command failed: %w: %s", err, stderr.String()),
			}
		}
		return Result{
			Success: false,
			Output:  stdout.String(),
			Error:   fmt.Errorf("command failed: %w", err),
		}
	}

	return parseResponse(stdout.Bytes())
}

// parseResponse parses the JSON response from Claude CLI.
func parseResponse(data []byte) Result {
	var resp claudeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return Result{
			Success: false,
			Output:  string(data),
			Error:   fmt.Errorf("failed to parse response: %w", err),
		}
	}

	// Check for success based on subtype
	if resp.Subtype == "success" && !resp.IsError {
		return Result{
			Success: true,
			Output:  resp.Result,
			Error:   nil,
		}
	}

	// Handle error cases
	errMsg := resp.Subtype
	if resp.Result != "" {
		errMsg = resp.Result
	}
	return Result{
		Success: false,
		Output:  resp.Result,
		Error:   fmt.Errorf("claude execution failed: %s", errMsg),
	}
}
