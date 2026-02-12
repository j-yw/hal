package cloud

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// SandboxBundleRecord holds a collected file's path and raw content bytes.
type SandboxBundleRecord struct {
	// Path is the workspace-relative path (e.g., ".hal/prd.json").
	Path string
	// Content is the raw file content.
	Content []byte
}

// CollectSandboxBundle lists files under /workspace/.hal inside the sandbox,
// filters them by workflow artifact patterns, and reads each matching file's
// content via base64-encoded exec calls. It returns bundle records with
// workspace-relative paths.
func CollectSandboxBundle(ctx context.Context, r runner.Runner, sandboxID string, workflowKind WorkflowKind) ([]SandboxBundleRecord, error) {
	patterns := WorkflowDefaultArtifactPatterns(workflowKind)
	if len(patterns) == 0 {
		return nil, fmt.Errorf("no artifact patterns for workflow kind %q", workflowKind)
	}

	// List all files under /workspace/.hal using find.
	listResult, err := r.Exec(ctx, sandboxID, &runner.ExecRequest{
		Command: "find /workspace/.hal -type f 2>/dev/null",
		WorkDir: "/workspace",
	})
	if err != nil {
		return nil, fmt.Errorf("listing sandbox .hal files: %w", err)
	}

	// find returns exit code 0 on success; non-zero may indicate the directory
	// does not exist which we treat as an empty workspace.
	if listResult.ExitCode != 0 {
		return nil, nil
	}

	stdout := strings.TrimSpace(listResult.Stdout)
	if stdout == "" {
		return nil, nil
	}

	lines := strings.Split(stdout, "\n")

	// Filter paths by workflow artifact patterns.
	var matchedPaths []string
	for _, line := range lines {
		absPath := strings.TrimSpace(line)
		if absPath == "" {
			continue
		}

		// Convert absolute sandbox path to workspace-relative (e.g., ".hal/prd.json").
		relPath := strings.TrimPrefix(absPath, "/workspace/")
		if relPath == absPath {
			// Path is not under /workspace — skip.
			continue
		}

		if MatchesArtifactPatterns(relPath, patterns) {
			matchedPaths = append(matchedPaths, relPath)
		}
	}

	if len(matchedPaths) == 0 {
		return nil, nil
	}

	// Read each matching file's content via base64-encoded exec.
	var records []SandboxBundleRecord
	for _, relPath := range matchedPaths {
		record, err := readSandboxFile(ctx, r, sandboxID, relPath)
		if err != nil {
			return nil, err
		}
		records = append(records, *record)
	}

	return records, nil
}

// readSandboxFile reads a single file from the sandbox using base64 encoding
// to safely capture binary and multiline content.
func readSandboxFile(ctx context.Context, r runner.Runner, sandboxID, relPath string) (*SandboxBundleRecord, error) {
	// Use base64 -w0 to produce non-wrapped output suitable for decode.
	absPath := "/workspace/" + relPath
	cmd := fmt.Sprintf("base64 -w0 %s", ShellQuote(absPath))
	result, err := r.Exec(ctx, sandboxID, &runner.ExecRequest{
		Command: cmd,
		WorkDir: "/workspace",
	})
	if err != nil {
		return nil, fmt.Errorf("reading sandbox file %s: %w", relPath, err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("base64 encode failed for %s (exit %d): %s", relPath, result.ExitCode, result.Stderr)
	}

	encoded := strings.TrimSpace(result.Stdout)
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed for %s: %w (stderr: %s)", relPath, err, result.Stderr)
	}

	return &SandboxBundleRecord{
		Path:    relPath,
		Content: content,
	}, nil
}
