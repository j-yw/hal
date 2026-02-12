package cloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// GitHubPRCreator returns a PRCreator that executes `gh pr create` inside a
// sandbox workspace. The returned function sources GITHUB_TOKEN from
// ${authDir}/credentials and escapes all user-controlled arguments with
// ShellQuote.
func GitHubPRCreator(r runner.Runner, sandboxID, authDir string) PRCreator {
	return func(ctx context.Context, req *PRCreateRequest) (string, error) {
		// Build the gh pr create command with token sourcing and escaped args.
		cmd := buildGHPRCreateCommand(req, authDir)

		result, err := r.Exec(ctx, sandboxID, &runner.ExecRequest{
			Command: cmd,
			WorkDir: "/workspace",
		})
		if err != nil {
			return "", fmt.Errorf("executing gh pr create: %w", err)
		}
		if result.ExitCode != 0 {
			return "", fmt.Errorf("gh pr create failed (exit %d): %s", result.ExitCode, result.Stderr)
		}

		prRef := parseGHPROutput(result.Stdout)
		return prRef, nil
	}
}

// buildGHPRCreateCommand constructs the shell command for creating a PR via
// the GitHub CLI. It sources GITHUB_TOKEN from the auth credentials file and
// escapes all user-controlled arguments with ShellQuote.
func buildGHPRCreateCommand(req *PRCreateRequest, authDir string) string {
	credFile := authDir + "/credentials"

	// Source the token and run gh pr create.
	parts := []string{
		fmt.Sprintf("export GITHUB_TOKEN=$(cat %s)", ShellQuote(credFile)),
		"&&",
		"gh pr create",
		"--title", ShellQuote(req.Title),
		"--head", ShellQuote(req.Head),
		"--base", ShellQuote(req.Base),
		"--repo", ShellQuote(req.Repo),
	}

	if req.Body != "" {
		parts = append(parts, "--body", ShellQuote(req.Body))
	} else {
		parts = append(parts, "--body", "''")
	}

	return strings.Join(parts, " ")
}

// parseGHPROutput extracts the PR URL from gh pr create stdout. The gh CLI
// prints the PR URL as the last non-empty line of output.
func parseGHPROutput(stdout string) string {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}
