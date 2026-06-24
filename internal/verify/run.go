package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/jywlabs/hal/internal/template"
)

type runDeps struct {
	now            func() time.Time
	commandContext func(context.Context, string, ...string) *exec.Cmd
}

// Run executes configured verification checks and returns a verify-v1 result.
func Run(ctx context.Context, cfg *Config) (*Result, error) {
	if cfg == nil {
		defaultConfig := DefaultConfig()
		cfg = &defaultConfig
	}

	return runWithDeps(ctx, *cfg, runDeps{
		now:            time.Now,
		commandContext: exec.CommandContext,
	})
}

func runWithDeps(ctx context.Context, cfg Config, deps runDeps) (*Result, error) {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.commandContext == nil {
		deps.commandContext = exec.CommandContext
	}

	result := &Result{
		SchemaVersion: SchemaVersion,
		Status:        StatusPass,
		Checks:        make([]CheckResult, 0, len(cfg.Checks)),
		Warnings:      []Warning{},
		Artifacts:     []ArtifactReference{},
	}
	artifactRun := newArtifactRun(resolveProjectRoot(cfg), deps.now())
	artifactIDs := make(map[string]struct{}, len(cfg.Checks))

	for i, check := range cfg.Checks {
		artifactID := uniqueArtifactID(check.ID, i, artifactIDs)
		checkResult, artifacts, err := runShellCheck(ctx, check, deps, artifactRun, artifactID)
		if err != nil {
			return nil, err
		}
		result.Checks = append(result.Checks, checkResult)
		result.Artifacts = append(result.Artifacts, artifacts...)
		applyCheckSummary(result, checkResult)
		if warning, ok := warningForCheck(checkResult); ok {
			result.Warnings = append(result.Warnings, warning)
		}
	}

	result.Summary.Total = len(result.Checks)
	result.Summary.Warnings = len(result.Warnings)
	result.Status = statusForResult(result)
	result.GeneratedAt = deps.now()
	return result, nil
}

func runShellCheck(ctx context.Context, check ShellCheck, deps runDeps, artifacts *artifactRun, artifactID string) (CheckResult, []ArtifactReference, error) {
	startedAt := deps.now()
	result := baseCheckResult(check, startedAt)
	if missingMessage, ok := missingShellCheckMessage(check); ok {
		finishedAt := deps.now()
		result.Status = CheckStatusMissing
		result.FinishedAt = finishedAt
		result.DurationMs = finishedAt.Sub(startedAt).Milliseconds()
		result.ExitCode = -1
		result.Message = missingMessage
		return result, nil, nil
	}

	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shell, args := shellCommand(check.Command)
	cmd := deps.commandContext(checkCtx, shell, args...)
	cmd.Dir = check.WorkDir
	cmd.SysProcAttr = newSysProcAttr()
	setupProcessCleanup(cmd)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	finishedAt := deps.now()

	result.FinishedAt = finishedAt
	result.DurationMs = finishedAt.Sub(startedAt).Milliseconds()

	if err != nil {
		if errors.Is(checkCtx.Err(), context.Canceled) {
			return CheckResult{}, nil, checkCtx.Err()
		}
		result.Status = CheckStatusFail
		result.ExitCode = exitCode(err)
		result.Message = fmt.Sprintf("check failed: %v", err)
		if errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
			result.Status = CheckStatusTimeout
			result.Message = fmt.Sprintf("check timed out after %d seconds", check.TimeoutSeconds)
		} else if isMissingCommandFailure(result.ExitCode, stderr.String()) {
			result.Status = CheckStatusMissing
			result.Message = "check command is unavailable"
		}
	}

	checkArtifacts, err := writeCheckArtifacts(check.ID, artifactID, stdout.Bytes(), stderr.Bytes(), artifacts)
	if err != nil {
		return CheckResult{}, nil, err
	}
	for _, artifact := range checkArtifacts {
		switch artifact.Kind {
		case ArtifactKindStdout:
			result.StdoutArtifact = artifact.Path
		case ArtifactKindStderr:
			result.StderrArtifact = artifact.Path
		}
	}

	return result, checkArtifacts, nil
}

func resolveProjectRoot(cfg Config) string {
	if strings.TrimSpace(cfg.ProjectRoot) != "" {
		return cfg.ProjectRoot
	}
	for _, check := range cfg.Checks {
		if strings.TrimSpace(check.WorkDir) != "" {
			return check.WorkDir
		}
	}
	return "."
}

func verifyArtifactsDir(projectRoot string) string {
	return filepath.Join(projectRoot, template.HalDir, "reports", "verify")
}

type artifactRun struct {
	baseDir string
	baseRel string
	runID   string
	dir     string
	relDir  string
}

func newArtifactRun(projectRoot string, startedAt time.Time) *artifactRun {
	return &artifactRun{
		baseDir: verifyArtifactsDir(projectRoot),
		baseRel: path.Join(template.HalDir, "reports", "verify"),
		runID:   artifactRunID(startedAt),
	}
}

func artifactRunID(startedAt time.Time) string {
	return startedAt.UTC().Format("20060102T150405.000000000Z")
}

func (r *artifactRun) ensureDir() (string, string, error) {
	if r.dir != "" {
		return r.dir, r.relDir, nil
	}
	if err := os.MkdirAll(r.baseDir, 0755); err != nil {
		return "", "", fmt.Errorf("create verify artifacts directory: %w", err)
	}

	for suffix := 1; ; suffix++ {
		candidate := r.runID
		if suffix > 1 {
			candidate = fmt.Sprintf("%s-%d", r.runID, suffix)
		}
		dir := filepath.Join(r.baseDir, candidate)
		if err := os.Mkdir(dir, 0755); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", "", fmt.Errorf("create verify artifacts run directory: %w", err)
		}
		r.dir = dir
		r.relDir = path.Join(r.baseRel, candidate)
		return r.dir, r.relDir, nil
	}
}

func writeCheckArtifacts(checkID string, artifactID string, stdout []byte, stderr []byte, runArtifacts *artifactRun) ([]ArtifactReference, error) {
	artifactRefs := make([]ArtifactReference, 0, 2)
	if len(stdout) > 0 {
		artifact, err := writeCheckArtifact(checkID, artifactID, ArtifactKindStdout, stdout, runArtifacts)
		if err != nil {
			return nil, err
		}
		artifactRefs = append(artifactRefs, artifact)
	}
	if len(stderr) > 0 {
		artifact, err := writeCheckArtifact(checkID, artifactID, ArtifactKindStderr, stderr, runArtifacts)
		if err != nil {
			return nil, err
		}
		artifactRefs = append(artifactRefs, artifact)
	}
	return artifactRefs, nil
}

func writeCheckArtifact(checkID, artifactID, kind string, data []byte, runArtifacts *artifactRun) (ArtifactReference, error) {
	artifactsDir, artifactsRelDir, err := runArtifacts.ensureDir()
	if err != nil {
		return ArtifactReference{}, err
	}

	fileName := fmt.Sprintf("%s-%s.txt", artifactID, kind)
	artifactPath := filepath.Join(artifactsDir, fileName)
	if err := os.WriteFile(artifactPath, data, 0644); err != nil {
		return ArtifactReference{}, fmt.Errorf("write verify artifact %s: %w", fileName, err)
	}

	return ArtifactReference{
		CheckID: checkID,
		Kind:    kind,
		Path:    path.Join(artifactsRelDir, fileName),
	}, nil
}

func uniqueArtifactID(checkID string, checkIndex int, used map[string]struct{}) string {
	baseID := safeArtifactID(checkID)
	if _, ok := used[baseID]; !ok {
		used[baseID] = struct{}{}
		return baseID
	}

	candidatePrefix := fmt.Sprintf("%s-%d", baseID, checkIndex+1)
	candidate := candidatePrefix
	for suffix := 2; ; suffix++ {
		if _, ok := used[candidate]; !ok {
			used[candidate] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", candidatePrefix, suffix)
	}
}

func safeArtifactID(checkID string) string {
	var builder strings.Builder
	for _, r := range checkID {
		if r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}
	if builder.Len() == 0 {
		return "check"
	}
	return builder.String()
}

func baseCheckResult(check ShellCheck, startedAt time.Time) CheckResult {
	return CheckResult{
		ID:             check.ID,
		Name:           check.Name,
		Adapter:        AdapterShell,
		Status:         CheckStatusPass,
		Required:       check.Required,
		Command:        check.Command,
		WorkDir:        check.WorkDir,
		TimeoutSeconds: check.TimeoutSeconds,
		StartedAt:      startedAt,
		FinishedAt:     startedAt,
		DurationMs:     0,
		ExitCode:       0,
		StdoutArtifact: "",
		StderrArtifact: "",
		Message:        "check passed",
	}
}

func missingShellCheckMessage(check ShellCheck) (string, bool) {
	if check.Command == "" {
		return "check command is missing", true
	}
	if check.WorkDir == "" {
		return "check working directory is missing", true
	}
	info, err := os.Stat(check.WorkDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Sprintf("check working directory is missing: %s", check.WorkDir), true
		}
		return fmt.Sprintf("check working directory is unavailable: %v", err), true
	}
	if !info.IsDir() {
		return fmt.Sprintf("check working directory is not a directory: %s", check.WorkDir), true
	}
	return "", false
}

func shellCommand(command string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", command}
	}
	return "sh", []string{"-c", command}
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func isMissingCommandFailure(code int, stderr string) bool {
	stderr = strings.ToLower(stderr)
	if code == 127 && (strings.Contains(stderr, "not found") || strings.Contains(stderr, "not found:")) {
		return true
	}
	if runtime.GOOS == "windows" && code == 1 && strings.Contains(stderr, "not recognized") {
		return true
	}
	return false
}

func applyCheckSummary(result *Result, check CheckResult) {
	switch check.Status {
	case CheckStatusPass:
		result.Summary.Passed++
	case CheckStatusFail:
		result.Summary.Failed++
	case CheckStatusTimeout:
		result.Summary.TimedOut++
	case CheckStatusMissing:
		result.Summary.Missing++
	case CheckStatusSkipped:
		result.Summary.Skipped++
	}
}

func warningForCheck(check CheckResult) (Warning, bool) {
	if check.Required || check.Status == CheckStatusPass {
		return Warning{}, false
	}

	return Warning{
		CheckID: check.ID,
		Status:  check.Status,
		Message: check.Message,
	}, true
}

func statusForResult(result *Result) string {
	for _, check := range result.Checks {
		if check.Required && (check.Status == CheckStatusFail || check.Status == CheckStatusTimeout || check.Status == CheckStatusMissing) {
			return StatusFail
		}
	}
	if len(result.Warnings) > 0 {
		return StatusWarn
	}
	return StatusPass
}
