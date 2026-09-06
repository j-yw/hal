package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type factorySandboxRuntimeBootstrapExecutor struct {
	driver       sandboxruntime.Driver
	target       sandboxruntime.Target
	out          io.Writer
	outputRedact func(string) string
}

func (e *factorySandboxRuntimeBootstrapExecutor) Run(ctx context.Context, command factory.BootstrapCommand) (factory.BootstrapCommandResult, error) {
	if e == nil || e.driver == nil {
		return factory.BootstrapCommandResult{}, fmt.Errorf("sandbox runtime bootstrap executor is required")
	}
	var summary bytes.Buffer
	out := io.Writer(&summary)
	var streamOut *factorySandboxBootstrapOutputWriter
	if e.out != nil {
		streamOut = &factorySandboxBootstrapOutputWriter{
			dst:    e.out,
			redact: e.outputRedact,
		}
		out = io.MultiWriter(streamOut, &summary)
	}
	result, err := e.driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: e.target,
		Args:   factorySandboxBootstrapCommandArgs(command),
		Env:    cloneRuntimeStringMap(command.Env),
		Stdout: out,
		Stderr: out,
	})
	if streamOut != nil {
		if flushErr := streamOut.Flush(); err == nil && flushErr != nil {
			err = flushErr
		}
	}
	return factory.BootstrapCommandResult{
		ExitCode:      sandboxRuntimeExecExitCode(result, err),
		OutputSummary: strings.TrimSpace(summary.String()),
	}, err
}

func sandboxRuntimeExecExitCode(result *sandboxruntime.ExecResult, err error) int {
	if result != nil {
		return result.ExitCode
	}
	if err == nil {
		return 0
	}
	return -1
}

func prepareFactorySandboxWorkspaceRuntime(ctx context.Context, store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, req factorySandboxExecutorRequest, prep sandboxexec.PrepareContext, remoteOutput *factorySandboxTimelineWriter) error {
	bootstrapReq, ok := factorySandboxBootstrapRequest(*record, req.ResolvedSecrets)
	if !ok {
		return nil
	}
	bootstrapResult, bootstrapErr := sandboxRuntimeBootstrapWorkspace(ctx, bootstrapReq, prep, req.RemoteOutput, deps.now, deps.bootstrap)
	target := sandboxStateFromRuntimeTarget(prep.Target)
	if appendErr := appendFactorySandboxBootstrapTimeline(store, deps, record, target, bootstrapResult, remoteOutput); appendErr != nil {
		return fmt.Errorf("record sandbox bootstrap timeline: %w", appendErr)
	}
	if syncErr := remoteOutput.SyncNextSequence(); syncErr != nil {
		return fmt.Errorf("sync sandbox timeline sequence: %w", syncErr)
	}
	return bootstrapErr
}

func sandboxRuntimeBootstrapWorkspace(ctx context.Context, req factory.BootstrapRequest, prep sandboxexec.PrepareContext, out io.Writer, now func() time.Time, bootstrap func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)) (factory.BootstrapResult, error) {
	if bootstrap == nil {
		return factory.BootstrapResult{}, fmt.Errorf("sandbox bootstrap dependency is required")
	}
	executor := &factorySandboxRuntimeBootstrapExecutor{
		driver:       prep.Driver,
		target:       prep.Target,
		out:          out,
		outputRedact: factory.NewBootstrapSanitizer(req).SanitizeString,
	}
	return bootstrap(ctx, req, factory.BootstrapDeps{
		Executor: executor,
		Now:      now,
		RepoExists: func(path string) (bool, error) {
			return factorySandboxRuntimeRepoExists(ctx, prep.Driver, prep.Target, path, req.RepositoryURL)
		},
	})
}

func factorySandboxRuntimeRepoExists(ctx context.Context, driver sandboxruntime.Driver, target sandboxruntime.Target, repoPath, expectedRemote string) (bool, error) {
	if driver == nil {
		return false, fmt.Errorf("sandbox runtime driver is required")
	}
	repoPath = pathpkg.Clean(filepath.ToSlash(strings.TrimSpace(repoPath)))
	if repoPath == "" || repoPath == "." {
		return false, errFactorySandboxWorkspaceRequired
	}
	repoGitPath := pathpkg.Join(repoPath, ".git")
	quotedRepoPath := shellQuote(repoPath)
	script := strings.Join([]string{
		"if [ -e " + shellQuote(repoGitPath) + " ]; then git -C " + quotedRepoPath + " remote get-url origin; exit $?; fi",
		"if [ ! -e " + quotedRepoPath + " ]; then exit 10; fi",
		"if [ -d " + quotedRepoPath + " ] && [ -z \"$(find " + quotedRepoPath + " -mindepth 1 -maxdepth 1 -print -quit)\" ]; then exit 10; fi",
		"exit 11",
	}, "\n")
	var stdout bytes.Buffer
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: target,
		Args:   []string{"sh", "-c", script},
		Stdout: &stdout,
		Stderr: io.Discard,
	})
	if err == nil {
		if !factorySandboxRemoteMatches(expectedRemote, stdout.String()) {
			return false, fmt.Errorf("existing checkout origin does not match requested repository")
		}
		return true, nil
	}
	switch sandboxRuntimeExecExitCode(result, err) {
	case 10:
		return false, nil
	case 11:
		return false, fmt.Errorf("repository path exists but is not a git checkout and is not empty")
	default:
		return false, err
	}
}

func factorySandboxSyncEngineAuthRuntime(ctx context.Context, prep sandboxexec.PrepareContext, deps factorySandboxExecutorDeps) error {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	if deps.engineAuthFiles == nil {
		return nil
	}
	for _, authFile := range deps.engineAuthFiles() {
		sourcePath := strings.TrimSpace(authFile.SourcePath)
		remotePath := strings.TrimSpace(authFile.RemotePath)
		if sourcePath == "" || remotePath == "" {
			continue
		}
		if _, err := os.Stat(sourcePath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("read sandbox engine auth %q: %w", filepath.Base(sourcePath), err)
		}
		if err := factorySandboxCopyAuthFileRuntime(ctx, prep, sourcePath, remotePath); err != nil {
			return fmt.Errorf("sync sandbox engine auth %q: %w", filepath.Base(sourcePath), err)
		}
	}
	return nil
}

func factorySandboxCopyAuthFileRuntime(ctx context.Context, prep sandboxexec.PrepareContext, sourcePath, remotePath string) error {
	if prep.Driver == nil {
		return fmt.Errorf("sandbox runtime driver is required")
	}
	remotePath = pathpkg.Clean(filepath.ToSlash(strings.TrimSpace(remotePath)))
	if remotePath == "" || remotePath == "." || pathpkg.IsAbs(remotePath) || remotePath == ".." || strings.HasPrefix(remotePath, "../") {
		return fmt.Errorf("remote home path is invalid")
	}
	tmpPath := "/tmp/hal-auth-" + factorySandboxRemoteTempBase(remotePath, []byte(sourcePath))
	if err := prep.Driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          prep.Target,
		SourcePath:      sourcePath,
		DestinationPath: tmpPath,
	}); err != nil {
		return err
	}
	pathScript := factorySandboxRemoteHomePathScript(
		pathpkg.Dir(remotePath),
		remotePath,
		factorySandboxRemoteTempBase(remotePath, []byte(sourcePath)),
	)
	script := strings.Join([]string{
		pathScript,
		"source_tmp=" + shellQuote(tmpPath),
		`if [ -L "$source_tmp" ] || [ ! -f "$source_tmp" ]; then echo "runtime auth source is not regular" >&2; exit 1; fi`,
		factorySandboxRemoteBeginCopyScript(),
		`cat "$source_tmp" >> "$remote_tmp"`,
		factorySandboxRemoteFinalizeCopyScript("0600"),
		`rm -f "$source_tmp"`,
	}, "\n")
	_, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: prep.Target,
		Args:   []string{"sh", "-c", script},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		_, _ = prep.Driver.Exec(context.WithoutCancel(ctx), sandboxruntime.ExecRequest{
			Target: prep.Target,
			Args:   []string{"rm", "-f", tmpPath},
			Stdout: io.Discard,
			Stderr: io.Discard,
		})
	}
	return err
}

func factorySandboxPrepareRemoteInputsRuntime(ctx context.Context, req factorySandboxExecutorRequest, prep sandboxexec.PrepareContext) (factoryRunAutoRequest, error) {
	remoteReq := req.RemoteAuto
	workspaceDir := factorySandboxRemoteWorkspaceDir(req.RunRecord)
	if workspaceDir == "" {
		return remoteReq, errFactorySandboxWorkspaceRequired
	}
	if len(remoteReq.Args) > 0 {
		remotePath, changed, err := factorySandboxCopyInputRuntime(ctx, prep, req.ProjectDir, remoteReq.Args[0], workspaceDir)
		if err != nil {
			return remoteReq, err
		}
		if changed {
			remoteReq.Args = append([]string{remotePath}, remoteReq.Args[1:]...)
		}
	}
	if strings.TrimSpace(remoteReq.ReportPath) != "" {
		remotePath, changed, err := factorySandboxCopyInputRuntime(ctx, prep, req.ProjectDir, remoteReq.ReportPath, workspaceDir)
		if err != nil {
			return remoteReq, err
		}
		if changed {
			remoteReq.ReportPath = remotePath
		}
	}
	return remoteReq, nil
}

func factorySandboxCopyInputRuntime(ctx context.Context, prep sandboxexec.PrepareContext, projectDir, localPath, workspaceDir string) (string, bool, error) {
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		return localPath, false, nil
	}
	sourcePath := localPath
	if !filepath.IsAbs(sourcePath) {
		sourcePath = filepath.Join(strings.TrimSpace(projectDir), sourcePath)
	}
	if _, err := os.Stat(sourcePath); err != nil {
		return localPath, false, fmt.Errorf("read sandbox input %q: %w", localPath, err)
	}
	remotePath := factorySandboxRemoteInputPath(localPath)
	remoteAbsPath := pathpkg.Join(filepath.ToSlash(workspaceDir), remotePath)
	if _, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: prep.Target,
		Args:   []string{"mkdir", "-p", pathpkg.Dir(remoteAbsPath)},
		Stdout: io.Discard,
		Stderr: io.Discard,
	}); err != nil {
		return localPath, false, fmt.Errorf("prepare sandbox input %q: %w", remotePath, err)
	}
	if err := prep.Driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          prep.Target,
		SourcePath:      sourcePath,
		DestinationPath: remoteAbsPath,
	}); err != nil {
		return localPath, false, fmt.Errorf("copy sandbox input %q to %q: %w", localPath, remotePath, err)
	}
	return remotePath, true, nil
}

func cloneRuntimeStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
