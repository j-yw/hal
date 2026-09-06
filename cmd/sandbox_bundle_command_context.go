package cmd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
)

var sandboxCommandContextFiles = []string{
	template.ConfigFile,
	template.PromptFile,
	template.ProgressFile,
	template.PRDFile,
	template.AutoPRDFile,
	template.AutoStateFile,
}

func prepareSandboxCommandContextRuntime(ctx context.Context, prep sandboxexec.PrepareContext, projectDir, workspaceDir string, out io.Writer) (sandboxworkspace.MaterializationOperation, error) {
	if prep.Driver == nil {
		return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("sandbox runtime driver is required")
	}
	projectDir = strings.TrimSpace(projectDir)
	workspaceDir = pathpkg.Clean(filepath.ToSlash(strings.TrimSpace(workspaceDir)))
	if projectDir == "" {
		return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("sandbox bundle command context project directory is required")
	}
	if workspaceDir == "" || workspaceDir == "." || !pathpkg.IsAbs(workspaceDir) {
		return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("sandbox bundle command context workspace directory must be absolute")
	}
	if out == nil {
		out = io.Discard
	}
	hasContext, err := hasSandboxCommandContext(projectDir)
	if err != nil {
		return sandboxworkspace.MaterializationOperation{}, err
	}
	if !hasContext {
		return sandboxworkspace.MaterializationOperation{
			Phase:   sandboxworkspace.MaterializationPhaseCommandConfig,
			Summary: "prepared Hal command context (no host context files)",
		}, nil
	}

	copied := 0
	reset := 0
	for _, name := range sandboxCommandContextFiles {
		sourcePath := filepath.Join(projectDir, template.HalDir, name)
		info, err := os.Lstat(sourcePath)
		if os.IsNotExist(err) {
			if err := removeSandboxCommandContextFile(ctx, prep, workspaceDir, name); err != nil {
				return sandboxworkspace.MaterializationOperation{}, err
			}
			reset++
			continue
		}
		if err != nil {
			return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("inspect sandbox command context %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("sandbox command context %q is not a regular file", name)
		}
		if err := copySandboxBundleCommandContextFile(ctx, prep, sourcePath, workspaceDir, name); err != nil {
			return sandboxworkspace.MaterializationOperation{}, err
		}
		copied++
	}

	result, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: prep.Target,
		Args:   []string{"sh", "-c", "set -eu\ncd " + shellQuote(workspaceDir) + "\nexec hal init"},
		Stdout: out,
		Stderr: out,
	})
	if err != nil {
		return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("initialize sandbox bundle command context: %w", err)
	}
	if result != nil && result.ExitCode != 0 {
		return sandboxworkspace.MaterializationOperation{}, fmt.Errorf("initialize sandbox bundle command context: hal init exited with status %d", result.ExitCode)
	}

	return sandboxworkspace.MaterializationOperation{
		Phase:   sandboxworkspace.MaterializationPhaseCommandConfig,
		Summary: fmt.Sprintf("prepared Hal command context (%d copied, %d reset)", copied, reset),
	}, nil
}

func hasSandboxCommandContext(projectDir string) (bool, error) {
	for _, name := range sandboxCommandContextFiles {
		_, err := os.Lstat(filepath.Join(projectDir, template.HalDir, name))
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("inspect sandbox command context %q: %w", name, err)
		}
	}
	return false, nil
}

func removeSandboxCommandContextFile(ctx context.Context, prep sandboxexec.PrepareContext, workspaceDir, name string) error {
	halDir := pathpkg.Join(workspaceDir, template.HalDir)
	destinationPath := pathpkg.Join(halDir, name)
	script := strings.Join([]string{
		"set -eu",
		"hal_dir=" + shellQuote(halDir),
		"destination=" + shellQuote(destinationPath),
		`if [ -L "$hal_dir" ] || { [ -e "$hal_dir" ] && [ ! -d "$hal_dir" ]; }; then echo "sandbox .hal path is not a directory" >&2; exit 1; fi`,
		`rm -f "$destination"`,
	}, "\n")
	result, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: prep.Target,
		Args:   []string{"sh", "-c", script},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err == nil && result != nil && result.ExitCode != 0 {
		err = fmt.Errorf("reset exited with status %d", result.ExitCode)
	}
	if err != nil {
		return fmt.Errorf("reset sandbox command context %q: %w", name, err)
	}
	return nil
}

func copySandboxBundleCommandContextFile(ctx context.Context, prep sandboxexec.PrepareContext, sourcePath, workspaceDir, name string) error {
	hash := sha256.Sum256([]byte(workspaceDir + "\x00" + name))
	tmpPath := fmt.Sprintf("/tmp/hal-command-context-%x", hash[:8])
	if err := prep.Driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          prep.Target,
		SourcePath:      sourcePath,
		DestinationPath: tmpPath,
	}); err != nil {
		return fmt.Errorf("copy sandbox command context %q: %w", name, err)
	}

	halDir := pathpkg.Join(workspaceDir, template.HalDir)
	destinationPath := pathpkg.Join(halDir, name)
	script := strings.Join([]string{
		"set -eu",
		"umask 077",
		"hal_dir=" + shellQuote(halDir),
		"destination=" + shellQuote(destinationPath),
		"source_tmp=" + shellQuote(tmpPath),
		`if [ -L "$hal_dir" ] || { [ -e "$hal_dir" ] && [ ! -d "$hal_dir" ]; }; then echo "sandbox .hal path is not a directory" >&2; exit 1; fi`,
		`if [ -L "$source_tmp" ] || [ ! -f "$source_tmp" ]; then echo "sandbox command context source is not regular" >&2; exit 1; fi`,
		`mkdir -p "$hal_dir"`,
		`rm -f "$destination"`,
		`mv "$source_tmp" "$destination"`,
		`chmod 0600 "$destination"`,
	}, "\n")
	result, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: prep.Target,
		Args:   []string{"sh", "-c", script},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err == nil && result != nil && result.ExitCode != 0 {
		err = fmt.Errorf("install exited with status %d", result.ExitCode)
	}
	if err != nil {
		_, _ = prep.Driver.Exec(context.WithoutCancel(ctx), sandboxruntime.ExecRequest{
			Target: prep.Target,
			Args:   []string{"rm", "-f", tmpPath},
			Stdout: io.Discard,
			Stderr: io.Discard,
		})
		return fmt.Errorf("install sandbox command context %q: %w", name, err)
	}
	return nil
}
