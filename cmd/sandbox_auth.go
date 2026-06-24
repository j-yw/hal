package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
)

var sandboxAuthIncludeClaude bool

var sandboxAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage sandbox agent auth profiles",
	Long: `Manage local agent authentication copied into running sandboxes.

The auth sync flow copies only the small subscription-login profile files needed
by CLIs such as Codex and pi. It avoids caches, logs, sessions, and GitHub CLI
credentials. GitHub authentication is managed separately through sandbox token
setup and gh's credential helper.`,
	Example: `  hal sandbox auth sync my-sandbox
  hal sandbox auth sync --include-claude my-sandbox`,
}

var sandboxAuthSyncCmd = &cobra.Command{
	Use:   "sync [NAME]",
	Short: "Sync Codex and pi auth into a sandbox",
	Args:  maxArgsValidation(1),
	Long: `Sync local Codex and pi subscription-login auth files into a running sandbox.

By default this copies selected files from ~/.codex and ~/.pi into the remote
exec user's home using tar over the existing sandbox SSH transport. The command
does not copy GitHub CLI credentials, caches, logs, sessions, or entire auth
directories.

Use --include-claude to also copy known Claude Code auth/settings files when
they exist locally.`,
	Example: `  hal sandbox auth sync my-sandbox
  hal sandbox auth sync --include-claude my-sandbox
  hal sandbox auth sync`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var name string
		if len(args) > 0 {
			name = args[0]
		}
		return runSandboxCobra(cmd, "Sandbox Auth Sync failed", func() error {
			_, err := runSandboxAuthSyncWithDeps(cmd.Context(), name, sandboxAuthSyncOptions{
				IncludeClaude: sandboxAuthIncludeClaude,
			}, cmd.OutOrStdout(), sandboxAuthSyncDeps{})
			return err
		})
	},
}

func init() {
	sandboxAuthSyncCmd.Flags().BoolVar(&sandboxAuthIncludeClaude, "include-claude", false, "also sync known Claude Code auth/settings files")
	sandboxAuthCmd.AddCommand(sandboxAuthSyncCmd)
	sandboxCmd.AddCommand(sandboxAuthCmd)
}

type sandboxAuthSyncOptions struct {
	IncludeClaude bool
}

type sandboxAuthSyncResult struct {
	SandboxName string
	FileCount   int
	Profiles    map[string]int
}

type sandboxAuthSyncDeps struct {
	homeDir         func() (string, error)
	resolveTarget   func(string) (*sandbox.SandboxState, string, error)
	resolveProvider func(string) (sandbox.Provider, error)
	runRemote       func(sandbox.Provider, *sandbox.ConnectInfo, []byte, io.Writer) error
}

type sandboxAuthProfileSpec struct {
	Name    string
	Entries []string
}

type sandboxAuthFile struct {
	Profile     string
	LocalPath   string
	ArchivePath string
	Mode        fs.FileMode
	Size        int64
	ModTime     time.Time
}

func normalizeSandboxAuthSyncDeps(deps sandboxAuthSyncDeps) sandboxAuthSyncDeps {
	if deps.homeDir == nil {
		deps.homeDir = os.UserHomeDir
	}
	if deps.resolveTarget == nil {
		deps.resolveTarget = resolveSSHTarget
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = func(providerName string) (sandbox.Provider, error) {
			return resolveProviderWithFallback(".", providerName)
		}
	}
	if deps.runRemote == nil {
		deps.runRemote = runSandboxAuthRemoteInstall
	}
	return deps
}

func runSandboxAuthSyncWithDeps(ctx context.Context, name string, opts sandboxAuthSyncOptions, out io.Writer, deps sandboxAuthSyncDeps) (sandboxAuthSyncResult, error) {
	deps = normalizeSandboxAuthSyncDeps(deps)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return sandboxAuthSyncResult{}, err
	}
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return sandboxAuthSyncResult{}, err
	}

	target, hint, err := deps.resolveTarget(strings.TrimSpace(name))
	if err != nil {
		return sandboxAuthSyncResult{}, err
	}
	if hint != "" && out != nil {
		fmt.Fprintln(out, hint)
	}
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		return sandboxAuthSyncResult{}, fmt.Errorf("resolving provider for %q: %w", target.Name, err)
	}
	return runSandboxAuthSyncToTarget(ctx, target, provider, opts, out, deps)
}

func runSandboxAuthSyncToTarget(ctx context.Context, target *sandbox.SandboxState, provider sandbox.Provider, opts sandboxAuthSyncOptions, out io.Writer, deps sandboxAuthSyncDeps) (sandboxAuthSyncResult, error) {
	deps = normalizeSandboxAuthSyncDeps(deps)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return sandboxAuthSyncResult{}, err
	}
	if target == nil {
		return sandboxAuthSyncResult{}, fmt.Errorf("sandbox target is required")
	}
	if provider == nil {
		return sandboxAuthSyncResult{}, fmt.Errorf("sandbox provider is required")
	}

	home, err := deps.homeDir()
	if err != nil {
		return sandboxAuthSyncResult{}, fmt.Errorf("resolve home directory: %w", err)
	}
	files, err := collectSandboxAuthFiles(home, opts)
	if err != nil {
		return sandboxAuthSyncResult{}, err
	}

	result := sandboxAuthSyncResult{
		SandboxName: target.Name,
		Profiles:    sandboxAuthProfileCounts(files),
		FileCount:   len(files),
	}
	if len(files) == 0 {
		if out != nil {
			fmt.Fprintln(out, "No local Codex/pi auth files found; skipping sandbox auth sync.")
		}
		return result, nil
	}

	archive, err := buildSandboxAuthArchive(files)
	if err != nil {
		return sandboxAuthSyncResult{}, err
	}
	if out != nil {
		fmt.Fprintf(out, "Syncing sandbox auth to %s (%s)...\n", target.Name, formatSandboxAuthProfiles(result.Profiles))
	}
	if err := deps.runRemote(provider, sandbox.ConnectInfoFromState(target), archive, out); err != nil {
		return sandboxAuthSyncResult{}, fmt.Errorf("install sandbox auth profile: %w", err)
	}
	if out != nil {
		fmt.Fprintf(out, "Synced sandbox auth to %s (%d files).\n", target.Name, result.FileCount)
	}
	return result, nil
}

func sandboxAuthProfileSpecs(opts sandboxAuthSyncOptions) []sandboxAuthProfileSpec {
	specs := []sandboxAuthProfileSpec{
		{
			Name: "codex",
			Entries: []string{
				".codex/auth.json",
				".codex/config.toml",
				".codex/version.json",
				".codex/installation_id",
			},
		},
		{
			Name: "pi",
			Entries: []string{
				".pi/agent/auth.json",
				".pi/agent/settings.json",
				".pi/agent/trust.json",
			},
		},
	}
	if opts.IncludeClaude {
		specs = append(specs, sandboxAuthProfileSpec{
			Name: "claude",
			Entries: []string{
				".claude.json",
				".claude/settings.json",
				".claude/credentials.json",
				".claude/.credentials.json",
			},
		})
	}
	return specs
}

func collectSandboxAuthFiles(home string, opts sandboxAuthSyncOptions) ([]sandboxAuthFile, error) {
	home = strings.TrimSpace(home)
	if home == "" {
		return nil, fmt.Errorf("home directory is empty")
	}

	var files []sandboxAuthFile
	for _, spec := range sandboxAuthProfileSpecs(opts) {
		for _, entry := range spec.Entries {
			cleanEntry := path.Clean(strings.TrimSpace(entry))
			if cleanEntry == "." || strings.HasPrefix(cleanEntry, "../") || path.IsAbs(cleanEntry) {
				return nil, fmt.Errorf("invalid auth sync entry %q", entry)
			}
			localPath := sandboxAuthLocalPath(home, spec, cleanEntry)
			info, err := os.Lstat(localPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, fmt.Errorf("stat auth file %s: %w", cleanEntry, err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			files = append(files, sandboxAuthFile{
				Profile:     spec.Name,
				LocalPath:   localPath,
				ArchivePath: cleanEntry,
				Mode:        info.Mode().Perm(),
				Size:        info.Size(),
				ModTime:     info.ModTime(),
			})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].ArchivePath < files[j].ArchivePath
	})
	return files, nil
}

func sandboxAuthLocalPath(home string, spec sandboxAuthProfileSpec, cleanEntry string) string {
	if spec.Name == "codex" {
		if rel, ok := strings.CutPrefix(cleanEntry, ".codex/"); ok {
			if codexHome := os.Getenv("CODEX_HOME"); codexHome != "" {
				return filepath.Join(codexHome, filepath.FromSlash(rel))
			}
		}
	}
	return filepath.Join(home, filepath.FromSlash(cleanEntry))
}

func buildSandboxAuthArchive(files []sandboxAuthFile) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	writtenDirs := map[string]bool{}

	for _, file := range files {
		if err := writeSandboxAuthParentDirs(tw, file.ArchivePath, writtenDirs); err != nil {
			return nil, err
		}
		if err := writeSandboxAuthFile(tw, file); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("finalize auth archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("compress auth archive: %w", err)
	}
	return buf.Bytes(), nil
}

func writeSandboxAuthParentDirs(tw *tar.Writer, archivePath string, written map[string]bool) error {
	var dirs []string
	for dir := path.Dir(archivePath); dir != "." && dir != "/"; dir = path.Dir(dir) {
		dirs = append(dirs, dir)
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		if written[dir] {
			continue
		}
		header := &tar.Header{
			Name:     dir,
			Typeflag: tar.TypeDir,
			Mode:     0o700,
			ModTime:  time.Unix(0, 0),
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write auth archive dir %s: %w", dir, err)
		}
		written[dir] = true
	}
	return nil
}

func writeSandboxAuthFile(tw *tar.Writer, file sandboxAuthFile) error {
	f, err := os.Open(file.LocalPath)
	if err != nil {
		return fmt.Errorf("open auth file %s: %w", file.ArchivePath, err)
	}
	defer f.Close()

	mode := int64(file.Mode)
	if mode == 0 {
		mode = 0o600
	}
	header := &tar.Header{
		Name:    file.ArchivePath,
		Size:    file.Size,
		Mode:    mode & 0o700,
		ModTime: file.ModTime,
	}
	if header.Mode == 0 {
		header.Mode = 0o600
	}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write auth archive header %s: %w", file.ArchivePath, err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("write auth archive file %s: %w", file.ArchivePath, err)
	}
	return nil
}

func runSandboxAuthRemoteInstall(provider sandbox.Provider, info *sandbox.ConnectInfo, archive []byte, out io.Writer) error {
	cmd, err := provider.Exec(info, []string{"sh", "-lc", sandboxAuthRemoteInstallScript()})
	if err != nil {
		return err
	}
	cmd.Stdin = bytes.NewReader(archive)
	return sandbox.RunCmd(cmd, out)
}

func sandboxAuthRemoteInstallScript() string {
	return strings.Join([]string{
		"set -eu",
		"remote_home=\"${HOME:-}\"",
		"if [ -z \"$remote_home\" ] && command -v getent >/dev/null 2>&1; then",
		"  remote_home=\"$(getent passwd \"$(id -u)\" | cut -d: -f6)\"",
		"fi",
		"if [ -z \"$remote_home\" ]; then remote_home=\"$(pwd)\"; fi",
		"export HOME=\"$remote_home\"",
		"mkdir -p \"$HOME\"",
		"tar -C \"$HOME\" -xzf -",
		"chmod -R go-rwx \"$HOME/.codex\" \"$HOME/.pi\" \"$HOME/.claude\" \"$HOME/.claude.json\" 2>/dev/null || true",
	}, "\n")
}

func sandboxAuthProfileCounts(files []sandboxAuthFile) map[string]int {
	counts := make(map[string]int)
	for _, file := range files {
		counts[file.Profile]++
	}
	return counts
}

func formatSandboxAuthProfiles(counts map[string]int) string {
	if len(counts) == 0 {
		return "no profiles"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}
