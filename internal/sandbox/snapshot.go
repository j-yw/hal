package sandbox

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

const snapshotStateActive = "active"

var snapshotWorkingDirMu sync.Mutex

type snapshotCreateFn func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error)
type snapshotGetFn func(ctx context.Context, nameOrID string) (*types.Snapshot, error)

// CreateSnapshot creates a Daytona snapshot from a Docker image reference.
// It streams build logs to the provided writer and returns the snapshot ID on success.
func CreateSnapshot(ctx context.Context, client *daytona.Client, name, imageRef string, out io.Writer) (string, error) {
	return createSnapshot(
		ctx,
		name,
		imageRef,
		out,
		func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
			return client.Snapshot.Create(ctx, params)
		},
		func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
			return client.Snapshot.Get(ctx, nameOrID)
		},
	)
}

// CreateSnapshotFromDockerfile creates a Daytona snapshot from a local Dockerfile
// and build context directory.
func CreateSnapshotFromDockerfile(ctx context.Context, client *daytona.Client, name, dockerfilePath, contextPath string, out io.Writer) (string, error) {
	if out == nil {
		out = io.Discard
	}

	contextPath = strings.TrimSpace(contextPath)
	if contextPath == "" {
		contextPath = "."
	}

	absContext, err := filepath.Abs(contextPath)
	if err != nil {
		return "", fmt.Errorf("resolving context path: %w", err)
	}
	absDockerfile, err := filepath.Abs(dockerfilePath)
	if err != nil {
		return "", fmt.Errorf("resolving dockerfile path: %w", err)
	}

	relDockerfile, err := filepath.Rel(absContext, absDockerfile)
	if err != nil {
		return "", fmt.Errorf("resolving dockerfile path relative to context: %w", err)
	}
	if relDockerfile == ".." || strings.HasPrefix(relDockerfile, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("dockerfile %q must be inside context %q", dockerfilePath, contextPath)
	}

	preparedContext, cleanup, err := prepareSnapshotContext(absContext, out)
	if err != nil {
		return "", fmt.Errorf("preparing build context: %w", err)
	}
	defer cleanup()

	preparedDockerfile := filepath.Join(preparedContext, relDockerfile)
	dockerfile, err := ReadDockerfile(preparedDockerfile)
	if err != nil {
		return "", err
	}

	image := daytona.FromDockerfile(dockerfile).
		AddLocalDir(".", "/tmp/hal-build-context")

	return withSnapshotWorkingDir(preparedContext, func() (string, error) {
		return createSnapshotWithImage(
			ctx,
			name,
			image,
			out,
			func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
				return client.Snapshot.Create(ctx, params)
			},
			func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
				return client.Snapshot.Get(ctx, nameOrID)
			},
		)
	})
}

// ListSnapshots returns snapshots visible to the configured Daytona account.
func ListSnapshots(ctx context.Context, client *daytona.Client) ([]*types.Snapshot, error) {
	result, err := client.Snapshot.List(ctx, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	if result == nil || result.Items == nil {
		return []*types.Snapshot{}, nil
	}
	return result.Items, nil
}

func createSnapshot(ctx context.Context, name, imageRef string, out io.Writer, createFn snapshotCreateFn, getFn snapshotGetFn) (string, error) {
	return createSnapshotWithImage(ctx, name, daytona.Base(imageRef), out, createFn, getFn)
}

func createSnapshotWithImage(ctx context.Context, name string, image any, out io.Writer, createFn snapshotCreateFn, getFn snapshotGetFn) (string, error) {
	if out == nil {
		out = io.Discard
	}

	params := &types.CreateSnapshotParams{
		Name:  name,
		Image: image,
	}

	snapshot, logChan, err := createFn(ctx, params)
	if err != nil {
		return "", fmt.Errorf("creating snapshot: %w", err)
	}
	if snapshot == nil {
		return "", fmt.Errorf("creating snapshot: empty snapshot response")
	}

	// Stream build logs
	if logChan != nil {
		streaming := true
		for streaming {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("streaming snapshot %q logs: %w", snapshot.ID, ctx.Err())
			case line, ok := <-logChan:
				if !ok {
					streaming = false
					continue
				}
				fmt.Fprintln(out, line)
			}
		}
	}

	latestSnapshot, err := getFn(ctx, snapshot.ID)
	if err != nil {
		return "", fmt.Errorf("checking snapshot %q status: %w", snapshot.ID, err)
	}
	if latestSnapshot == nil {
		return "", fmt.Errorf("checking snapshot %q status: empty snapshot response", snapshot.ID)
	}
	if latestSnapshot.State != snapshotStateActive {
		if latestSnapshot.ErrorReason != nil && *latestSnapshot.ErrorReason != "" {
			return "", fmt.Errorf("snapshot %q finished in state %s: %s", latestSnapshot.ID, latestSnapshot.State, *latestSnapshot.ErrorReason)
		}
		return "", fmt.Errorf("snapshot %q finished in state %s", latestSnapshot.ID, latestSnapshot.State)
	}

	return snapshot.ID, nil
}

// DeleteSnapshot deletes a Daytona snapshot by ID.
func DeleteSnapshot(ctx context.Context, client *daytona.Client, snapshotID string) error {
	snapshot, err := client.Snapshot.Get(ctx, snapshotID)
	if err != nil {
		return fmt.Errorf("getting snapshot %q: %w", snapshotID, err)
	}

	if err := client.Snapshot.Delete(ctx, snapshot); err != nil {
		return fmt.Errorf("deleting snapshot %q: %w", snapshotID, err)
	}

	return nil
}

// ReadDockerfile reads the Dockerfile at the given path and returns its content.
// Returns a descriptive error if the file does not exist.
func ReadDockerfile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("Dockerfile not found at %s", path)
		}
		return "", fmt.Errorf("reading Dockerfile: %w", err)
	}
	return string(data), nil
}

func withSnapshotWorkingDir(dir string, fn func() (string, error)) (string, error) {
	snapshotWorkingDirMu.Lock()
	defer snapshotWorkingDirMu.Unlock()

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	if err := os.Chdir(dir); err != nil {
		return "", fmt.Errorf("changing working directory: %w", err)
	}
	defer func() {
		_ = os.Chdir(cwd)
	}()

	return fn()
}

func prepareSnapshotContext(sourceDir string, out io.Writer) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "hal-snapshot-context-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp context dir: %w", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	matcher, err := loadDockerIgnore(sourceDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	if err := copySnapshotContext(sourceDir, tmpDir, out, matcher); err != nil {
		cleanup()
		return "", nil, err
	}

	return tmpDir, cleanup, nil
}

func copySnapshotContext(sourceDir, targetDir string, out io.Writer, matcher dockerIgnoreMatcher) error {
	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if matcher.ignored(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		dst := filepath.Join(targetDir, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			targetInfo, statErr := os.Stat(path)
			if statErr != nil {
				if out != nil {
					fmt.Fprintf(out, "Skipping broken symlink in build context: %s\n", rel)
				}
				return nil
			}
			if ignored, err := matcher.ignoredSymlinkTarget(sourceDir, path, targetInfo.IsDir()); err != nil {
				return err
			} else if ignored {
				return nil
			}
			if targetInfo.IsDir() {
				if out != nil {
					fmt.Fprintf(out, "Skipping symlinked directory in build context: %s\n", rel)
				}
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			return copyFile(path, dst, targetInfo.Mode().Perm())
		}

		if d.IsDir() {
			perm := info.Mode().Perm()
			if perm == 0 {
				perm = 0755
			}
			return os.MkdirAll(dst, perm)
		}

		if !info.Mode().IsRegular() {
			if out != nil {
				fmt.Fprintf(out, "Skipping unsupported file in build context: %s\n", rel)
			}
			return nil
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}

		return copyFile(path, dst, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	if perm == 0 {
		perm = 0644
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return nil
}

type dockerIgnorePattern struct {
	pattern string
	negated bool
}

type dockerIgnoreMatcher []dockerIgnorePattern

func loadDockerIgnore(sourceDir string) (dockerIgnoreMatcher, error) {
	data, err := os.ReadFile(filepath.Join(sourceDir, ".dockerignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading .dockerignore: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	patterns := make(dockerIgnoreMatcher, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pattern := dockerIgnorePattern{}
		if strings.HasPrefix(line, "!") {
			pattern.negated = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}
		line = filepath.ToSlash(filepath.Clean(strings.Trim(line, "/")))
		if line == "." || line == "" {
			continue
		}
		pattern.pattern = line
		patterns = append(patterns, pattern)
	}

	return patterns, nil
}

func (m dockerIgnoreMatcher) ignored(rel string, isDir bool) bool {
	if len(m) == 0 {
		return false
	}

	rel = filepath.ToSlash(rel)
	ignored := false
	for _, pattern := range m {
		if pattern.matches(rel, isDir) {
			ignored = !pattern.negated
		}
	}

	return ignored
}

func (m dockerIgnoreMatcher) ignoredSymlinkTarget(sourceDir, symlinkPath string, isDir bool) (bool, error) {
	if len(m) == 0 {
		return false, nil
	}

	resolved, err := filepath.EvalSymlinks(symlinkPath)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(sourceDir, resolved)
	if err != nil {
		return false, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}

	return m.ignored(rel, isDir), nil
}

func (p dockerIgnorePattern) matches(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	candidates := pathAncestors(rel)
	for _, candidate := range candidates {
		ok, err := path.Match(p.pattern, candidate)
		if err == nil && ok {
			return true
		}
	}

	if strings.Contains(p.pattern, "/") {
		return false
	}

	parts := strings.Split(rel, "/")
	for _, part := range parts {
		ok, err := path.Match(p.pattern, part)
		if err == nil && ok {
			return true
		}
	}

	if isDir {
		ok, err := path.Match(p.pattern, path.Base(rel))
		return err == nil && ok
	}

	return false
}

func pathAncestors(rel string) []string {
	parts := strings.Split(rel, "/")
	ancestors := make([]string, 0, len(parts))
	for i := 1; i <= len(parts); i++ {
		ancestors = append(ancestors, strings.Join(parts[:i], "/"))
	}
	return ancestors
}
