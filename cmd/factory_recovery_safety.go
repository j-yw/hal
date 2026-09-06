package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const factoryRecoveryBundleLimit = 512 << 20

func factoryRecoverySafetyError(reason string, cause error) error {
	return factoryRunRedactedError{message: "apply sandbox recovery bundle: " + reason + "; manual recovery required", cause: cause}
}

func applyFactoryRecoverySafely(ctx context.Context, store factory.Store, dir string, record factory.RunRecord, deps factoryRunDeps) (branch, storedPath string, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return "", "", factoryRecoverySafetyError("cancelled", ctx.Err())
	}
	if deps.runGit == nil {
		return "", "", factoryRecoverySafetyError("Git dependency unavailable", nil)
	}
	branch = strings.TrimSpace(record.BranchName)
	for _, name := range []string{branch, strings.TrimSpace(record.BaseBranch)} {
		if name == "" || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "refs/") {
			return "", "", factoryRecoverySafetyError("invalid branch identity", nil)
		}
		canonical, checkErr := deps.runGit(ctx, dir, "check-ref-format", "--branch", name)
		if checkErr != nil || canonical != name {
			return "", "", factoryRecoverySafetyError("invalid branch identity", checkErr)
		}
	}
	if branch == strings.TrimSpace(record.BaseBranch) {
		return "", "", factoryRecoverySafetyError("run branch equals base branch", nil)
	}
	root, err := deps.runGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil || !filepath.IsAbs(root) {
		return "", "", factoryRecoverySafetyError("workspace root unavailable", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", factoryRecoverySafetyError("workspace root unavailable", err)
	}
	// Reuse the SafeApply/direct-workspace manager and key, outside the tree.
	lock, err := sandboxworkspace.NewLockManager(filepath.Join(os.TempDir(), "hal-workspace-locks")).Acquire("workspace:" + root)
	if err != nil {
		return "", "", factoryRecoverySafetyError("workspace lock unavailable", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			err = errors.Join(err, factoryRecoverySafetyError("workspace lock release failed", releaseErr))
		}
	}()
	before, err := factoryRecoveryHostState(ctx, root, record, deps)
	if err != nil {
		return "", "", err
	}
	checkState := func(expected factoryRecoveryState) error {
		current, err := factoryRecoveryHostState(ctx, root, record, deps)
		if err != nil {
			return err
		}
		if current != expected || ctx.Err() != nil {
			return factoryRecoverySafetyError("workspace changed during recovery", ctx.Err())
		}
		return nil
	}
	var artifact factory.ArtifactReference
	count := 0
	for _, candidate := range record.Artifacts {
		if _, selected := factoryRunRecoveryBundleArtifact(factory.RunRecord{Artifacts: []factory.ArtifactReference{candidate}}); selected {
			artifact = candidate
			count++
		}
	}
	if count != 1 {
		return "", "", factoryRecoverySafetyError("one complete recovery bundle artifact is required", nil)
	}
	tmp, err := os.MkdirTemp("", "hal-factory-recovery-")
	if err != nil {
		return "", "", factoryRecoverySafetyError("private analysis directory unavailable", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(tmp); cleanupErr != nil {
			err = errors.Join(err, factoryRecoverySafetyError("private analysis cleanup failed", cleanupErr))
		}
	}()
	snapshot := filepath.Join(tmp, "recovery.bundle")
	if err := snapshotFactoryRecoveryBundle(ctx, store, record.RunID, artifact, snapshot); err != nil {
		return "", "", factoryRecoverySafetyError("stored bundle unavailable", err)
	}
	if _, err := deps.runGit(ctx, root, "bundle", "verify", snapshot); err != nil {
		return "", "", factoryRecoverySafetyError("bundle verification failed", err)
	}
	heads, err := deps.runGit(ctx, root, "bundle", "list-heads", snapshot)
	fields := strings.Fields(heads)
	if err != nil || len(fields) != 2 || fields[1] != "HEAD" || !factoryBundleCommitID(fields[0]) {
		return "", "", factoryRecoverySafetyError("bundle HEAD is ambiguous", err)
	}
	output := fields[0]
	analysis := filepath.Join(tmp, "analysis.git")
	// A local shared clone reads existing objects, but writes only private refs
	// and imported bundle objects. Never consult a configured remote for history.
	if _, err := deps.runGit(ctx, root, "clone", "--bare", "--shared", "--no-hardlinks", "--", root, analysis); err != nil {
		return "", "", factoryRecoverySafetyError("local analysis unavailable", err)
	}
	if _, err := deps.runGit(ctx, analysis, "fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", snapshot, "HEAD"); err != nil {
		return "", "", factoryRecoverySafetyError("bundle analysis import failed", err)
	}
	for _, ancestor := range []string{before.anchor, before.destination} {
		if ancestor != "" {
			if _, err := deps.runGit(ctx, analysis, "merge-base", "--is-ancestor", ancestor, output); err != nil {
				return "", "", factoryRecoverySafetyError("output history does not fast-forward the local anchor or destination", err)
			}
		}
	}
	if err := factoryRecoveryCheckAddedPaths(ctx, root, analysis, before.head, output, deps); err != nil {
		return "", "", err
	}
	if err := checkState(before); err != nil {
		return "", "", err
	}
	if _, err := deps.runGit(ctx, root, "fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", snapshot, "HEAD"); err != nil {
		return "", "", factoryRecoverySafetyError("verified bundle import failed", err)
	}
	if err := checkState(before); err != nil {
		return "", "", err
	}
	if before.destination == "" {
		_, err = deps.runGit(ctx, root, "checkout", "--no-overwrite-ignore", "-b", branch, output)
	} else {
		if _, err = deps.runGit(ctx, root, "checkout", "--no-overwrite-ignore", branch); err == nil {
			expected := before
			expected.head, expected.currentRef = before.destination, "refs/heads/"+branch
			if err := checkState(expected); err != nil {
				return "", "", err
			}
			_, err = deps.runGit(ctx, root, "merge", "--ff-only", "--no-overwrite-ignore", output)
		}
	}
	if err != nil {
		return "", "", factoryRecoverySafetyError("safe branch apply failed", err)
	}
	if err := checkState(factoryRecoveryState{head: output, currentRef: "refs/heads/" + branch, anchor: before.anchor, destination: output}); err != nil {
		return "", "", err
	}
	return branch, artifact.StoredPath, nil
}

type factoryRecoveryState struct{ head, currentRef, anchor, destination string }

func factoryRecoveryHostState(ctx context.Context, root string, record factory.RunRecord, deps factoryRunDeps) (factoryRecoveryState, error) {
	var state factoryRecoveryState
	fail := func(cause error) (factoryRecoveryState, error) {
		return state, factoryRecoverySafetyError("clean local history unavailable", cause)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	dirty, err := deps.runGit(ctx, root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || strings.TrimSpace(dirty) != "" {
		return fail(err)
	}
	state.head, err = deps.runGit(ctx, root, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
	if err != nil || !factoryBundleCommitID(state.head) {
		return fail(err)
	}
	state.currentRef, err = deps.runGit(ctx, root, "symbolic-ref", "--quiet", "HEAD")
	if err != nil && factoryVerificationProviderExitCode(err) != 1 {
		return fail(err)
	}
	if record.Sandbox != nil && record.Sandbox.Workspace != nil {
		workspace := record.Sandbox.Workspace
		pin := strings.TrimSpace(workspace.SyncRef)
		if workspace.InputSource == sandbox.SandboxWorkspaceInputSourceGitBundle && !factoryBundleCommitID(pin) {
			return fail(nil)
		}
		if factoryBundleCommitID(pin) {
			state.anchor = pin
		}
	}
	if state.anchor != "" {
		if !factoryBundleCommitID(state.anchor) {
			return fail(nil)
		}
		if _, err := deps.runGit(ctx, root, "cat-file", "-e", state.anchor+"^{commit}"); err != nil {
			return fail(err)
		}
	} else {
		// Historical SSH records did not pin input. This is only a conservative
		// already-local base compatibility check, never original-input proof.
		state.anchor, err = deps.runGit(ctx, root, "rev-parse", "--verify", "--end-of-options", "refs/heads/"+strings.TrimSpace(record.BaseBranch)+"^{commit}")
		if err != nil || !factoryBundleCommitID(state.anchor) {
			return fail(err)
		}
	}
	_, err = deps.runGit(ctx, root, "show-ref", "--verify", "--quiet", "refs/heads/"+strings.TrimSpace(record.BranchName))
	if err != nil {
		if factoryVerificationProviderExitCode(err) != 1 {
			return fail(err)
		}
	} else {
		state.destination, err = deps.runGit(ctx, root, "rev-parse", "--verify", "--end-of-options", "refs/heads/"+strings.TrimSpace(record.BranchName)+"^{commit}")
		if err != nil || !factoryBundleCommitID(state.destination) {
			return fail(err)
		}
	}
	return state, nil
}

func factoryRecoveryCheckAddedPaths(ctx context.Context, root, analysis, head, output string, deps factoryRunDeps) error {
	// Raw records start with metadata, so runGit's surrounding-whitespace trim
	// cannot alter a first filename that begins with a space or newline.
	added, err := deps.runGit(ctx, analysis, "diff-tree", "--no-commit-id", "--raw", "--diff-filter=A", "-r", "-z", head, output)
	if err != nil {
		return factoryRecoverySafetyError("output path inspection failed", err)
	}
	directory, err := os.OpenRoot(root)
	if err != nil {
		return factoryRecoverySafetyError("workspace unavailable", err)
	}
	defer directory.Close()
	if added == "" {
		return nil
	}
	fields := strings.Split(added, "\x00")
	if len(fields)%2 != 1 || fields[len(fields)-1] != "" {
		return factoryRecoverySafetyError("output path records are invalid", nil)
	}
	for i := 0; i < len(fields)-1; i += 2 {
		name := fields[i+1]
		if !strings.HasPrefix(fields[i], ":") || !strings.HasSuffix(fields[i], " A") || name == "" {
			return factoryRecoverySafetyError("output path records are invalid", nil)
		}
		// Existing paths include ignored files: neither checkout nor merge may
		// silently overwrite them, even though porcelain considers them clean.
		if _, err := directory.Lstat(name); !os.IsNotExist(err) {
			return factoryRecoverySafetyError("output collides with a local path", err)
		}
	}
	return nil
}

func snapshotFactoryRecoveryBundle(ctx context.Context, store factory.Store, runID string, artifact factory.ArtifactReference, destination string) error {
	return snapshotFactoryRecoveryBundleWithOpen(ctx, store, runID, artifact, destination, openFactoryRecoveryFile)
}

func snapshotFactoryRecoveryBundleWithOpen(ctx context.Context, store factory.Store, runID string, artifact factory.ArtifactReference, destination string, open func(*os.Root, string) (*os.File, error)) error {
	path, err := store.ResolveArtifactPath(runID, artifact.StoredPath)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(store.Root())
	if err != nil {
		return err
	}
	roots := []*os.Root{root}
	defer func() {
		for _, root := range roots {
			_ = root.Close()
		}
	}()
	relative, err := filepath.Rel(store.Root(), path)
	if err != nil {
		return err
	}
	parts := strings.Split(relative, string(filepath.Separator))
	var bindings []factoryRecoveryPathBinding
	parent := root
	for _, name := range parts[:len(parts)-1] {
		info, err := parent.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("nonregular artifact directory")
		}
		next, err := parent.OpenRoot(name)
		if err != nil {
			return err
		}
		roots = append(roots, next)
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("artifact directory changed at open")
		}
		binding := factoryRecoveryPathBinding{parent, name, info}
		if err := binding.check(); err != nil {
			return err
		}
		bindings = append(bindings, binding)
		parent = next
	}
	name := parts[len(parts)-1]
	expected, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	if !expected.Mode().IsRegular() {
		return errors.New("nonregular artifact file")
	}
	bindings = append(bindings, factoryRecoveryPathBinding{parent, name, expected})
	checkBindings := func() error {
		for _, binding := range bindings {
			if err := binding.check(); err != nil {
				return err
			}
		}
		return nil
	}
	file, err := open(parent, name)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(expected, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > factoryRecoveryBundleLimit || artifact.SizeBytes != nil && info.Size() != *artifact.SizeBytes {
		return errors.New("invalid bundle size or type")
	}
	if err := checkBindings(); err != nil {
		return err
	}
	copy, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(copy, io.LimitReader(factoryRecoveryContextReader{ctx, file}, info.Size()+1))
	closeErr := copy.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if n != info.Size() || ctx.Err() != nil {
		return errors.Join(errors.New("bundle changed during snapshot"), ctx.Err())
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(info, final) || info.Size() != final.Size() || !info.ModTime().Equal(final.ModTime()) {
		return errors.New("bundle changed during snapshot")
	}
	return checkBindings()
}

type factoryRecoveryPathBinding struct {
	parent *os.Root
	name   string
	info   os.FileInfo
}

func (b factoryRecoveryPathBinding) check() error {
	current, err := b.parent.Lstat(b.name)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(b.info, current) || b.info.Mode() != current.Mode() {
		return errors.New("artifact path binding changed")
	}
	if b.info.Mode().IsRegular() && (b.info.Size() != current.Size() || !b.info.ModTime().Equal(current.ModTime())) {
		return errors.New("artifact file changed")
	}
	return nil
}

type factoryRecoveryContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r factoryRecoveryContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
