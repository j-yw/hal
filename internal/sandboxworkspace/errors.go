package sandboxworkspace

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNonGitWorktree is returned when clone mode is requested for a non-Git
	// project directory.
	ErrNonGitWorktree = errors.New("non-git worktree")

	// ErrDirtyWorktree is returned when clone mode would omit local changes.
	ErrDirtyWorktree = errors.New("dirty worktree")

	// ErrDirectOptInRequired is returned when direct mode is requested without
	// explicit direct workspace opt-in.
	ErrDirectOptInRequired = errors.New("direct workspace opt-in required")

	// ErrDirectLockActive is returned when a direct workspace resource key is
	// already locked.
	ErrDirectLockActive = errors.New("direct workspace lock already active")

	// ErrLocalGitRequired is returned when bundle preparation is requested
	// without a local Git adapter.
	ErrLocalGitRequired = errors.New("local git adapter is required")

	// ErrGitBundlePlanRequired is returned when local bundle preparation is
	// requested for a plan that is not bundle-backed.
	ErrGitBundlePlanRequired = errors.New("git-bundle workspace plan required")

	// ErrRemoteCopierRequired is returned when bundle copy-in is requested
	// without a remote copy adapter.
	ErrRemoteCopierRequired = errors.New("remote copy adapter is required")

	// ErrLocalBundleRequired is returned when bundle copy-in is requested
	// without a verified local bundle path.
	ErrLocalBundleRequired = errors.New("local bundle is required")
)

// PlanningError adds stable context around a planning rejection while preserving
// errors.Is classification for sentinel planning errors.
type PlanningError struct {
	Kind       error
	ProjectDir string
	Mode       string
	Dirty      DirtyState
	Err        error
}

func (e *PlanningError) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{"workspace planning"}
	if e.Mode != "" {
		parts = append(parts, "mode "+e.Mode)
	}
	if e.ProjectDir != "" {
		parts = append(parts, e.ProjectDir)
	}
	if e.Kind != nil {
		parts = append(parts, e.Kind.Error())
	}
	if e.Dirty.Any() {
		parts = append(parts, fmt.Sprintf("dirty state staged=%t unstaged=%t untracked=%t", e.Dirty.Staged, e.Dirty.Unstaged, e.Dirty.Untracked))
	}
	if e.Err != nil {
		parts = append(parts, e.Err.Error())
	}
	return strings.Join(parts, ": ")
}

func (e *PlanningError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *PlanningError) Is(target error) bool {
	if e == nil {
		return false
	}
	return target != nil && e.Kind == target
}

func planningError(kind error, req Request, dirty DirtyState, err error) error {
	return &PlanningError{
		Kind:       kind,
		ProjectDir: req.ProjectDir,
		Mode:       req.WorkspaceMode,
		Dirty:      dirty,
		Err:        err,
	}
}
