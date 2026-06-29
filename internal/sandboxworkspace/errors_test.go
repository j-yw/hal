package sandboxworkspace

import (
	"errors"
	"testing"
)

func TestPlanningErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "non git",
			err:  planningError(ErrNonGitWorktree, Request{ProjectDir: "/work/repo", WorkspaceMode: "clone"}, DirtyState{}, nil),
			want: ErrNonGitWorktree,
		},
		{
			name: "dirty",
			err:  planningError(ErrDirtyWorktree, Request{ProjectDir: "/work/repo", WorkspaceMode: "clone"}, DirtyState{Staged: true}, nil),
			want: ErrDirtyWorktree,
		},
		{
			name: "direct opt in",
			err:  planningError(ErrDirectOptInRequired, Request{ProjectDir: "/work/repo", WorkspaceMode: "direct"}, DirtyState{}, nil),
			want: ErrDirectOptInRequired,
		},
		{
			name: "active direct lock",
			err:  planningError(ErrDirectLockActive, Request{ResourceKey: "workspace:/work/repo"}, DirtyState{}, nil),
			want: ErrDirectLockActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.want) {
				t.Fatalf("errors.Is(%v, %v) = false", tt.err, tt.want)
			}
		})
	}
}

func TestDirtyPlanningErrorPreservesDirtyState(t *testing.T) {
	dirty := DirtyState{Staged: true, Unstaged: true, Untracked: true}
	err := planningError(ErrDirtyWorktree, Request{ProjectDir: "/work/repo", WorkspaceMode: "clone"}, dirty, nil)

	var planningErr *PlanningError
	if !errors.As(err, &planningErr) {
		t.Fatalf("errors.As(%T) = false", planningErr)
	}
	if planningErr.Dirty != dirty {
		t.Fatalf("Dirty = %#v, want %#v", planningErr.Dirty, dirty)
	}
}
