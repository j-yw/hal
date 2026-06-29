package sandboxworkspace

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestToSandboxWorkspaceMapsPlanMetadata(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
		want sandbox.SandboxWorkspace
	}{
		{
			name: "clone remote ref",
			plan: Plan{
				Mode:        sandbox.SandboxWorkspaceModeClone,
				InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
				Repository:  "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     "refs/remotes/origin/phase/workspace",
			},
			want: sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeClone,
				InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
				Repo:        "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     "refs/remotes/origin/phase/workspace",
			},
		},
		{
			name: "clone git bundle",
			plan: Plan{
				Mode:        sandbox.SandboxWorkspaceModeClone,
				InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
				Repository:  "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     "abc123",
			},
			want: sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeClone,
				InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
				Repo:        "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     "abc123",
			},
		},
		{
			name: "copy",
			plan: Plan{
				Mode:        sandbox.SandboxWorkspaceModeCopy,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repository:  "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     workingTreeSyncRef,
			},
			want: sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeCopy,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repo:        "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     workingTreeSyncRef,
			},
		},
		{
			name: "direct",
			plan: Plan{
				Mode:        sandbox.SandboxWorkspaceModeDirect,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repository:  "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     workingTreeSyncRef,
			},
			want: sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeDirect,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repo:        "git@github.com:jywlabs/hal.git",
				Branch:      "phase/workspace",
				SyncRef:     workingTreeSyncRef,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToSandboxWorkspace(tt.plan)
			if got != tt.want {
				t.Fatalf("ToSandboxWorkspace() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
