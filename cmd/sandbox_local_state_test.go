package cmd

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestSandboxStateMatchesTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		local  *sandbox.SandboxState
		target *sandbox.SandboxState
		want   bool
	}{
		{
			name: "matches on stable sandbox id",
			local: &sandbox.SandboxState{
				ID:   "sandbox-123",
				Name: "main",
			},
			target: &sandbox.SandboxState{
				ID:   "sandbox-123",
				Name: "other-name",
			},
			want: true,
		},
		{
			name: "falls back to repo scoped name when ids differ",
			local: &sandbox.SandboxState{
				ID:          "sandbox-local",
				WorkspaceID: "ws-local",
				Name:        "main",
				Repo:        "github.com/example/repo-a",
			},
			target: &sandbox.SandboxState{
				ID:          "sandbox-target",
				WorkspaceID: "ws-target",
				Name:        "main",
				Repo:        "github.com/example/repo-a",
			},
			want: true,
		},
		{
			name: "matches by repo scoped name only when no stronger ids exist",
			local: &sandbox.SandboxState{
				Name: "main",
				Repo: "github.com/example/repo-a",
			},
			target: &sandbox.SandboxState{
				Name: "main",
				Repo: "github.com/example/repo-a",
			},
			want: true,
		},
		{
			name: "does not match name only across repos",
			local: &sandbox.SandboxState{
				Name: "main",
				Repo: "github.com/example/repo-a",
			},
			target: &sandbox.SandboxState{
				Name: "main",
				Repo: "github.com/example/repo-b",
			},
			want: false,
		},
		{
			name: "matches by name when repos are unavailable",
			local: &sandbox.SandboxState{
				ID:          "sandbox-local",
				WorkspaceID: "ws-local",
				Name:        "main",
			},
			target: &sandbox.SandboxState{
				ID:          "sandbox-target",
				WorkspaceID: "ws-target",
				Name:        "main",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sandboxStateMatchesTarget(tt.local, tt.target); got != tt.want {
				t.Fatalf("sandboxStateMatchesTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}
