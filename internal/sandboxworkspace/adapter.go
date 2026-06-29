package sandboxworkspace

import "github.com/jywlabs/hal/internal/sandbox"

// ToSandboxWorkspace maps a workspace plan to durable sandbox workspace
// metadata.
func ToSandboxWorkspace(plan Plan) sandbox.SandboxWorkspace {
	return sandbox.SandboxWorkspace{
		Mode:        plan.Mode,
		InputSource: plan.InputSource,
		Repo:        plan.Repository,
		Branch:      plan.Branch,
		SyncRef:     plan.SyncRef,
	}
}
