package sandboxworkspace

import "github.com/jywlabs/hal/internal/sandbox"

// ToSandboxWorkspace maps a workspace plan to durable sandbox workspace
// metadata.
func ToSandboxWorkspace(plan Plan) sandbox.SandboxWorkspace {
	result := NewMaterializationResult(plan, MaterializationDetails{})
	return SandboxWorkspaceFromMaterializationResult(result)
}

// SandboxWorkspaceFromMaterializationResult maps safe materialization metadata
// to the durable sandbox workspace manifest shape.
func SandboxWorkspaceFromMaterializationResult(result MaterializationResult) sandbox.SandboxWorkspace {
	return sandbox.SandboxWorkspace{
		Mode:        result.Mode,
		InputSource: result.InputSource,
		Repo:        result.Repository,
		Branch:      result.Branch,
		SyncRef:     result.SyncRef,
	}
}
