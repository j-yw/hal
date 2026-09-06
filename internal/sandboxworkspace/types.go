package sandboxworkspace

// Request describes a workspace planning request.
type Request struct {
	ProjectDir        string
	WorkspaceMode     string
	DirectOptIn       bool
	PreferredBranch   string
	PreferredUpstream string
	ResourceKey       string
}

// Plan describes how a future sandbox runtime should materialize a workspace.
// It is a planning contract only; it does not perform clone, copy, mount, or
// artifact recovery work.
type Plan struct {
	Mode           string
	InputSource    string
	ProjectDir     string
	Repository     string
	Branch         string
	Upstream       string
	SyncRef        string
	RequiresBundle bool
	Dirty          DirtyState
	ResourceKey    string
}

// DirtyState summarizes local worktree changes relevant to workspace planning.
type DirtyState struct {
	Staged    bool
	Unstaged  bool
	Untracked bool
}

// Any reports whether any dirty state is present.
func (s DirtyState) Any() bool {
	return s.Staged || s.Unstaged || s.Untracked
}

// GitStatus is the normalized Git inspection result consumed by Planner.
type GitStatus struct {
	IsGitWorktree           bool
	Repository              string
	Branch                  string
	Upstream                string
	UpstreamRef             string
	HeadRef                 string
	HeadContainedInUpstream bool
	Dirty                   DirtyState
	RawStatusLines          []string
}
