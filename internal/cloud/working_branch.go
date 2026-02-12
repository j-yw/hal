package cloud

import "fmt"

// WorkingBranchPrefix is the prefix for cloud working branches.
const WorkingBranchPrefix = "hal/cloud/"

// WorkingBranch returns the deterministic working branch name for a run.
// The branch name is derived from the run ID so it is unique and stable
// across retry attempts: hal/cloud/<runID>.
func WorkingBranch(runID string) string {
	return fmt.Sprintf("%s%s", WorkingBranchPrefix, runID)
}
