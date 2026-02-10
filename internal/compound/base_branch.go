package compound

import "strings"

// ResolveBaseBranch resolves the effective base branch.
// Priority:
//  1. Explicit --base value (trimmed)
//  2. Current branch lookup
//  3. Empty string fallback (treated as current HEAD by git)
//
// Lookup failures are treated as best-effort fallback so dry-run and detached
// HEAD flows can continue. A warning can be emitted via warnf.
func ResolveBaseBranch(baseFlag string, currentBranchFn func() (string, error), warnf func(string, ...any)) string {
	baseBranch := strings.TrimSpace(baseFlag)
	if baseBranch != "" {
		return baseBranch
	}

	if currentBranchFn == nil {
		currentBranchFn = CurrentBranchOptional
	}

	baseBranch, err := currentBranchFn()
	if err != nil {
		if warnf != nil {
			warnf("   Note: could not determine current branch; defaulting to current HEAD\n")
		}
		return ""
	}

	return strings.TrimSpace(baseBranch)
}
