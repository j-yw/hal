package cloud

import "fmt"

// ArtifactGroup identifies a category of cloud run artifacts for pull selection.
type ArtifactGroup string

const (
	ArtifactGroupState   ArtifactGroup = "state"
	ArtifactGroupReports ArtifactGroup = "reports"
	ArtifactGroupAll     ArtifactGroup = "all"
)

// validArtifactGroups is the exhaustive set of allowed artifact groups.
var validArtifactGroups = map[ArtifactGroup]bool{
	ArtifactGroupState:   true,
	ArtifactGroupReports: true,
	ArtifactGroupAll:     true,
}

// IsValid reports whether g is one of the allowed artifact groups.
func (g ArtifactGroup) IsValid() bool {
	return validArtifactGroups[g]
}

// ArtifactPathPattern describes a file path pattern within a cloud run snapshot.
// Patterns ending with /** are recursive globs; otherwise they are exact matches
// relative to the .hal directory.
type ArtifactPathPattern struct {
	Path  string        `json:"path"`
	Group ArtifactGroup `json:"group"`
}

// statePatterns are the .hal paths that form continuation state — needed to resume a run.
var statePatterns = []ArtifactPathPattern{
	{Path: ".hal/prd.json", Group: ArtifactGroupState},
	{Path: ".hal/auto-prd.json", Group: ArtifactGroupState},
	{Path: ".hal/progress.txt", Group: ArtifactGroupState},
	{Path: ".hal/auto-state.json", Group: ArtifactGroupState},
	{Path: ".hal/prompt.md", Group: ArtifactGroupState},
	{Path: ".hal/config.yaml", Group: ArtifactGroupState},
	{Path: ".hal/standards/**", Group: ArtifactGroupState},
}

// reportPatterns are the .hal paths that contain output reports.
var reportPatterns = []ArtifactPathPattern{
	{Path: ".hal/reports/**", Group: ArtifactGroupReports},
}

// ArtifactGroupPatterns returns the set of path patterns that belong to the
// requested artifact group. For ArtifactGroupAll it returns both state and
// report patterns.
func ArtifactGroupPatterns(group ArtifactGroup) ([]ArtifactPathPattern, error) {
	switch group {
	case ArtifactGroupState:
		return statePatterns, nil
	case ArtifactGroupReports:
		return reportPatterns, nil
	case ArtifactGroupAll:
		all := make([]ArtifactPathPattern, 0, len(statePatterns)+len(reportPatterns))
		all = append(all, statePatterns...)
		all = append(all, reportPatterns...)
		return all, nil
	default:
		return nil, fmt.Errorf("artifact group %q is not valid; allowed values: state, reports, all", group)
	}
}

// WorkflowArtifactGroups returns the default artifact groups produced by a
// given workflow kind. All workflows produce state artifacts. Auto and review
// workflows additionally produce report artifacts.
func WorkflowArtifactGroups(kind WorkflowKind) []ArtifactGroup {
	switch kind {
	case WorkflowKindAuto, WorkflowKindReview:
		return []ArtifactGroup{ArtifactGroupState, ArtifactGroupReports}
	default:
		return []ArtifactGroup{ArtifactGroupState}
	}
}

// WorkflowDefaultArtifactPatterns returns the combined path patterns for all
// artifact groups produced by the given workflow kind.
func WorkflowDefaultArtifactPatterns(kind WorkflowKind) []ArtifactPathPattern {
	groups := WorkflowArtifactGroups(kind)
	var patterns []ArtifactPathPattern
	for _, g := range groups {
		p, _ := ArtifactGroupPatterns(g)
		patterns = append(patterns, p...)
	}
	return patterns
}

// ArtifactMetadata holds the artifact group classification persisted with a
// cloud run so that pull operations know which files to fetch.
type ArtifactMetadata struct {
	// Groups lists which artifact groups this run produces.
	Groups []ArtifactGroup `json:"groups"`
	// Patterns lists every path pattern with its group classification.
	Patterns []ArtifactPathPattern `json:"patterns"`
}

// Validate checks that the metadata contains at least one group and all groups
// are valid.
func (m *ArtifactMetadata) Validate() error {
	if len(m.Groups) == 0 {
		return fmt.Errorf("artifact_metadata.groups must not be empty")
	}
	seen := make(map[ArtifactGroup]bool, len(m.Groups))
	for i, g := range m.Groups {
		if !g.IsValid() || g == ArtifactGroupAll {
			return fmt.Errorf("artifact_metadata.groups[%d] %q is not a concrete group; allowed: state, reports", i, g)
		}
		if seen[g] {
			return fmt.Errorf("artifact_metadata.groups contains duplicate %q", g)
		}
		seen[g] = true
	}
	for i, p := range m.Patterns {
		if p.Path == "" {
			return fmt.Errorf("artifact_metadata.patterns[%d].path must not be empty", i)
		}
		if !p.Group.IsValid() || p.Group == ArtifactGroupAll {
			return fmt.Errorf("artifact_metadata.patterns[%d].group %q is not a concrete group", i, p.Group)
		}
		if !seen[p.Group] {
			return fmt.Errorf("artifact_metadata.patterns[%d].group %q is not listed in groups", i, p.Group)
		}
	}
	return nil
}

// NewArtifactMetadata builds ArtifactMetadata for the given workflow kind
// using the default group and pattern definitions.
func NewArtifactMetadata(kind WorkflowKind) *ArtifactMetadata {
	groups := WorkflowArtifactGroups(kind)
	patterns := WorkflowDefaultArtifactPatterns(kind)
	return &ArtifactMetadata{
		Groups:   groups,
		Patterns: patterns,
	}
}

// SelectPatterns returns the patterns from the metadata that match the requested
// artifact group. For ArtifactGroupAll it returns all patterns.
func (m *ArtifactMetadata) SelectPatterns(group ArtifactGroup) ([]ArtifactPathPattern, error) {
	if !group.IsValid() {
		return nil, fmt.Errorf("artifact group %q is not valid; allowed values: state, reports, all", group)
	}
	if group == ArtifactGroupAll {
		return m.Patterns, nil
	}
	var selected []ArtifactPathPattern
	for _, p := range m.Patterns {
		if p.Group == group {
			selected = append(selected, p)
		}
	}
	return selected, nil
}
