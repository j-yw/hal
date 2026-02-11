package cloud

import (
	"strings"
	"testing"
)

func TestArtifactGroupIsValid(t *testing.T) {
	tests := []struct {
		name  string
		group ArtifactGroup
		want  bool
	}{
		{name: "state is valid", group: ArtifactGroupState, want: true},
		{name: "reports is valid", group: ArtifactGroupReports, want: true},
		{name: "all is valid", group: ArtifactGroupAll, want: true},
		{name: "empty is invalid", group: "", want: false},
		{name: "unknown is invalid", group: "logs", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.group.IsValid(); got != tt.want {
				t.Errorf("ArtifactGroup(%q).IsValid() = %v, want %v", tt.group, got, tt.want)
			}
		})
	}
}

func TestArtifactGroupPatterns(t *testing.T) {
	tests := []struct {
		name      string
		group     ArtifactGroup
		wantErr   string
		wantPaths []string // subset of paths expected
		wantGroup ArtifactGroup
	}{
		{
			name:      "state returns state patterns",
			group:     ArtifactGroupState,
			wantPaths: []string{".hal/prd.json", ".hal/progress.txt", ".hal/auto-state.json"},
			wantGroup: ArtifactGroupState,
		},
		{
			name:      "reports returns report patterns",
			group:     ArtifactGroupReports,
			wantPaths: []string{".hal/reports/**"},
			wantGroup: ArtifactGroupReports,
		},
		{
			name:      "all returns both state and report patterns",
			group:     ArtifactGroupAll,
			wantPaths: []string{".hal/prd.json", ".hal/reports/**"},
		},
		{
			name:    "invalid group returns error",
			group:   "logs",
			wantErr: "is not valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns, err := ArtifactGroupPatterns(tt.group)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			pathSet := make(map[string]bool, len(patterns))
			for _, p := range patterns {
				pathSet[p.Path] = true
			}
			for _, want := range tt.wantPaths {
				if !pathSet[want] {
					t.Errorf("expected path %q in patterns, got %v", want, pathSet)
				}
			}
			if tt.wantGroup != "" {
				for _, p := range patterns {
					if p.Group != tt.wantGroup {
						t.Errorf("pattern %q has group %q, want %q", p.Path, p.Group, tt.wantGroup)
					}
				}
			}
		})
	}
}

func TestArtifactGroupPatternsAllContainsBoth(t *testing.T) {
	all, err := ArtifactGroupPatterns(ArtifactGroupAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasState := false
	hasReports := false
	for _, p := range all {
		if p.Group == ArtifactGroupState {
			hasState = true
		}
		if p.Group == ArtifactGroupReports {
			hasReports = true
		}
	}
	if !hasState {
		t.Error("all patterns should include state group")
	}
	if !hasReports {
		t.Error("all patterns should include reports group")
	}
}

func TestWorkflowArtifactGroups(t *testing.T) {
	tests := []struct {
		name        string
		kind        WorkflowKind
		wantGroups  []ArtifactGroup
		wantReports bool
	}{
		{
			name:        "run includes only state",
			kind:        WorkflowKindRun,
			wantGroups:  []ArtifactGroup{ArtifactGroupState},
			wantReports: false,
		},
		{
			name:        "auto includes state and reports",
			kind:        WorkflowKindAuto,
			wantGroups:  []ArtifactGroup{ArtifactGroupState, ArtifactGroupReports},
			wantReports: true,
		},
		{
			name:        "review includes state and reports",
			kind:        WorkflowKindReview,
			wantGroups:  []ArtifactGroup{ArtifactGroupState, ArtifactGroupReports},
			wantReports: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := WorkflowArtifactGroups(tt.kind)
			if len(groups) != len(tt.wantGroups) {
				t.Fatalf("WorkflowArtifactGroups(%q) returned %d groups, want %d", tt.kind, len(groups), len(tt.wantGroups))
			}
			groupSet := make(map[ArtifactGroup]bool, len(groups))
			for _, g := range groups {
				groupSet[g] = true
			}
			for _, want := range tt.wantGroups {
				if !groupSet[want] {
					t.Errorf("expected group %q for workflow %q, got %v", want, tt.kind, groups)
				}
			}
			hasReports := groupSet[ArtifactGroupReports]
			if hasReports != tt.wantReports {
				t.Errorf("workflow %q hasReports=%v, want %v", tt.kind, hasReports, tt.wantReports)
			}
		})
	}
}

func TestWorkflowDefaultArtifactPatterns(t *testing.T) {
	tests := []struct {
		name        string
		kind        WorkflowKind
		wantState   bool
		wantReports bool
	}{
		{name: "run has state only", kind: WorkflowKindRun, wantState: true, wantReports: false},
		{name: "auto has state and reports", kind: WorkflowKindAuto, wantState: true, wantReports: true},
		{name: "review has state and reports", kind: WorkflowKindReview, wantState: true, wantReports: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := WorkflowDefaultArtifactPatterns(tt.kind)
			hasState := false
			hasReports := false
			for _, p := range patterns {
				if p.Group == ArtifactGroupState {
					hasState = true
				}
				if p.Group == ArtifactGroupReports {
					hasReports = true
				}
			}
			if hasState != tt.wantState {
				t.Errorf("workflow %q hasState=%v, want %v", tt.kind, hasState, tt.wantState)
			}
			if hasReports != tt.wantReports {
				t.Errorf("workflow %q hasReports=%v, want %v", tt.kind, hasReports, tt.wantReports)
			}
		})
	}
}

func TestNewArtifactMetadata(t *testing.T) {
	tests := []struct {
		name       string
		kind       WorkflowKind
		wantGroups int
		wantValid  bool
	}{
		{name: "run metadata", kind: WorkflowKindRun, wantGroups: 1, wantValid: true},
		{name: "auto metadata", kind: WorkflowKindAuto, wantGroups: 2, wantValid: true},
		{name: "review metadata", kind: WorkflowKindReview, wantGroups: 2, wantValid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := NewArtifactMetadata(tt.kind)
			if len(meta.Groups) != tt.wantGroups {
				t.Errorf("NewArtifactMetadata(%q) has %d groups, want %d", tt.kind, len(meta.Groups), tt.wantGroups)
			}
			if len(meta.Patterns) == 0 {
				t.Error("expected at least one pattern")
			}
			if err := meta.Validate(); (err == nil) != tt.wantValid {
				t.Errorf("Validate() error = %v, wantValid = %v", err, tt.wantValid)
			}
		})
	}
}

func TestArtifactMetadataValidate(t *testing.T) {
	tests := []struct {
		name    string
		meta    *ArtifactMetadata
		wantErr string
	}{
		{
			name:    "empty groups",
			meta:    &ArtifactMetadata{Groups: nil, Patterns: nil},
			wantErr: "groups must not be empty",
		},
		{
			name: "invalid group value",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{"invalid"},
				Patterns: nil,
			},
			wantErr: "is not a concrete group",
		},
		{
			name: "all is not a concrete group",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{ArtifactGroupAll},
				Patterns: nil,
			},
			wantErr: "is not a concrete group",
		},
		{
			name: "duplicate group",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{ArtifactGroupState, ArtifactGroupState},
				Patterns: nil,
			},
			wantErr: "duplicate",
		},
		{
			name: "pattern with empty path",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{ArtifactGroupState},
				Patterns: []ArtifactPathPattern{{Path: "", Group: ArtifactGroupState}},
			},
			wantErr: "path must not be empty",
		},
		{
			name: "pattern with group not in groups list",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{ArtifactGroupState},
				Patterns: []ArtifactPathPattern{{Path: ".hal/reports/**", Group: ArtifactGroupReports}},
			},
			wantErr: "is not listed in groups",
		},
		{
			name: "valid state-only metadata",
			meta: &ArtifactMetadata{
				Groups:   []ArtifactGroup{ArtifactGroupState},
				Patterns: []ArtifactPathPattern{{Path: ".hal/prd.json", Group: ArtifactGroupState}},
			},
		},
		{
			name: "valid state+reports metadata",
			meta: &ArtifactMetadata{
				Groups: []ArtifactGroup{ArtifactGroupState, ArtifactGroupReports},
				Patterns: []ArtifactPathPattern{
					{Path: ".hal/prd.json", Group: ArtifactGroupState},
					{Path: ".hal/reports/**", Group: ArtifactGroupReports},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.meta.Validate()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestArtifactMetadataSelectPatterns(t *testing.T) {
	meta := NewArtifactMetadata(WorkflowKindAuto)

	tests := []struct {
		name      string
		group     ArtifactGroup
		wantErr   string
		wantState bool
		wantRpt   bool
	}{
		{
			name:      "select state",
			group:     ArtifactGroupState,
			wantState: true,
			wantRpt:   false,
		},
		{
			name:      "select reports",
			group:     ArtifactGroupReports,
			wantState: false,
			wantRpt:   true,
		},
		{
			name:      "select all",
			group:     ArtifactGroupAll,
			wantState: true,
			wantRpt:   true,
		},
		{
			name:    "invalid group",
			group:   "logs",
			wantErr: "is not valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns, err := meta.SelectPatterns(tt.group)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			hasState := false
			hasReports := false
			for _, p := range patterns {
				if p.Group == ArtifactGroupState {
					hasState = true
				}
				if p.Group == ArtifactGroupReports {
					hasReports = true
				}
			}
			if hasState != tt.wantState {
				t.Errorf("select %q hasState=%v, want %v", tt.group, hasState, tt.wantState)
			}
			if hasReports != tt.wantRpt {
				t.Errorf("select %q hasReports=%v, want %v", tt.group, hasReports, tt.wantRpt)
			}
		})
	}
}

func TestSelectPatternsRunWorkflow(t *testing.T) {
	// Run workflow only has state — selecting reports should return empty.
	meta := NewArtifactMetadata(WorkflowKindRun)

	statePatterns, err := meta.SelectPatterns(ArtifactGroupState)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(statePatterns) == 0 {
		t.Error("run workflow should have state patterns")
	}

	reportPatterns, err := meta.SelectPatterns(ArtifactGroupReports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reportPatterns) != 0 {
		t.Errorf("run workflow should have no report patterns, got %d", len(reportPatterns))
	}
}

func TestArtifactMetadataSerializationRoundTrip(t *testing.T) {
	// Verify that all three workflow kinds produce valid, consistent metadata.
	for _, kind := range []WorkflowKind{WorkflowKindRun, WorkflowKindAuto, WorkflowKindReview} {
		t.Run(string(kind), func(t *testing.T) {
			meta := NewArtifactMetadata(kind)
			if err := meta.Validate(); err != nil {
				t.Fatalf("NewArtifactMetadata(%q) produced invalid metadata: %v", kind, err)
			}

			// Verify all patterns reference groups that are in the groups list
			groupSet := make(map[ArtifactGroup]bool, len(meta.Groups))
			for _, g := range meta.Groups {
				groupSet[g] = true
			}
			for _, p := range meta.Patterns {
				if !groupSet[p.Group] {
					t.Errorf("pattern %q references group %q not in groups list %v", p.Path, p.Group, meta.Groups)
				}
			}

			// Verify state patterns are always present
			statePatterns, _ := meta.SelectPatterns(ArtifactGroupState)
			if len(statePatterns) == 0 {
				t.Errorf("workflow %q should always have state patterns", kind)
			}
		})
	}
}

func TestStatePatternsIncludeBundleAllowlist(t *testing.T) {
	// Verify that every BundleAllowlist path is covered by a state pattern.
	// State patterns may include additional paths (e.g., auto-state.json)
	// that are produced during execution but not uploaded as input.
	patterns, _ := ArtifactGroupPatterns(ArtifactGroupState)
	patternSet := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		patternSet[p.Path] = true
	}

	for _, allowed := range BundleAllowlist {
		if !patternSet[allowed] {
			t.Errorf("BundleAllowlist path %q is not covered by state patterns", allowed)
		}
	}
}

func TestReportPatternsExcludedFromBundleAllowlist(t *testing.T) {
	// Reports are in BundleDenylist (not uploaded as input) but are valid output artifacts.
	patterns, _ := ArtifactGroupPatterns(ArtifactGroupReports)
	denySet := make(map[string]bool, len(BundleDenylist))
	for _, p := range BundleDenylist {
		denySet[p] = true
	}

	for _, p := range patterns {
		if !denySet[p.Path] {
			t.Errorf("report pattern %q should be in BundleDenylist (reports are output-only, not input)", p.Path)
		}
	}
}

func TestMatchesArtifactPatterns(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		patterns []ArtifactPathPattern
		want     bool
	}{
		{
			name:     "exact match state file",
			filePath: ".hal/prd.json",
			patterns: statePatterns,
			want:     true,
		},
		{
			name:     "exact match progress file",
			filePath: ".hal/progress.txt",
			patterns: statePatterns,
			want:     true,
		},
		{
			name:     "glob match standards subdir",
			filePath: ".hal/standards/coding.md",
			patterns: statePatterns,
			want:     true,
		},
		{
			name:     "report file not in state patterns",
			filePath: ".hal/reports/review.html",
			patterns: statePatterns,
			want:     false,
		},
		{
			name:     "report file matches report patterns",
			filePath: ".hal/reports/review.html",
			patterns: reportPatterns,
			want:     true,
		},
		{
			name:     "nested report file matches report patterns",
			filePath: ".hal/reports/2026/jan/review.html",
			patterns: reportPatterns,
			want:     true,
		},
		{
			name:     "state file not in report patterns",
			filePath: ".hal/prd.json",
			patterns: reportPatterns,
			want:     false,
		},
		{
			name:     "unknown file matches no patterns",
			filePath: ".hal/unknown.txt",
			patterns: statePatterns,
			want:     false,
		},
		{
			name:     "empty patterns matches nothing",
			filePath: ".hal/prd.json",
			patterns: nil,
			want:     false,
		},
		{
			name:     "all patterns match state file",
			filePath: ".hal/prd.json",
			patterns: append(statePatterns, reportPatterns...),
			want:     true,
		},
		{
			name:     "all patterns match report file",
			filePath: ".hal/reports/review.html",
			patterns: append(statePatterns, reportPatterns...),
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesArtifactPatterns(tt.filePath, tt.patterns)
			if got != tt.want {
				t.Errorf("MatchesArtifactPatterns(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}
