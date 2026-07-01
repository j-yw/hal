package sandboxworkspace

import (
	pathpkg "path"
	"path/filepath"
	"strings"
)

// SanitizeSyncOutSummary returns a copy of summary with command-facing sync-out
// metadata constrained to safe identifiers, messages, and relative paths.
func SanitizeSyncOutSummary(summary SyncOutSummary) SyncOutSummary {
	summary.Workspace.Mode = sanitizeSyncOutText(summary.Workspace.Mode)
	summary.Workspace.InputSource = sanitizeSyncOutText(summary.Workspace.InputSource)
	summary.Workspace.Branch = sanitizeSyncOutText(summary.Workspace.Branch)
	summary.Workspace.SyncRef = sanitizeSyncOutText(summary.Workspace.SyncRef)

	summary.Committed.Patch = sanitizeSyncOutArtifactPtr(summary.Committed.Patch)
	summary.Committed.Bundle = sanitizeSyncOutArtifactPtr(summary.Committed.Bundle)
	summary.Uncommitted.Diff = sanitizeSyncOutArtifactPtr(summary.Uncommitted.Diff)
	summary.Untracked.Archive = sanitizeSyncOutArtifactPtr(summary.Untracked.Archive)
	summary.Untracked.List = sanitizeSyncOutArtifactPtr(summary.Untracked.List)
	summary.CoreArtifacts = sanitizeSyncOutArtifacts(summary.CoreArtifacts)
	summary.Recovery.Artifacts = sanitizeSyncOutArtifacts(summary.Recovery.Artifacts)
	summary.Warnings = sanitizeSyncOutWarnings(summary.Warnings)
	summary.Apply.ArtifactID = sanitizeSyncOutIdentifier(summary.Apply.ArtifactID)
	summary.Apply.Reasons = append([]SyncOutApplyEligibilityReason(nil), summary.Apply.Reasons...)
	return summary
}

// SanitizeSafeApplyResult returns a copy of result safe for manifests, JSON, and
// human-facing handoff output.
func SanitizeSafeApplyResult(result SafeApplyResult) SafeApplyResult {
	result.ArtifactID = sanitizeSyncOutIdentifier(result.ArtifactID)
	result.DisplayName = sanitizeSyncOutText(result.DisplayName)
	result.DisplayPath = sanitizeSyncOutDisplayPath(result.DisplayPath)
	result.Reasons = append([]SyncOutApplyEligibilityReason(nil), result.Reasons...)
	result.Warnings = sanitizeSyncOutWarnings(result.Warnings)
	result.HandoffInstructions = sanitizeSyncOutHandoffInstructions(result.HandoffInstructions)
	return result
}

func sanitizeSyncOutArtifactPtr(artifact *SyncOutArtifact) *SyncOutArtifact {
	if artifact == nil {
		return nil
	}
	sanitized := sanitizeSyncOutArtifact(*artifact)
	return &sanitized
}

func sanitizeSyncOutArtifacts(artifacts []SyncOutArtifact) []SyncOutArtifact {
	if len(artifacts) == 0 {
		return nil
	}
	sanitized := make([]SyncOutArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		sanitized = append(sanitized, sanitizeSyncOutArtifact(artifact))
	}
	return sanitized
}

func sanitizeSyncOutArtifact(artifact SyncOutArtifact) SyncOutArtifact {
	artifact.ID = sanitizeSyncOutIdentifier(artifact.ID)
	artifact.DisplayName = sanitizeSyncOutText(artifact.DisplayName)
	artifact.DisplayPath = sanitizeSyncOutDisplayPath(artifact.DisplayPath)
	artifact.StoredPath = sanitizeSyncOutStorePath(artifact.StoredPath)
	if artifact.ApplyEligibility != nil {
		eligibility := *artifact.ApplyEligibility
		eligibility.Reasons = append([]SyncOutApplyEligibilityReason(nil), artifact.ApplyEligibility.Reasons...)
		artifact.ApplyEligibility = &eligibility
	}
	return artifact
}

func sanitizeSyncOutWarnings(warnings []SyncOutWarning) []SyncOutWarning {
	if len(warnings) == 0 {
		return nil
	}
	sanitized := make([]SyncOutWarning, 0, len(warnings))
	for _, warning := range warnings {
		warning.Code = sanitizeSyncOutIdentifier(warning.Code)
		warning.Message = sanitizeSyncOutText(warning.Message)
		warning.ArtifactID = sanitizeSyncOutIdentifier(warning.ArtifactID)
		sanitized = append(sanitized, warning)
	}
	return sanitized
}

func sanitizeSyncOutHandoffInstructions(instructions []SyncOutHandoffInstruction) []SyncOutHandoffInstruction {
	if len(instructions) == 0 {
		return nil
	}
	sanitized := make([]SyncOutHandoffInstruction, 0, len(instructions))
	for _, instruction := range instructions {
		instruction.Message = sanitizeSyncOutText(instruction.Message)
		if len(instruction.Artifacts) > 0 {
			artifacts := make([]SyncOutHandoffArtifactRef, 0, len(instruction.Artifacts))
			for _, artifact := range instruction.Artifacts {
				artifact.ID = sanitizeSyncOutIdentifier(artifact.ID)
				artifact.DisplayName = sanitizeSyncOutText(artifact.DisplayName)
				artifact.DisplayPath = sanitizeSyncOutDisplayPath(artifact.DisplayPath)
				if artifact.ID != "" || artifact.DisplayName != "" || artifact.DisplayPath != "" {
					artifacts = append(artifacts, artifact)
				}
			}
			instruction.Artifacts = artifacts
		}
		sanitized = append(sanitized, instruction)
	}
	return sanitized
}

func sanitizeSyncOutIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || syncOutUnsafeRelativeFragment(value) {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return ""
		}
	}
	return value
}

func sanitizeSyncOutText(value string) string {
	return strings.TrimSpace(sanitizePathDetail(value))
}

func sanitizeSyncOutDisplayPath(value string) string {
	return sanitizeSyncOutRelativePath(value)
}

func sanitizeSyncOutStorePath(value string) string {
	return sanitizeSyncOutRelativePath(value)
}

func sanitizeSyncOutRelativePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || syncOutUnsafeRelativeFragment(value) || filepath.IsAbs(value) || pathpkg.IsAbs(value) || strings.Contains(value, "\\") {
		return ""
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return ""
		}
	}
	clean := pathpkg.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}

func syncOutUnsafeRelativeFragment(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"token=",
		"credential=",
		"api_key=",
		"apikey=",
		"access_token=",
		"client_secret=",
		"private_key=",
		"ghp_",
		"gho_",
		"ghu_",
		"ghs_",
		"ghr_",
		"sk-",
		"tskey-",
		"/tmp/",
		"/workspace/",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
