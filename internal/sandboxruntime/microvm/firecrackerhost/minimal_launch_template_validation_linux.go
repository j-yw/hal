//go:build linux

package firecrackerhost

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

func validMinimalTemplateAssociation(entry minimalTemplateAssociation) bool {
	if entry.scope.Revision == 0 || !sandboxruntime.ValidMinimalLaunchTemplateIdentity(entry.template) {
		return false
	}
	for _, id := range []string{entry.scope.PolicyID, entry.scope.PrincipalID, entry.scope.WorkerID, entry.scope.HostID, entry.scope.TemplatePolicyID, entry.scope.WorkspacePolicyID, entry.scope.NetworkPolicyID} {
		if !sandboxruntime.ValidMinimalLaunchID(id) {
			return false
		}
	}
	if len(entry.templateSource) > 4096 {
		return false
	}
	reference, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Ref: entry.templateSource})
	if err != nil || !minimalTemplateDigestMatches(reference.Reference.Digest, entry.template.TemplateManifestSHA256) ||
		reference.Reference.Ref+"@sha256:"+entry.template.TemplateManifestSHA256 != entry.templateSource {
		return false
	}
	for _, path := range []string{entry.bundleDir, entry.parentL7Dir} {
		if len(path) > 4096 || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return false
		}
	}
	if !minimalTemplateHex(entry.expected.SourceRevision, 40) {
		return false
	}
	for _, digest := range []string{entry.expected.RootfsSHA256, entry.expected.GuestInitSHA256, entry.expected.GuestAgentSHA256,
		entry.expected.SourceLockSHA256, entry.expected.FinalInspectionSHA256, entry.expected.ProvenanceSHA256,
		entry.expected.Runtime.NodeSHA256, entry.expected.Runtime.PiLauncherSHA256, entry.expected.Runtime.PiDependencyTreeSHA256} {
		if !minimalTemplateHex(digest, 64) {
			return false
		}
	}
	// Require complete bounded expected facts here; the genuine asset verifier
	// remains the authority for the supported runtime versions and package.
	for _, value := range []string{entry.expected.Runtime.NodeVersion, entry.expected.Runtime.PiPackage, entry.expected.Runtime.PiVersion} {
		if value == "" || len(value) > 128 || strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			return false
		}
	}
	return true
}

func validMinimalTemplateHints(hints sandboxruntime.MinimalLaunchSelectionHints, scope sandboxruntime.MinimalLaunchScope) bool {
	for _, id := range []string{hints.SandboxID, hints.ExecutionID, hints.SubmissionID, hints.RuntimeID, hints.PlanID, hints.TemplatePolicyID, hints.WorkspacePolicyID} {
		if !sandboxruntime.ValidMinimalLaunchID(id) {
			return false
		}
	}
	return hints.TemplatePolicyID == scope.TemplatePolicyID && hints.WorkspacePolicyID == scope.WorkspacePolicyID
}

func minimalTemplateSelectionMatches(result selection.Result, expected sandboxruntime.MinimalLaunchTemplateIdentity, hints sandboxruntime.MinimalLaunchSelectionHints) bool {
	if result.RuntimeDriver != "microvm" || result.IsolationLevel != "vm" || result.RuntimeImage != expected.RuntimeImage ||
		result.Trust.Mode != acquisition.TrustPolicyModeStrict || result.Trust.Decision != acquisition.TrustPolicyDecisionTrusted ||
		result.Trust.Enforcement == nil || !result.Trust.Enforcement.StrictlyEnforced || len(result.Trust.Errors) != 0 || len(result.Trust.Warnings) != 0 ||
		len(result.Lock.Warnings) != 0 || result.Lock.Document.Status != acquisition.LockStatusLocked ||
		!minimalTemplateDigestMatches(result.Lock.Document.Digest, expected.TemplateDocumentSHA256) ||
		!minimalTemplateDigestMatches(result.ManifestDigest, expected.TemplateManifestSHA256) {
		return false
	}
	manifestCount, imageCount := 0, 0
	for _, reference := range result.Lock.References {
		switch reference.Field {
		case "metadata.reference":
			manifestCount++
			if reference.Kind != sandboxtemplate.ReferenceKindOCIArtifact || reference.Status != acquisition.LockStatusLocked || !minimalTemplateDigestMatches(reference.Digest, expected.TemplateManifestSHA256) {
				return false
			}
		case "runtime.image":
			imageCount++
			if reference.Kind != sandboxtemplate.ReferenceKindOCIImage || reference.Status != acquisition.LockStatusLocked || !minimalTemplateDigestMatches(reference.Digest, expected.RuntimeImageSHA256) {
				return false
			}
		}
	}
	if manifestCount != 1 || imageCount != 1 {
		return false
	}
	_, err := selection.Bind(result, selection.BindingRequest{ExecutionID: hints.ExecutionID, SandboxID: hints.SandboxID, RuntimeID: hints.RuntimeID,
		RuntimeDriver: "microvm", IsolationLevel: "vm", RuntimeImage: expected.RuntimeImage, ManifestDigest: result.ManifestDigest})
	return err == nil
}

func minimalTemplateDigestMatches(digest *sandboxtemplate.DigestMetadata, expected string) bool {
	return digest != nil && digest.Algorithm == sandboxtemplate.DigestAlgorithmSHA256 && digest.Value == expected && minimalTemplateHex(expected, 64)
}

func minimalTemplateHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
