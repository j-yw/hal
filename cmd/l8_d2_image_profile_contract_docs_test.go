package cmd

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestL8D2ImageProfileContractClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	combined := seam + "\n" + architecture + "\n" + verification

	for _, required := range []string{
		"### L8 D2 image-profile concrete closure",
		`ImageProfileL8ProductionCredentials = "l8-production-credentials-v1"`,
		`L8GuestAgentProtocolV2 = "guest-agent-v2"`,
		`"copy_in", "copy_out", "credential_delivery_v2"`,
		`"exec", "readiness", "ssh_agent_relay_v1"`,
		"generic L5/L7 validator is not called on an L8 value",
		"manifest and provenance GuestAgent values must match exactly",
		"L8SourceLockSchemaVersionV1",
		"L8FinalInspectionSchemaVersionV1",
		"Node 22.22.0",
		"@earendil-works/pi-coding-agent 0.82.1",
		"type L8SourceLock struct",
		"type L8FinalInspection struct",
		"type L8ProcessCompositionFacts struct",
		"NodeSHA256",
		"PiLauncherSHA256",
		"4..4096 entries",
		"at most 4 MiB",
		"exactly these 22 records",
		"l8-production-credentials-image",
		"exactly seven regular files",
		"five metadata files is nonempty and at most 4 MiB",
		"`vmlinux` and `rootfs.ext4` is nonempty and at most 1 GiB",
		"an oversized installed file cannot force an unbounded digest pass",
		"final-inspection.json",
		"sources.lock.json",
		"parent L7 evidence fingerprint",
		`opaque16("hal/l8/image-profile/parent-l7-evidence/v1")`,
		`opaque16("hal/l8/image-profile/descriptor/v1")`,
		`opaque16("hal/l8/image-profile/evidence/v1")`,
		"evidence substitution",
		"ValidateL8DistributionManifest",
		"ValidateL8ProvenanceAgainstManifest",
		"ValidateL8SourceLock",
		"ValidateL8FinalInspection",
		"type L8ValidationError struct",
		"type L8LaunchMaterialWriter interface",
		"failure leaves writer",
		"ownership with the caller",
		"failed call does not consume the successful single-use latch",
		"Every `L8LaunchMaterialWriter` callback is panic-contained",
		"success atomically transfers writer ownership to the lease",
		"joins the sanitized",
		"close error with the primary error",
		`opaque16("hal/l8/pi-dependency-tree/v1")`,
		"uint32_be(npmArchiveCount)",
		"token(piPackage.kind)",
		"token(piPackage.filename)",
		"token(piShrinkwrap.kind)",
		"token(piShrinkwrap.filename)",
		"case-insensitive",
		"URL/credential-marker algorithm",
		"ASCII bytes permitted in a source filename",
		`"authorization", "bearer", "token", "secret"`,
		`"credential", "password"`,
		`"api_key", "apikey"`,
		`"access_key", "private_key"`,
		`"ghp_", "github_pat_"`,
		`"sk-"`,
		"schema_invalid",
		"correlation_mismatch",
		"first error in this exact precedence",
		"L8Profile() (VerifiedL8Profile, bool)",
		"type L8DistributionRequest struct",
		"ParentL7 VerifiedDistribution",
		"VerifyL8DistributionBundle(L8DistributionRequest)",
		"five-file L5/L7\nentry point and cannot issue L8 authority",
		"AcquireL8AssetLease",
		"PrepareLaunch",
		"evidence fingerprint is copied unchanged",
		"VerifiedL8ProfileMatches",
		"VerifiedL8ProfileMatchesLease",
		"same evidence fingerprint",
		"no public constructor or fingerprint accessor",
		"VerifiedL8Profile *localresolver.VerifiedL8Profile `json:\"-\"`",
		"VerifiedL8Assets *localresolver.VerifiedL8AssetLease `json:\"-\"`",
		"L7 and L8 profile/lease fields are mutually exclusive",
		"type L8LiveBootConfigRequest struct",
		"type L8LiveBootConfigOverlay struct",
		"type L8LiveBootConfigProvider interface",
		"ProvideL8LiveBootConfig(context.Context, L8LiveBootConfigRequest)",
		"L8LiveConfigProvider L8LiveBootConfigProvider",
		"provider retains ownership of every returned value",
		"ownership of every non-nil lease immediately transfers to Backend",
		"copies the opaque profile by value into Backend-owned storage",
		"provider must not mutate or access any nil-error output after return",
		"temporary parent L7 lease immediately after a successful",
		"blocks issuance because parent-handle absence",
		"confirms current assets before ownership of",
		"L8 lease transfers to Backend",
		"recursively deep-copies",
		"launch descriptor and every nested slice/pointer",
		"snapshots every caller-mutable safe field before validation",
		"per-marker production allowlist",
		"AST-level issuer identifier guard",
		"does not parse a source lock",
		"host profile never enters the guest",
		"one canonical HL8Q artifact and its external HL8E evidence",
		"WorkloadSnapshotSHA256",
		"RuntimeProfileSHA256",
		"PolicyArtifactSHA256",
		"PolicySourceLockSHA256",
		"PolicyBinaryBindingSetSHA256",
		"PinnedCallsiteEvidenceSHA256",
		"first two fields are immutable views derived from the sole HL8Q artifact",
		"Manifest, provenance, and final inspection carry all six fields in this exact",
		"the evidence fingerprint binds all six in the same exact order",
		"type verifiedL8PolicyAuthorityBindings struct",
		"policyAuthority verifiedL8PolicyAuthorityBindings",
		"measured rootfs image digest",
		"provenance, descriptor, and clean root directory",
		"PinnedCallsiteEvidence []byte",
		"non-nil, nonempty, and at most 16 MiB",
		"checks that bound before allocating the snapshot",
		"deep-snapshots `PinnedCallsiteEvidence` before hashing or import",
		"defer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)",
		"caller mutation cannot affect verification",
		"EmbeddedVerifiedPolicyArtifact",
		"EmbeddedExpectedPinnedCallsiteEvidence",
		"type l8VerifiedPolicyCompositionDigests struct",
		"func deriveL8PolicyCompositionDigests(",
		"artifact.Workload().SHA256()",
		"artifact.Runtime().SHA256()",
		"artifact.SHA256()",
		"artifact.SourceLockSHA256()",
		"evidence.BinaryBindings().SHA256()",
		"evidence.SHA256()",
		"func l8PolicyCompositionDigestsEqual(",
		"func validateL8PolicyCompositionCorrelation(",
		"manifest, provenance, and final-inspection `ProcessComposition`",
		"final inspection independently repeats the complete six-field equality",
		"manifest first, provenance second, and final inspection third",
		"mutates each of the six fields in each of the three documents",
		"retains no caller slice or imported evidence graph after sealing",
		"seven-file distribution remains unchanged",
		"D2 is schema, pure validation, opaque issuance/matching, guards, and fakes only",
		"D6 consumes only the opaque profile and lease",
		"D7 owns real source-lock contents, building, inspection, reproducibility, and live issuance",
		"L5 and L7 JSON bytes remain unchanged",
		"TestL8D2ImageProfile",
		"./internal/sandboxruntime/microvm/assets/build",
		"./internal/sandboxruntime/microvm/assets/localresolver",
		"./internal/sandboxruntime/microvm/firecracker",
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("L8 D2 image-profile contract omits normative marker %q", required)
		}
	}

	assertL8DocStruct(t, seam, "L8ProcessCompositionFacts", []l8DocField{
		{name: "CatalogVersion", typ: "string", tag: `json:"catalogVersion"`},
		{name: "GuestAgentSHA256", typ: "string", tag: `json:"guestAgentSha256"`},
		{name: "GuestInitSHA256", typ: "string", tag: `json:"guestInitSha256"`},
		{name: "CredentialHelperSHA256", typ: "string", tag: `json:"credentialHelperSha256"`},
		{name: "MountMonitorSHA256", typ: "string", tag: `json:"mountMonitorSha256"`},
		{name: "WorkloadShimSHA256", typ: "string", tag: `json:"workloadShimSha256"`},
		{name: "RoleBootstrapSHA256", typ: "string", tag: `json:"roleBootstrapSha256"`},
		{name: "HelperDescriptorSHA256", typ: "string", tag: `json:"helperDescriptorSha256"`},
		{name: "ClientDescriptorSHA256", typ: "string", tag: `json:"clientDescriptorSha256"`},
		{name: "CompositionSHA256", typ: "string", tag: `json:"compositionSha256"`},
		{name: "WorkloadSnapshotSHA256", typ: "string", tag: `json:"workloadSnapshotSha256"`},
		{name: "RuntimeProfileSHA256", typ: "string", tag: `json:"runtimeProfileSha256"`},
		{name: "PolicyArtifactSHA256", typ: "string", tag: `json:"policyArtifactSha256"`},
		{name: "PolicySourceLockSHA256", typ: "string", tag: `json:"policySourceLockSha256"`},
		{name: "PolicyBinaryBindingSetSHA256", typ: "string", tag: `json:"policyBinaryBindingSetSha256"`},
		{name: "PinnedCallsiteEvidenceSHA256", typ: "string", tag: `json:"pinnedCallsiteEvidenceSha256"`},
	})
	assertL8DocStruct(t, seam, "verifiedL8PolicyAuthorityBindings", []l8DocField{
		{name: "policyArtifactSHA256", typ: "[32]byte"},
		{name: "policySourceLockSHA256", typ: "[32]byte"},
		{name: "policyBinaryBindingSetSHA256", typ: "[32]byte"},
		{name: "pinnedCallsiteEvidenceSHA256", typ: "[32]byte"},
		{name: "imageSHA256", typ: "[32]byte"},
	})
	assertL8DocStruct(t, seam, "l8VerifiedPolicyCompositionDigests", []l8DocField{
		{name: "workloadSnapshotSHA256", typ: "[32]byte"},
		{name: "runtimeProfileSHA256", typ: "[32]byte"},
		{name: "policyArtifactSHA256", typ: "[32]byte"},
		{name: "policySourceLockSHA256", typ: "[32]byte"},
		{name: "policyBinaryBindingSetSHA256", typ: "[32]byte"},
		{name: "pinnedCallsiteEvidenceSHA256", typ: "[32]byte"},
	})
	assertL8DocStruct(t, seam, "verifiedL8ProfileCorrelation", []l8DocField{
		{name: "descriptorFingerprint", typ: "[32]byte"},
		{name: "evidenceFingerprint", typ: "[32]byte"},
		{name: "policyAuthority", typ: "verifiedL8PolicyAuthorityBindings"},
	})
	assertL8DocStruct(t, seam, "verifiedL8LeaseCorrelation", []l8DocField{
		{name: "sourceDescriptorFingerprint", typ: "[32]byte"},
		{name: "preparedDescriptorFingerprint", typ: "[32]byte"},
		{name: "hasPreparedDescriptor", typ: "bool"},
		{name: "evidenceFingerprint", typ: "[32]byte"},
		{name: "policyAuthority", typ: "verifiedL8PolicyAuthorityBindings"},
	})
	assertL8DocStruct(t, seam, "VerifiedL8Profile", []l8DocField{
		{name: "seal", typ: "verifiedL8ProfileSeal"},
		{name: "correlation", typ: "verifiedL8ProfileCorrelation"},
	})
	assertL8DocStruct(t, seam, "VerifiedL8AssetLease", []l8DocField{
		{name: "state", typ: "*verifiedL8AssetLeaseState"},
		{name: "correlation", typ: "verifiedL8LeaseCorrelation"},
	})
	assertL8DocStruct(t, seam, "L8DistributionRequest", []l8DocField{
		{name: "DistributionRequest", typ: "DistributionRequest"},
		{name: "ParentL7", typ: "VerifiedDistribution"},
		{name: "PinnedCallsiteEvidence", typ: "[]byte"},
	})
	if !strings.Contains(seam, "digest32(compositionSha256) || digest32(workloadSnapshotSha256) ||\n  digest32(runtimeProfileSha256) || digest32(policyArtifactSha256) ||\n  digest32(policySourceLockSha256) ||\n  digest32(policyBinaryBindingSetSha256) ||\n  digest32(pinnedCallsiteEvidenceSha256))") {
		t.Fatal("L8 evidence fingerprint does not bind the six policy/evidence fields in exact order")
	}

	for _, forbidden := range []string{
		"WorkloadPolicySHA256",
		"RuntimePolicySHA256",
		"SyscallPolicySHA256",
		"workloadPolicySha256",
		"runtimePolicySha256",
		"syscallPolicySha256",
		"three canonical artifacts",
		"D7 embeds the exact expected workload, runtime, and syscall-policy catalog digests",
		"The profile exposes only the safe",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("L8 image-profile contract retains superseded policy authority %q", forbidden)
		}
	}

	for _, required := range []string{
		"Profile/lease pair correlation",
		"same sealed evidence fingerprint",
		"L8LiveBootConfigProvider",
		"ownership-transferring live overlay",
		"post-start validation failure stops and reaps",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 architecture omits image-profile ownership marker %q", required)
		}
	}

	for _, required := range []string{
		"cross-bundle profile/lease substitution",
		"provider-error ownership retention",
		"post-return validation failure closes the lease exactly once",
		"post-start revalidation failure forces stop/reap",
	} {
		if !strings.Contains(verification, required) {
			t.Fatalf("L8 verification omits image-profile ownership marker %q", required)
		}
	}
}

func TestL8D2ImageProfilePolicyCompositionCorrelationIsExact(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	combined := seam + "\n" + architecture + "\n" + verification

	for _, required := range []string{
		"type l8VerifiedPolicyCompositionDigests struct",
		"workloadSnapshotSHA256       [32]byte",
		"runtimeProfileSHA256         [32]byte",
		"policyArtifactSHA256         [32]byte",
		"policySourceLockSHA256       [32]byte",
		"policyBinaryBindingSetSHA256 [32]byte",
		"pinnedCallsiteEvidenceSHA256 [32]byte",
		"artifact.Workload().SHA256()",
		"artifact.Runtime().SHA256()",
		"artifact.SHA256()",
		"artifact.SourceLockSHA256()",
		"evidence.BinaryBindings().SHA256()",
		"evidence.SHA256()",
		"crypto/subtle.ConstantTimeCompare",
		"manifest first, provenance second, and final inspection third",
		"final inspection independently repeats the complete six-field equality",
		"correlation_mismatch",
		"mutates each of the six fields in each of the three documents",
		"mere disconnected accessor or comparison marker calls do not satisfy",
		"func validateL8PolicyCompositionCorrelation(",
		"func l8PolicyCompositionCorrelationMismatch() error",
		"assetbuild.L8ValidationError",
		"func classifyL8PolicyCompositionCorrelationError(_ error) error",
		"public result is therefore exact resolver code `asset_lock_mismatch`",
		"localresolver/l8_distribution_verifier.go",
		"protected one-assignment values",
		"closed,\ncontiguous, ordered top-level authority block",
		"localresolver/l8_distribution_verifier_test.go",
		"function-local `[18]struct { document string; field string }`",
		"exact 3x6 table",
		"package-wide parsed production reference guard",
		"no basename-wide\nallowlist",
		"Same-file or alternate-\nfile helpers, wrappers, methods, closures, `defer`, `go`, function values",
		"executed count to equal exactly 18",
		"requires the real\n`VerifyL8DistributionBundle` to succeed before any mutation",
		"For each tuple a fresh request also must succeed through\nthe real verifier before mutation",
		"proves only the selected array index changed",
		"all other 17 fields remain identical",
		"all three non-policy document\nsemantic hashes remain identical",
		"closed\nauthority-owner graph",
		"recursive authority-containing named-type closure",
		"Exactly one all-build-context declaration",
		"single direct returned result",
		"package/global/interface/\nmap/slice/generic container/channel",
		"`go:linkname`",
		"every reference to the cases outside that exact\nlocal test body",
		"localresolver/l8_distribution_policy_composition_fixture_test.go",
		"runtime.Goexit",
		"selected-only, other-17",
		"partially\nlanded product stays fail-closed",
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("L8 policy-composition correlation closure omits %q", required)
		}
	}
}

func TestL8D2ImageProfilePolicyCompositionASTGuardRejectsMarkerBypasses(t *testing.T) {
	canonical := `package localresolver
import (
	"crypto/subtle"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)
type l8VerifiedPolicyCompositionDigests struct {
	workloadSnapshotSHA256 [32]byte
	runtimeProfileSHA256 [32]byte
	policyArtifactSHA256 [32]byte
	policySourceLockSHA256 [32]byte
	policyBinaryBindingSetSHA256 [32]byte
	pinnedCallsiteEvidenceSHA256 [32]byte
}
func deriveL8PolicyCompositionDigests(artifact syscallpolicy.VerifiedPolicyArtifact, evidence syscallpolicy.PinnedCallsiteEvidenceSet) l8VerifiedPolicyCompositionDigests {
	return l8VerifiedPolicyCompositionDigests{
		workloadSnapshotSHA256: artifact.Workload().SHA256(),
		runtimeProfileSHA256: artifact.Runtime().SHA256(),
		policyArtifactSHA256: artifact.SHA256(),
		policySourceLockSHA256: artifact.SourceLockSHA256(),
		policyBinaryBindingSetSHA256: evidence.BinaryBindings().SHA256(),
		pinnedCallsiteEvidenceSHA256: evidence.SHA256(),
	}
}
func l8PolicyCompositionDigestsEqual(left, right l8VerifiedPolicyCompositionDigests) bool {
	matches := 1
	matches &= subtle.ConstantTimeCompare(left.workloadSnapshotSHA256[:], right.workloadSnapshotSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.runtimeProfileSHA256[:], right.runtimeProfileSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policySourceLockSHA256[:], right.policySourceLockSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policyBinaryBindingSetSHA256[:], right.policyBinaryBindingSetSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.pinnedCallsiteEvidenceSHA256[:], right.pinnedCallsiteEvidenceSHA256[:])
	return matches == 1
}
func validateL8PolicyCompositionCorrelation(derived, manifest, provenance, finalInspection l8VerifiedPolicyCompositionDigests) error {
	if !l8PolicyCompositionDigestsEqual(derived, manifest) { return l8PolicyCompositionCorrelationMismatch() }
	if !l8PolicyCompositionDigestsEqual(derived, provenance) { return l8PolicyCompositionCorrelationMismatch() }
	if !l8PolicyCompositionDigestsEqual(derived, finalInspection) { return l8PolicyCompositionCorrelationMismatch() }
	return nil
}
func l8PolicyCompositionCorrelationMismatch() error {
	return &assetbuild.L8ValidationError{Code: assetbuild.L8ValidationCode("correlation_mismatch"), Field: "processComposition"}
}`
	if issues := l8D2PolicyCompositionASTIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical policy-composition correlation source rejected: %v", issues)
	}

	for name, mutate := range map[string]func(string) string{
		"reordered digest layout": func(source string) string {
			return strings.Replace(source,
				"workloadSnapshotSHA256 [32]byte\n\truntimeProfileSHA256 [32]byte",
				"runtimeProfileSHA256 [32]byte\n\tworkloadSnapshotSHA256 [32]byte", 1)
		},
		"reordered extraction": func(source string) string {
			return strings.Replace(source,
				"workloadSnapshotSHA256: artifact.Workload().SHA256(),\n\t\truntimeProfileSHA256: artifact.Runtime().SHA256(),",
				"runtimeProfileSHA256: artifact.Runtime().SHA256(),\n\t\tworkloadSnapshotSHA256: artifact.Workload().SHA256(),", 1)
		},
		"wrong extraction receiver": func(source string) string {
			return strings.Replace(source, "artifact.Workload().SHA256()", "artifact.SHA256()", 1)
		},
		"lookalike artifact type": func(source string) string {
			return strings.Replace(source, "syscallpolicy.VerifiedPolicyArtifact", "VerifiedPolicyArtifact", 1)
		},
		"extra import": func(source string) string {
			return strings.Replace(source, `"crypto/subtle"`, `"crypto/subtle"\n\t"fmt"`, 1)
		},
		"nil mismatch error": func(source string) string {
			return strings.Replace(source, `return &assetbuild.L8ValidationError{Code: assetbuild.L8ValidationCode("correlation_mismatch"), Field: "processComposition"}`, `return nil`, 1)
		},
		"disconnected accessor marker": func(source string) string {
			return strings.Replace(source,
				"return l8VerifiedPolicyCompositionDigests{\n\t\tworkloadSnapshotSHA256: artifact.Workload().SHA256(),",
				"artifact.Workload().SHA256()\n\treturn l8VerifiedPolicyCompositionDigests{\n\t\tworkloadSnapshotSHA256: artifact.SHA256(),", 1)
		},
		"ordinary digest equality": func(source string) string {
			return strings.Replace(source,
				"matches &= subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])",
				"if left.policyArtifactSHA256 == right.policyArtifactSHA256 { matches &= 1 }", 1)
		},
		"disconnected constant-time marker": func(source string) string {
			return strings.Replace(source,
				"matches &= subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])",
				"subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])\n\tmatches &= 1", 1)
		},
		"final compared to provenance": func(source string) string {
			return strings.Replace(source,
				"l8PolicyCompositionDigestsEqual(derived, finalInspection)",
				"l8PolicyCompositionDigestsEqual(provenance, finalInspection)", 1)
		},
		"reordered document comparisons": func(source string) string {
			return strings.Replace(source,
				"if !l8PolicyCompositionDigestsEqual(derived, manifest) { return l8PolicyCompositionCorrelationMismatch() }\n\tif !l8PolicyCompositionDigestsEqual(derived, provenance) { return l8PolicyCompositionCorrelationMismatch() }",
				"if !l8PolicyCompositionDigestsEqual(derived, provenance) { return l8PolicyCompositionCorrelationMismatch() }\n\tif !l8PolicyCompositionDigestsEqual(derived, manifest) { return l8PolicyCompositionCorrelationMismatch() }", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if issues := l8D2PolicyCompositionASTIssues(mutate(canonical)); len(issues) == 0 {
				t.Fatal("policy-composition AST guard accepted seeded bypass")
			}
		})
	}

	correlationPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "l8_policy_composition_correlation.go")
	payload, err := os.ReadFile(correlationPath)
	if err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		productRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "syscallpolicy")
		if _, productErr := os.Stat(productRoot); productErr == nil {
			t.Fatal("syscallpolicy product exists without exact localresolver policy-composition correlation file")
		} else if !os.IsNotExist(productErr) {
			t.Fatal(productErr)
		}
		return
	}
	if issues := l8D2PolicyCompositionASTIssues(string(payload)); len(issues) != 0 {
		t.Fatalf("production policy-composition correlation source violates closure: %v", issues)
	}
}

func TestL8D2ImageProfilePolicyCompositionIssuerASTGuardRejectsBypasses(t *testing.T) {
	canonical := `package localresolver
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func VerifyL8DistributionBundle(request L8DistributionRequest) (VerifiedDistribution, error) {
	manifest, err := decodeL8DistributionManifest(request.DistributionRequest)
	if err != nil { return VerifiedDistribution{}, classifyL8DistributionManifestError(err) }
	provenance, err := decodeL8Provenance(request.DistributionRequest)
	if err != nil { return VerifiedDistribution{}, classifyL8ProvenanceError(err) }
	sourceLock, err := decodeL8SourceLock(request.DistributionRequest)
	if err != nil { return VerifiedDistribution{}, classifyL8SourceLockError(err) }
	finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)
	if err != nil { return VerifiedDistribution{}, classifyL8FinalInspectionError(err) }
	descriptor, rootDir, parentL7EvidenceSHA256, err := validateL8BundleState(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, request.ParentL7)
	if err != nil { return VerifiedDistribution{}, classifyL8BundleStateError(err) }
	pinnedCallsiteEvidenceBytes, err := snapshotL8PinnedCallsiteEvidence(request.PinnedCallsiteEvidence)
	if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }
	defer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)
	artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()
	if err != nil { return VerifiedDistribution{}, classifyL8PolicyArtifactError(err) }
	expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()
	if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceExpectationError(err) }
	evidence, err := syscallpolicy.ImportPinnedCallsiteEvidence(pinnedCallsiteEvidenceBytes, artifact, expectedEvidence)
	if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }
	manifestPolicyComposition, err := decodeL8PolicyCompositionDigests(manifest.L8Profile.ProcessComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
	provenancePolicyComposition, err := decodeL8PolicyCompositionDigests(provenance.L8Profile.ProcessComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
	finalInspectionPolicyComposition, err := decodeL8PolicyCompositionDigests(finalInspection.ProcessComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
	derivedPolicyComposition := deriveL8PolicyCompositionDigests(artifact, evidence)
	if err := validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition); err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionCorrelationError(err)
	}
	evidenceFingerprint, imageSHA256, err := buildL8EvidenceFingerprint(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, derivedPolicyComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8EvidenceFingerprintError(err) }
	descriptorFingerprint, err := buildL8DescriptorFingerprint(descriptor)
	if err != nil { return VerifiedDistribution{}, classifyL8ProfileSealError(err) }
	verifiedL8Profile, err := sealVerifiedL8Profile(descriptorFingerprint, evidenceFingerprint, imageSHA256, derivedPolicyComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8ProfileSealError(err) }
	return sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil
}
func snapshotL8PinnedCallsiteEvidence(source []byte) ([]byte, error) {
	if len(source) == 0 || len(source) > l8MaxPinnedEvidenceBytes { return nil, ErrAssetLockMismatch }
	return append([]byte(nil), source...), nil
}
func classifyL8PolicyCompositionCorrelationError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "processComposition", "", "L8 policy composition correlation mismatch", ErrAssetLockMismatch)
}`
	if issues := l8D2PolicyCompositionIssuerASTIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical policy-composition issuer source rejected: %v", issues)
	}

	validation := `if err := validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition); err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionCorrelationError(err)
	}`
	fingerprint := `evidenceFingerprint, imageSHA256, err := buildL8EvidenceFingerprint(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, derivedPolicyComposition)
	if err != nil { return VerifiedDistribution{}, classifyL8EvidenceFingerprintError(err) }`
	for name, mutated := range map[string]string{
		"dead helper":                   strings.Replace(canonical, "func VerifyL8DistributionBundle", "func deadVerifyL8DistributionBundle", 1),
		"discarded validation error":    strings.Replace(canonical, validation, "_ = validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition)", 1),
		"validation after issuance":     strings.Replace(canonical, validation+"\n\t"+fingerprint, fingerprint+"\n\t"+validation, 1),
		"aliased document":              strings.Replace(canonical, "manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition", "manifestPolicyComposition, provenancePolicyComposition, provenancePolicyComposition", 1),
		"lookalike artifact":            strings.Replace(canonical, "deriveL8PolicyCompositionDigests(artifact, evidence)", "deriveL8PolicyCompositionDigests(otherArtifact, evidence)", 1),
		"wrong imported evidence":       strings.Replace(canonical, "deriveL8PolicyCompositionDigests(artifact, evidence)", "deriveL8PolicyCompositionDigests(artifact, otherEvidence)", 1),
		"wrong expected evidence":       strings.Replace(canonical, "pinnedCallsiteEvidenceBytes, artifact, expectedEvidence", "pinnedCallsiteEvidenceBytes, artifact, otherExpectedEvidence", 1),
		"unbounded evidence snapshot":   strings.Replace(canonical, "snapshotL8PinnedCallsiteEvidence(request.PinnedCallsiteEvidence)", "append([]byte(nil), request.PinnedCallsiteEvidence...)", 1),
		"unchecked evidence snapshot":   strings.Replace(canonical, "if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }\n\tdefer wipeL8PinnedEvidence", "defer wipeL8PinnedEvidence", 1),
		"uncopied evidence import":      strings.Replace(canonical, "ImportPinnedCallsiteEvidence(pinnedCallsiteEvidenceBytes, artifact", "ImportPinnedCallsiteEvidence(request.PinnedCallsiteEvidence, artifact", 1),
		"unwiped evidence copy":         strings.Replace(canonical, "\tdefer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)\n", "", 1),
		"aliased decoded source":        strings.Replace(canonical, "finalInspection.ProcessComposition", "provenance.L8Profile.ProcessComposition", 1),
		"protected reassignment":        strings.Replace(canonical, "derivedPolicyComposition :=", "artifact = otherArtifact\n\tderivedPolicyComposition :=", 1),
		"early successful issuance":     strings.Replace(canonical, validation, "if ready { return sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil }\n\t"+validation, 1),
		"unreachable validation":        strings.Replace(canonical, validation, "if false {\n\t\t"+validation+"\n\t}", 1),
		"noncontrolling validation":     strings.Replace(canonical, validation, "if err := validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition); err != nil { _ = err }", 1),
		"unsafe correlation classifier": strings.Replace(canonical, `return newResolverError(ErrorCodeAssetLockMismatch, "processComposition", "", "L8 policy composition correlation mismatch", ErrAssetLockMismatch)`, `return err`, 1),
		"prevalidation function value":  strings.Replace(canonical, validation, "issueEarly := sealVerifiedL8Profile\n\t_ = issueEarly\n\t"+validation, 1),
		"exact-name lookalike":          strings.Replace(canonical, "sealVerifiedL8Profile(descriptorFingerprint", "sealVerifiedL8ProfileLookalike(descriptorFingerprint", 1),
		"trailing unreachable return":   strings.Replace(canonical, "\treturn sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil\n}", "\treturn sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil\n\treturn VerifiedDistribution{}, nil\n}", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if issues := l8D2PolicyCompositionIssuerASTIssues(mutated); len(issues) == 0 {
				t.Fatal("policy-composition issuer AST guard accepted seeded bypass")
			}
		})
	}
	l8D2CheckPolicyCompositionProductTopology(t)
}

func TestL8D2ImageProfilePolicyCompositionMutationMatrixASTGuardRejectsBypasses(t *testing.T) {
	canonical := `package localresolver
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)
func TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations(t *testing.T) {
	baseline := validL8DistributionRequest(t)
	if _, err := VerifyL8DistributionBundle(baseline); err != nil { t.Fatalf("valid L8 baseline rejected: %v", err) }
	l8PolicyCompositionMutationCases := [18]struct { document string; field string }{
	{document: "manifest", field: "workloadSnapshotSha256"},
	{document: "manifest", field: "runtimeProfileSha256"},
	{document: "manifest", field: "policyArtifactSha256"},
	{document: "manifest", field: "policySourceLockSha256"},
	{document: "manifest", field: "policyBinaryBindingSetSha256"},
	{document: "manifest", field: "pinnedCallsiteEvidenceSha256"},
	{document: "provenance", field: "workloadSnapshotSha256"},
	{document: "provenance", field: "runtimeProfileSha256"},
	{document: "provenance", field: "policyArtifactSha256"},
	{document: "provenance", field: "policySourceLockSha256"},
	{document: "provenance", field: "policyBinaryBindingSetSha256"},
	{document: "provenance", field: "pinnedCallsiteEvidenceSha256"},
	{document: "finalInspection", field: "workloadSnapshotSha256"},
	{document: "finalInspection", field: "runtimeProfileSha256"},
	{document: "finalInspection", field: "policyArtifactSha256"},
	{document: "finalInspection", field: "policySourceLockSha256"},
	{document: "finalInspection", field: "policyBinaryBindingSetSha256"},
	{document: "finalInspection", field: "pinnedCallsiteEvidenceSha256"},
	}
	executed := 0
	for mutationIndex, mutation := range l8PolicyCompositionMutationCases {
		t.Run(mutation.document+"/"+mutation.field, func(t *testing.T) {
			request := validL8DistributionRequest(t)
			if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("valid per-case L8 baseline rejected: %v", err) }
			before, beforeNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			mutateL8PolicyCompositionFixture(t, &request, mutation.document, mutation.field)
			after, afterNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			assertExactlyOneL8PolicyCompositionFieldChanged(t, before, after, beforeNonPolicy, afterNonPolicy, mutationIndex)
			_, err := VerifyL8DistributionBundle(request)
			assertL8PolicyCompositionCorrelationMismatch(t, err)
			executed++
		})
	}
	if executed != 18 { t.Fatalf("executed %d policy-composition mutations, want 18", executed) }
}
func validL8DistributionRequest(t *testing.T) L8DistributionRequest {
	t.Helper()
	return materializeValidL8DistributionRequestFixture(t)
}
func mutateL8PolicyCompositionFixture(t *testing.T, request *L8DistributionRequest, document, field string) {
	t.Helper()
	if err := replaceL8DistributionPolicyCompositionField(request.DistributionRequest, document, field, "0101010101010101010101010101010101010101010101010101010101010101"); err != nil { t.Fatalf("mutate L8 policy composition: %v", err) }
}
func snapshotL8PolicyCompositionFields(t *testing.T, request L8DistributionRequest) ([18]string, [3][32]byte) {
	t.Helper()
	manifest, err := decodeL8DistributionManifest(request.DistributionRequest)
	if err != nil { t.Fatalf("decode L8 manifest snapshot: %v", err) }
	provenance, err := decodeL8Provenance(request.DistributionRequest)
	if err != nil { t.Fatalf("decode L8 provenance snapshot: %v", err) }
	finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)
	if err != nil { t.Fatalf("decode L8 final-inspection snapshot: %v", err) }
	fields := [18]string{
		manifest.L8Profile.ProcessComposition.WorkloadSnapshotSHA256, manifest.L8Profile.ProcessComposition.RuntimeProfileSHA256, manifest.L8Profile.ProcessComposition.PolicyArtifactSHA256, manifest.L8Profile.ProcessComposition.PolicySourceLockSHA256, manifest.L8Profile.ProcessComposition.PolicyBinaryBindingSetSHA256, manifest.L8Profile.ProcessComposition.PinnedCallsiteEvidenceSHA256,
		provenance.L8Profile.ProcessComposition.WorkloadSnapshotSHA256, provenance.L8Profile.ProcessComposition.RuntimeProfileSHA256, provenance.L8Profile.ProcessComposition.PolicyArtifactSHA256, provenance.L8Profile.ProcessComposition.PolicySourceLockSHA256, provenance.L8Profile.ProcessComposition.PolicyBinaryBindingSetSHA256, provenance.L8Profile.ProcessComposition.PinnedCallsiteEvidenceSHA256,
		finalInspection.ProcessComposition.WorkloadSnapshotSHA256, finalInspection.ProcessComposition.RuntimeProfileSHA256, finalInspection.ProcessComposition.PolicyArtifactSHA256, finalInspection.ProcessComposition.PolicySourceLockSHA256, finalInspection.ProcessComposition.PolicyBinaryBindingSetSHA256, finalInspection.ProcessComposition.PinnedCallsiteEvidenceSHA256,
	}
	manifest.L8Profile.ProcessComposition = L8ProcessCompositionFacts{}
	provenance.L8Profile.ProcessComposition = L8ProcessCompositionFacts{}
	finalInspection.ProcessComposition = L8ProcessCompositionFacts{}
	nonPolicy := [3][32]byte{
		canonicalL8NonPolicyDocumentSHA256(t, manifest),
		canonicalL8NonPolicyDocumentSHA256(t, provenance),
		canonicalL8NonPolicyDocumentSHA256(t, finalInspection),
	}
	return fields, nonPolicy
}
func canonicalL8NonPolicyDocumentSHA256(t *testing.T, value any) [32]byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil { t.Fatalf("canonicalize non-policy L8 document: %v", err) }
	return sha256.Sum256(encoded)
}
func assertExactlyOneL8PolicyCompositionFieldChanged(t *testing.T, before, after [18]string, beforeNonPolicy, afterNonPolicy [3][32]byte, selected int) {
	t.Helper()
	if beforeNonPolicy != afterNonPolicy { t.Fatal("non-policy L8 document semantics changed") }
	for index := range before {
		if index == selected {
			if before[index] == after[index] { t.Fatal("selected policy-composition field did not change") }
			if after[index] != "0101010101010101010101010101010101010101010101010101010101010101" { t.Fatal("selected policy-composition field is not the exact valid replacement digest") }
			continue
		}
		if before[index] != after[index] { t.Fatal("non-selected policy-composition field changed") }
	}
}
func assertL8PolicyCompositionCorrelationMismatch(t *testing.T, err error) {
	t.Helper()
	var resolverError *Error
	if !errors.As(err, &resolverError) { t.Fatal("missing typed resolver error") }
	if resolverError.Code != ErrorCodeAssetLockMismatch || resolverError.Field != "processComposition" || resolverError.Role != "" || resolverError.Message != "L8 policy composition correlation mismatch" { t.Fatal("unexpected resolver error") }
	if !errors.Is(err, ErrAssetLockMismatch) { t.Fatal("missing asset-lock sentinel") }
	if err.Error() != "local asset resolver failed (asset_lock_mismatch) field=processComposition: L8 policy composition correlation mismatch" { t.Fatal("unsafe resolver error text") }
}`
	if issues := l8D2PolicyCompositionMutationASTIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical policy-composition mutation source rejected: %v", issues)
	}
	for name, mutated := range map[string]string{
		"comment markers only":      strings.Replace(canonical, "l8PolicyCompositionMutationCases := [18]struct", "// l8PolicyCompositionMutationCases := [18]struct\n\tdeadPolicyCompositionMutationCases := [18]struct", 1),
		"string markers only":       strings.Replace(canonical, "l8PolicyCompositionMutationCases := [18]struct", "_ = `l8PolicyCompositionMutationCases := [18]struct`\n\tdeadPolicyCompositionMutationCases := [18]struct", 1),
		"dead table":                strings.Replace(canonical, "range l8PolicyCompositionMutationCases", "range deadPolicyCompositionMutationCases", 1),
		"duplicate tuple":           strings.Replace(canonical, `{document: "finalInspection", field: "pinnedCallsiteEvidenceSha256"}`, `{document: "finalInspection", field: "policyBinaryBindingSetSha256"}`, 1),
		"missing tuple":             strings.Replace(canonical, "\t{document: \"finalInspection\", field: \"pinnedCallsiteEvidenceSha256\"},\n", "", 1),
		"wrong field driver":        strings.Replace(canonical, "mutation.document, mutation.field)", `mutation.document, "policyArtifactSha256")`, 1),
		"no issuer call":            strings.Replace(canonical, "VerifyL8DistributionBundle(request)", "deadVerifyL8DistributionBundle(request)", 1),
		"invalid baseline":          strings.Replace(canonical, "VerifyL8DistributionBundle(baseline)", "deadVerifyL8DistributionBundle(baseline)", 1),
		"ignored baseline err":      strings.Replace(canonical, `if _, err := VerifyL8DistributionBundle(baseline); err != nil { t.Fatalf("valid L8 baseline rejected: %v", err) }`, `_, _ = VerifyL8DistributionBundle(baseline)`, 1),
		"no-op mutator":             strings.Replace(canonical, `if err := replaceL8DistributionPolicyCompositionField(request.DistributionRequest, document, field, "0101010101010101010101010101010101010101010101010101010101010101"); err != nil { t.Fatalf("mutate L8 policy composition: %v", err) }`, `_ = request; _ = document; _ = field`, 1),
		"fixed-field mutator":       strings.Replace(canonical, "request.DistributionRequest, document, field,", `request.DistributionRequest, "manifest", "policyArtifactSha256",`, 1),
		"alternate mutator":         strings.Replace(canonical, "mutateL8PolicyCompositionFixture(t, &request", "alternateMutationFixture(t, &request", 1),
		"lying snapshot":            strings.Replace(canonical, "manifest.L8Profile.ProcessComposition.WorkloadSnapshotSHA256", `"synthetic"`, 1),
		"missing per-case baseline": strings.Replace(canonical, `if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("valid per-case L8 baseline rejected: %v", err) }`, `_, _ = VerifyL8DistributionBundle(request)`, 1),
		"missing change proof":      strings.Replace(canonical, "assertExactlyOneL8PolicyCompositionFieldChanged(t, before, after, beforeNonPolicy, afterNonPolicy, mutationIndex)", `_ = before; _ = after; _ = beforeNonPolicy; _ = afterNonPolicy`, 1),
		"wrong selected index":      strings.Replace(canonical, "beforeNonPolicy, afterNonPolicy, mutationIndex)", "beforeNonPolicy, afterNonPolicy, 0)", 1),
		"missing non-policy proof":  strings.Replace(canonical, `if beforeNonPolicy != afterNonPolicy { t.Fatal("non-policy L8 document semantics changed") }`, `_ = beforeNonPolicy; _ = afterNonPolicy`, 1),
		"unsafe assertion":          strings.Replace(canonical, `resolverError.Field != "processComposition"`, `resolverError.Field != "other"`, 1),
		"zero executed":             strings.Replace(canonical, "executed++", "executed += 0", 1),
		"skipped case":              strings.Replace(canonical, "request := validL8DistributionRequest(t)", "if mutation.field == \"runtimeProfileSha256\" { t.SkipNow() }\n\t\t\trequest := validL8DistributionRequest(t)", 1),
		"continued case":            strings.Replace(canonical, "t.Run(mutation.document", "if mutation.field == \"runtimeProfileSha256\" { continue }\n\t\tt.Run(mutation.document", 1),
		"cleared local array":       strings.Replace(canonical, "executed := 0", "l8PolicyCompositionMutationCases = [18]struct { document string; field string }{}\n\texecuted := 0", 1),
		"weak executed check":       strings.Replace(canonical, "executed != 18", "executed < 1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if issues := l8D2PolicyCompositionMutationASTIssues(mutated); len(issues) == 0 {
				t.Fatal("policy-composition mutation AST guard accepted seeded bypass")
			}
		})
	}
}

func TestL8D2ImageProfilePolicyCompositionExternalReferenceGuardRejectsBypasses(t *testing.T) {
	for name, fixture := range map[string]struct {
		path   string
		source string
	}{
		"direct profile seal": {
			path:   "l8_authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{seal: verifiedL8ProfileSeal{}, correlation: verifiedL8ProfileCorrelation{descriptorFingerprint: descriptorFingerprint, evidenceFingerprint: evidenceFingerprint, policyAuthority: verifiedL8PolicyAuthorityBindings{policyArtifactSHA256: policyComposition.policyArtifactSHA256, imageSHA256: imageSHA256}}}, nil }`,
		},
		"direct distribution seal": {
			path:   "l8_authority.go",
			source: `package localresolver; func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, descriptor assets.LaunchDescriptor, rootDir string) VerifiedDistribution { return VerifiedDistribution{l8Profile: profile} }`,
		},
		"direct lease acquisition": {
			path:   "l8_authority.go",
			source: `package localresolver; func (distribution VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error) { return &VerifiedL8AssetLease{state: &verifiedL8AssetLeaseState{}, correlation: verifiedL8LeaseCorrelation{}}, nil }`,
		},
	} {
		t.Run("accept_"+name, func(t *testing.T) {
			if issues := l8D2PolicyCompositionExternalReferenceIssues(fixture.path, fixture.source); len(issues) != 0 {
				t.Fatalf("policy-composition authority guard rejected exact direct-return topology: %v", issues)
			}
		})
	}
	for name, fixture := range map[string]struct {
		path   string
		source string
	}{
		"external authority wrapper": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly() { sealVerifiedL8Profile(fingerprint, composition) }`,
		},
		"external mutation table reassignment": {
			path:   "alternate_test.go",
			source: `package localresolver; func init() { l8PolicyCompositionMutationCases = nil }`,
		},
		"same-file helper": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func extraIssuer() { sealVerifiedL8Profile(fingerprint, composition) }`,
		},
		"same-file wrapper": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper() { extraIssuer() }; func extraIssuer() { sealVerifiedL8Distribution(profile, fingerprint, composition) }`,
		},
		"same-file method wrapper": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; type issuer struct{}; func (*issuer) issue() { sealVerifiedL8Profile(fingerprint, composition) }`,
		},
		"function alias": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func alias() { issue := sealVerifiedL8Profile; _ = issue }`,
		},
		"method value": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func methodValue(distribution VerifiedDistribution) { acquire := distribution.AcquireL8AssetLease; _ = acquire }`,
		},
		"iife": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper() { func() { sealVerifiedL8Profile(fingerprint, composition) }() }`,
		},
		"lease mint": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper() { mintVerifiedL8AssetLease(profile) }`,
		},
		"exact-name shadow": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper(sealVerifiedL8Profile func()) { sealVerifiedL8Profile() }`,
		},
		"deferred seal": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper() { defer sealVerifiedL8Profile(fingerprint, composition) }`,
		},
		"goroutine seal": {
			path:   "l8_distribution_verifier.go",
			source: `package localresolver; func wrapper() { go sealVerifiedL8Distribution(profile, fingerprint, composition) }`,
		},
		"package function value": {
			path:   "alternate.go",
			source: `package localresolver; var alternateIssuer = sealVerifiedL8Distribution`,
		},
		"package authority literal": {
			path:   "alternate.go",
			source: `package localresolver; var alternateProfile = VerifiedL8Profile{seal: seal}`,
		},
		"designated sealer global cache": {
			path:   "authority.go",
			source: `package localresolver; var cachedProfile VerifiedL8Profile; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { cachedProfile = VerifiedL8Profile{seal: verifiedL8ProfileSeal{}}; return cachedProfile, nil }`,
		},
		"designated sealer escaped factory": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (func() VerifiedL8Profile, error) { profile := VerifiedL8Profile{seal: verifiedL8ProfileSeal{}}; return func() VerifiedL8Profile { return profile }, nil }`,
		},
		"designated sealer staged private fields": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { correlation := verifiedL8ProfileCorrelation{policyAuthority: verifiedL8PolicyAuthorityBindings{}}; profile := VerifiedL8Profile{correlation: correlation}; return profile, nil }`,
		},
		"designated sealer interface escape": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { var escaped any = VerifiedL8Profile{seal: verifiedL8ProfileSeal{}}; _ = escaped; return VerifiedL8Profile{}, nil }`,
		},
		"designated sealer container escape": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { escaped := map[string]VerifiedL8Profile{"x": {}}; _ = escaped; return VerifiedL8Profile{}, nil }`,
		},
		"designated sealer slice escape": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { escaped := []VerifiedL8Profile{{}}; _ = escaped; return VerifiedL8Profile{}, nil }`,
		},
		"designated sealer channel escape": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { escaped := make(chan VerifiedL8Profile, 1); escaped <- VerifiedL8Profile{}; return VerifiedL8Profile{}, nil }`,
		},
		"designated sealer helper escape": {
			path:   "authority.go",
			source: `package localresolver; func sealVerifiedL8Profile(fingerprint [32]byte, composition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return cacheProfile(VerifiedL8Profile{}), nil }`,
		},
		"alternate getter": {
			path:   "alternate.go",
			source: `package localresolver; func GetVerifiedL8Profile() VerifiedL8Profile { return VerifiedL8Profile{} }`,
		},
		"closure capture": {
			path:   "alternate.go",
			source: `package localresolver; func leak(profile VerifiedL8Profile) func() { return func() { _ = profile } }`,
		},
		"pointer alias": {
			path:   "alternate.go",
			source: `package localresolver; func leak(profile *VerifiedL8Profile) any { alias := profile; return alias }`,
		},
		"generic container": {
			path:   "alternate.go",
			source: `package localresolver; type box[T any] struct{ value T }; var escaped = box[VerifiedL8Profile]{}`,
		},
		"prepare launch": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly(distribution VerifiedDistribution) { distribution.PrepareLaunch() }`,
		},
		"alternate profile constructor": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly() { constructVerifiedL8Profile() }`,
		},
		"direct authority literal": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly() VerifiedL8Profile { return VerifiedL8Profile{sealed: true} }`,
		},
		"authority type alias": {
			path:   "alternate.go",
			source: `package localresolver; type bypassProfile = VerifiedL8Profile`,
		},
		"authority derived type": {
			path:   "alternate.go",
			source: `package localresolver; type bypassProfile VerifiedL8Profile`,
		},
		"authority conversion": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly(value bypassProfile) VerifiedL8Profile { return VerifiedL8Profile(value) }`,
		},
		"zero profile literal": {
			path:   "alternate.go",
			source: `package localresolver; func issueEarly() VerifiedL8Profile { return VerifiedL8Profile{} }`,
		},
		"equivalent issue API": {
			path:   "alternate.go",
			source: `package localresolver; func issueVerifiedL8AssetLease() {}`,
		},
		"wrong receiver lease construction": {
			path:   "alternate.go",
			source: `package localresolver; type bypassDistribution struct{}; func (bypassDistribution) AcquireL8AssetLease() *VerifiedL8AssetLease { return &VerifiedL8AssetLease{state: state} }`,
		},
		"designated acquirer factory return": {
			path:   "authority.go",
			source: `package localresolver; func (distribution VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error) { return buildLease(), nil }`,
		},
		"authority receiver helper escape": {
			path:   "authority.go",
			source: `package localresolver; func VerifiedL8ProfileMatches(profile, other VerifiedL8Profile) bool { profile.cache(); return true }`,
		},
		"authority matcher interface return": {
			path:   "authority.go",
			source: `package localresolver; func VerifiedL8ProfileMatches(profile, other VerifiedL8Profile) any { return profile }`,
		},
		"nested authority selector escape": {
			path:   "authority.go",
			source: `package localresolver; type authorityBox struct { profile VerifiedL8Profile }; func leak(box authorityBox) any { return box.profile }`,
		},
		"recursive authority selector escape": {
			path:   "authority.go",
			source: `package localresolver; type authorityInner struct { lease *VerifiedL8AssetLease }; type authorityOuter struct { inner authorityInner }; func leak(box authorityOuter) any { return box.inner.lease }`,
		},
		"nested authority copy escape": {
			path:   "authority.go",
			source: `package localresolver; type authorityBox struct { profile VerifiedL8Profile }; func leak(box authorityBox) { copied := box.profile; _ = copied }`,
		},
		"nested authority helper escape": {
			path:   "authority.go",
			source: `package localresolver; type authorityBox struct { profile VerifiedL8Profile }; func leak(box authorityBox) { arbitrary(box.profile) }`,
		},
		"nested authority accessor escape": {
			path:   "authority.go",
			source: `package localresolver; type authorityBox struct { profile VerifiedL8Profile }; func leak(box authorityBox) authorityBox { return box }`,
		},
		"linkname alias init": {
			path: "alternate_test.go",
			source: `package localresolver
import _ "unsafe"
//go:linkname mutationAlias l8PolicyCompositionMutationCases
var mutationAlias [18]struct { document string; field string }
func init() { mutationAlias = [18]struct { document string; field string }{} }`,
		},
		"unsafe alias": {
			path:   "alternate_test.go",
			source: `package localresolver; import "unsafe"; func mutate() { _ = unsafe.Pointer(&l8PolicyCompositionMutationCases) }`,
		},
		"test skip function value": {
			path:   "alternate_test.go",
			source: `package localresolver; import "testing"; func bypass(t *testing.T) { skip := t.SkipNow; skip() }`,
		},
		"reflection alias": {
			path:   "alternate_test.go",
			source: `package localresolver; import "reflect"; func mutate() { _ = reflect.ValueOf(l8PolicyCompositionMutationCases) }`,
		},
		"assembly alias": {
			path:   "mutation_alias.s",
			source: `TEXT mutationAlias(SB),$0-0`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if issues := l8D2PolicyCompositionExternalReferenceIssues(fixture.path, fixture.source); len(issues) == 0 {
				t.Fatal("policy-composition external-reference guard accepted seeded bypass")
			}
		})
	}
}

func TestL8D2ImageProfilePolicyCompositionPackageTopologyRejectsBuildContextDuplicates(t *testing.T) {
	canonical := map[string]string{
		"l8_authority.go": `package localresolver
func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }
func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, descriptor assets.LaunchDescriptor, rootDir string) VerifiedDistribution { return VerifiedDistribution{} }
func (distribution VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error) { return &VerifiedL8AssetLease{}, nil }`,
	}
	if issues := l8D2PolicyCompositionPackageDeclarationIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical package authority declarations rejected: %v", issues)
	}
	for name, extra := range map[string]string{
		"build-tagged profile sealer": `//go:build alternate
package localresolver
func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }`,
		"build-tagged distribution sealer": `//go:build alternate
package localresolver
func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, descriptor assets.LaunchDescriptor, rootDir string) VerifiedDistribution { return VerifiedDistribution{} }`,
		"build-tagged lease acquirer": `//go:build alternate
package localresolver
func (distribution VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error) { return &VerifiedL8AssetLease{}, nil }`,
	} {
		t.Run(name, func(t *testing.T) {
			mutated := map[string]string{"l8_authority.go": canonical["l8_authority.go"], "alternate_l8_authority.go": extra}
			if !l8D2PolicyCompositionSourcesContainPartialLanding(map[string]string{"alternate_l8_authority.go": extra}) {
				t.Fatal("partial-landing detector ignored a build-context authority declaration")
			}
			if issues := l8D2PolicyCompositionPackageDeclarationIssues(mutated); len(issues) == 0 {
				t.Fatal("package authority declaration guard accepted a build-context duplicate")
			}
		})
	}
}

func TestL8D2ImageProfileSealerRequiresMeasuredImageDigest(t *testing.T) {
	t.Helper()
	parseSealer := func(source string) *ast.FuncDecl {
		file, err := parser.ParseFile(token.NewFileSet(), "l8_profile.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		return l8D2TopLevelFunction(file, "sealVerifiedL8Profile")
	}

	withImage := parseSealer(`package localresolver
func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }`)
	if !l8D2PolicyCompositionAuthorityDefinitionAllowed(withImage) {
		t.Fatal("profile sealer cannot receive the independently measured rootfs digest")
	}

	withoutImage := parseSealer(`package localresolver
func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }`)
	if l8D2PolicyCompositionAuthorityDefinitionAllowed(withoutImage) {
		t.Fatal("profile sealer can mint image authority without the measured rootfs digest")
	}
}

func TestL8D2ImageProfileIssuerDoesNotCollideWithLegacyVerifier(t *testing.T) {
	legacySource, err := os.ReadFile(filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "distribution.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacySource), "func VerifyDistributionBundle(request DistributionRequest) (VerifiedDistribution, error)") {
		t.Fatal("legacy L5/L7 distribution verifier signature changed")
	}

	canonical := `package localresolver
func VerifyL8DistributionBundle(request L8DistributionRequest) (VerifiedDistribution, error) { return VerifiedDistribution{}, nil }`
	parsed, err := parser.ParseFile(token.NewFileSet(), "l8_distribution_verifier.go", canonical, 0)
	if err != nil {
		t.Fatal(err)
	}
	if l8D2TopLevelFunction(parsed, "VerifyL8DistributionBundle") == nil {
		t.Fatal("L8 issuer must use its distinct compileable function name")
	}
	if l8D2TopLevelFunction(parsed, "VerifyDistributionBundle") != nil {
		t.Fatal("L8 issuer collides with the legacy L5/L7 verifier")
	}
	for _, issue := range l8D2PolicyCompositionIssuerASTIssues(canonical) {
		if issue == "sole issuer signature is not exact" {
			t.Fatal("policy-composition guard still requires the colliding legacy verifier name")
		}
	}
}

func TestL8D2ImageProfileDistributionSealerRetainsVerifiedBundleState(t *testing.T) {
	parseSealer := func(source string) *ast.FuncDecl {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "l8_distribution_verifier.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		return l8D2TopLevelFunction(file, "sealVerifiedL8Distribution")
	}

	withState := parseSealer(`package localresolver
func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, descriptor assets.LaunchDescriptor, rootDir string) VerifiedDistribution { return VerifiedDistribution{} }`)
	if !l8D2PolicyCompositionAuthorityDefinitionAllowed(withState) {
		t.Fatal("distribution sealer cannot retain the verified bundle state required by lease issuance")
	}

	withoutState := parseSealer(`package localresolver
func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) VerifiedDistribution { return VerifiedDistribution{} }`)
	if l8D2PolicyCompositionAuthorityDefinitionAllowed(withoutState) {
		t.Fatal("distribution sealer can issue authority without retaining verified bundle state")
	}
}

func TestL8D2ImageProfileSealerReceivesDescriptorFingerprint(t *testing.T) {
	parseSealer := func(source string) *ast.FuncDecl {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "l8_authority.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		return l8D2TopLevelFunction(file, "sealVerifiedL8Profile")
	}

	withDescriptor := parseSealer(`package localresolver
func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }`)
	if !l8D2PolicyCompositionAuthorityDefinitionAllowed(withDescriptor) {
		t.Fatal("profile sealer cannot bind the normalized launch descriptor")
	}

	withoutDescriptor := parseSealer(`package localresolver
func sealVerifiedL8Profile(evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) { return VerifiedL8Profile{}, nil }`)
	if l8D2PolicyCompositionAuthorityDefinitionAllowed(withoutDescriptor) {
		t.Fatal("profile sealer can issue a profile without its descriptor fingerprint")
	}
}

func TestL8D2ImageProfilePolicyCompositionRecursiveAuthorityTaintRejectsCrossFileFlows(t *testing.T) {
	sources := map[string]string{
		"authority_box.go": `package localresolver
type authorityInner struct { profile VerifiedL8Profile }
type authorityOuter struct { inner authorityInner }`,
		"authority_leak.go": `package localresolver
func leakAuthority(box authorityOuter) any { copied := box.inner.profile; arbitrary(copied); return copied }`,
	}
	authorityTypes := l8D2PolicyCompositionAuthorityTypesForSources(sources)
	if _, ok := authorityTypes["authorityInner"]; !ok {
		t.Fatal("recursive authority type closure omitted inner owner")
	}
	if _, ok := authorityTypes["authorityOuter"]; !ok {
		t.Fatal("recursive authority type closure omitted outer owner")
	}
	var issues []string
	for path, source := range sources {
		issues = append(issues, l8D2PolicyCompositionExternalReferenceIssuesWithTypes(path, source, authorityTypes)...)
	}
	if len(issues) == 0 {
		t.Fatal("recursive package authority taint accepted cross-file selector/copy/helper/return escape")
	}
}

func TestL8D2ImageProfilePolicyCompositionRecursiveAuthorityTaintUnionsAllBuildDefinitions(t *testing.T) {
	authority := `//go:build linux
package localresolver
type authorityBox struct { profile VerifiedL8Profile }
type cyclicA struct { next *cyclicB }
type cyclicB struct { next *cyclicA; box authorityBox }
type genericBox[T any] struct { value T }
type genericOwner struct { value genericBox[authorityBox] }`
	benign := `//go:build windows
package localresolver
type authorityBox struct { value string }
type cyclicA struct { value string }
type cyclicB struct { value string }
type genericBox[T any] struct { value string }
type genericOwner struct { value string }`
	orders := []map[string]string{
		{"a_linux.go": authority, "z_windows.go": benign},
		{"a_windows.go": benign, "z_linux.go": authority},
	}
	for iteration := 0; iteration < 500; iteration++ {
		for orderIndex, sources := range orders {
			authorityTypes := l8D2PolicyCompositionAuthorityTypesForSources(sources)
			for _, name := range []string{"authorityBox", "cyclicA", "cyclicB", "genericOwner"} {
				if _, ok := authorityTypes[name]; !ok {
					t.Fatalf("iteration %d order %d omitted all-build-context authority type %s", iteration, orderIndex, name)
				}
			}
		}
	}
}

func TestL8D2ImageProfilePolicyCompositionPackageFixtureDeclarationsRejectBuildContextDuplicates(t *testing.T) {
	canonicalFixture := `package localresolver
import "testing"
func materializeValidL8DistributionRequestFixture(t *testing.T) L8DistributionRequest { return L8DistributionRequest{} }
func replaceL8DistributionPolicyCompositionField(request DistributionRequest, document, field, replacement string) error { return nil }`
	canonical := map[string]string{"l8_distribution_policy_composition_fixture_test.go": canonicalFixture}
	if issues := l8D2PolicyCompositionPackageFixtureDeclarationIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical package fixture declarations rejected: %v", issues)
	}
	for name, duplicate := range map[string]string{
		"builder": `//go:build alternate
package localresolver
import "testing"
func materializeValidL8DistributionRequestFixture(t *testing.T) L8DistributionRequest { return L8DistributionRequest{} }`,
		"mutator": `//go:build alternate
package localresolver
func replaceL8DistributionPolicyCompositionField(request DistributionRequest, document, field, replacement string) error { return nil }`,
	} {
		t.Run(name, func(t *testing.T) {
			mutated := map[string]string{"l8_distribution_policy_composition_fixture_test.go": canonicalFixture, "alternate_fixture_test.go": duplicate}
			if issues := l8D2PolicyCompositionPackageFixtureDeclarationIssues(mutated); len(issues) == 0 {
				t.Fatal("package fixture declaration guard accepted a build-context duplicate")
			}
		})
	}
}

func TestL8D2ImageProfilePolicyCompositionUnderlyingFixtureGuardRejectsBypasses(t *testing.T) {
	canonical := `package localresolver
import "testing"
func materializeValidL8DistributionRequestFixture(t *testing.T) L8DistributionRequest {
	t.Helper()
	request := buildCompleteValidL8DistributionRequestFixture(t)
	if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("materialized L8 fixture is invalid: %v", err) }
	return request
}
func replaceL8DistributionPolicyCompositionField(request DistributionRequest, document, field, replacement string) error {
	return rewriteExactL8PolicyCompositionField(request, document, field, replacement)
}`
	if issues := l8D2UnderlyingPolicyCompositionFixtureIssues(canonical); len(issues) != 0 {
		t.Fatalf("canonical underlying fixture source rejected: %v", issues)
	}
	for name, mutated := range map[string]string{
		"builder skip":        strings.Replace(canonical, "request := buildCompleteValidL8DistributionRequestFixture(t)", "t.SkipNow()\n\trequest := buildCompleteValidL8DistributionRequestFixture(t)", 1),
		"builder lookalike":   strings.Replace(canonical, "buildCompleteValidL8DistributionRequestFixture(t)", "lookalikeValidL8DistributionRequestFixture(t)", 1),
		"builder unchecked":   strings.Replace(canonical, `if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("materialized L8 fixture is invalid: %v", err) }`, `_ = request`, 1),
		"mutator no-op":       strings.Replace(canonical, "return rewriteExactL8PolicyCompositionField(request, document, field, replacement)", "return nil", 1),
		"mutator fixed field": strings.Replace(canonical, "request, document, field, replacement", `request, "manifest", "policyArtifactSha256", replacement`, 1),
		"mutator lookalike":   strings.Replace(canonical, "rewriteExactL8PolicyCompositionField", "rewriteL8PolicyCompositionFieldLookalike", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if issues := l8D2UnderlyingPolicyCompositionFixtureIssues(mutated); len(issues) == 0 {
				t.Fatal("underlying fixture guard accepted seeded bypass")
			}
		})
	}
}

func l8D2PolicyCompositionIssuerASTIssues(source string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), "l8_distribution_verifier.go", source, 0)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var issues []string
	if !l8D2HasExactImport(parsed, "syscallpolicy", "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy") {
		issues = append(issues, "issuer syscallpolicy import is absent, aliased, or ambiguous")
	}
	issuer := l8D2TopLevelFunction(parsed, "VerifyL8DistributionBundle")
	if issuer == nil || issuer.Recv != nil || issuer.Type.TypeParams != nil || !l8D2ExactNamedFields(issuer.Type.Params, []string{"request:L8DistributionRequest"}) || !l8D2ExactNamedFields(issuer.Type.Results, []string{"<unnamed>:VerifiedDistribution", "<unnamed>:error"}) {
		return append(issues, "sole issuer signature is not exact")
	}
	decoderPrelude := []string{
		"manifest, err := decodeL8DistributionManifest(request.DistributionRequest)",
		"if err != nil { return VerifiedDistribution{}, classifyL8DistributionManifestError(err) }",
		"provenance, err := decodeL8Provenance(request.DistributionRequest)",
		"if err != nil { return VerifiedDistribution{}, classifyL8ProvenanceError(err) }",
		"sourceLock, err := decodeL8SourceLock(request.DistributionRequest)",
		"if err != nil { return VerifiedDistribution{}, classifyL8SourceLockError(err) }",
		"finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)",
		"if err != nil { return VerifiedDistribution{}, classifyL8FinalInspectionError(err) }",
	}
	authorityAnchors := []string{
		"pinnedCallsiteEvidenceBytes, err := snapshotL8PinnedCallsiteEvidence(request.PinnedCallsiteEvidence)",
		"if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }",
		"defer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)",
		"artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()",
		"if err != nil { return VerifiedDistribution{}, classifyL8PolicyArtifactError(err) }",
		"expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()",
		"if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceExpectationError(err) }",
		"evidence, err := syscallpolicy.ImportPinnedCallsiteEvidence(pinnedCallsiteEvidenceBytes, artifact, expectedEvidence)",
		"if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }",
		"manifestPolicyComposition, err := decodeL8PolicyCompositionDigests(manifest.L8Profile.ProcessComposition)",
		"if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }",
		"provenancePolicyComposition, err := decodeL8PolicyCompositionDigests(provenance.L8Profile.ProcessComposition)",
		"if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }",
		"finalInspectionPolicyComposition, err := decodeL8PolicyCompositionDigests(finalInspection.ProcessComposition)",
		"if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }",
		"derivedPolicyComposition := deriveL8PolicyCompositionDigests(artifact, evidence)",
		"if err := validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition); err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionCorrelationError(err) }",
		"evidenceFingerprint, imageSHA256, err := buildL8EvidenceFingerprint(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, derivedPolicyComposition)",
		"if err != nil { return VerifiedDistribution{}, classifyL8EvidenceFingerprintError(err) }",
		"descriptorFingerprint, err := buildL8DescriptorFingerprint(descriptor)",
		"if err != nil { return VerifiedDistribution{}, classifyL8ProfileSealError(err) }",
		"verifiedL8Profile, err := sealVerifiedL8Profile(descriptorFingerprint, evidenceFingerprint, imageSHA256, derivedPolicyComposition)",
		"if err != nil { return VerifiedDistribution{}, classifyL8ProfileSealError(err) }",
		"return sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil",
	}
	if issuer.Body == nil {
		return append(issues, "issuer body is absent")
	}
	snapshot := l8D2TopLevelFunction(parsed, "snapshotL8PinnedCallsiteEvidence")
	wantSnapshot := `{
		if len(source) == 0 || len(source) > l8MaxPinnedEvidenceBytes { return nil, ErrAssetLockMismatch }
		return append([]byte(nil), source...), nil
	}`
	if snapshot == nil || snapshot.Recv != nil || snapshot.Type.TypeParams != nil || !l8D2ExactNamedFields(snapshot.Type.Params, []string{"source:[]byte"}) || !l8D2ExactNamedFields(snapshot.Type.Results, []string{"<unnamed>:[]byte", "<unnamed>:error"}) || snapshot.Body == nil || l8D2CompactGo(l8D2RenderNode(snapshot.Body)) != l8D2CompactGo(wantSnapshot) {
		issues = append(issues, "issuer evidence snapshot does not enforce the exact bound before copying")
	}
	previous := -1
	for anchorIndex, anchor := range decoderPrelude {
		position := l8D2FindExactTopLevelStatementAfter(issuer.Body, anchor, previous)
		if position <= previous || (anchorIndex%2 == 1 && position != previous+1) {
			issues = append(issues, "issuer decoder/error prelude is absent, duplicated, or reordered: "+anchor)
			return issues
		}
		previous = position
	}
	positions := make([]int, len(authorityAnchors))
	for anchorIndex, anchor := range authorityAnchors {
		position := l8D2FindExactTopLevelStatementAfter(issuer.Body, anchor, previous)
		positions[anchorIndex] = position
		if position <= previous || (anchorIndex > 0 && position != previous+1) {
			issues = append(issues, "issuer authority/dataflow anchor is absent, duplicated, or reordered: "+anchor)
			return issues
		}
		previous = position
	}
	if previous != len(issuer.Body.List)-1 {
		issues = append(issues, "issuer authority block does not end at the sole successful return")
	}
	validationPosition := positions[15]
	ast.Inspect(issuer.Body, func(node ast.Node) bool {
		if _, branch := node.(*ast.BranchStmt); branch {
			issues = append(issues, "issuer may not bypass correlation with branch control")
		}
		return true
	})
	for index, statement := range issuer.Body.List {
		if index < validationPosition && l8D2StatementCanIssueL8Authority(statement) {
			issues = append(issues, "issuer can return or construct authority before correlation validation")
		}
	}
	protected := []string{"manifest", "provenance", "sourceLock", "finalInspection", "descriptor", "rootDir", "parentL7EvidenceSHA256", "pinnedCallsiteEvidenceBytes", "artifact", "expectedEvidence", "evidence", "manifestPolicyComposition", "provenancePolicyComposition", "finalInspectionPolicyComposition", "derivedPolicyComposition", "evidenceFingerprint", "imageSHA256", "descriptorFingerprint", "verifiedL8Profile"}
	for _, name := range protected {
		if count := l8D2AssignmentCount(issuer.Body, name); count != 1 {
			issues = append(issues, "issuer protected value is absent or reassigned: "+name)
		}
	}
	classifier := l8D2TopLevelFunction(parsed, "classifyL8PolicyCompositionCorrelationError")
	wantClassifier := `return newResolverError(ErrorCodeAssetLockMismatch, "processComposition", "", "L8 policy composition correlation mismatch", ErrAssetLockMismatch)`
	if classifier == nil || classifier.Recv != nil || classifier.Type.TypeParams != nil || !l8D2ExactNamedFields(classifier.Type.Params, []string{"_:error"}) || !l8D2ExactNamedFields(classifier.Type.Results, []string{"<unnamed>:error"}) || classifier.Body == nil || len(classifier.Body.List) != 1 || l8D2CompactGo(l8D2RenderNode(classifier.Body.List[0])) != l8D2CompactGo(wantClassifier) {
		issues = append(issues, "issuer correlation classifier is not the exact sanitized resolver error")
	}
	issues = append(issues, l8D2PolicyCompositionExternalReferenceIssues("l8_distribution_verifier.go", source)...)
	return issues
}

func l8D2PolicyCompositionMutationASTIssues(source string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), "l8_distribution_verifier_test.go", source, parser.ParseComments)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var issues []string
	if len(parsed.Imports) != 4 || !l8D2HasExactImport(parsed, "sha256", "crypto/sha256") || !l8D2HasExactImport(parsed, "json", "encoding/json") || !l8D2HasExactImport(parsed, "errors", "errors") || !l8D2HasExactImport(parsed, "testing", "testing") {
		issues = append(issues, "mutation test lacks an exact required import")
	}
	if l8D2FileHasForbiddenPolicyCompositionMechanism(parsed) {
		issues = append(issues, "mutation test uses a forbidden directive, unsafe/reflection alias, or initialization mechanism")
	}
	if !l8D2ExactPolicyCompositionMutationDeclarations(parsed) {
		issues = append(issues, "mutation test declaration topology is not exact")
	}
	testFunction := l8D2TopLevelFunction(parsed, "TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations")
	if testFunction == nil || testFunction.Recv != nil || testFunction.Type.TypeParams != nil || !l8D2ExactNamedFields(testFunction.Type.Params, []string{"t:*testing.T"}) || !l8D2ExactNamedFields(testFunction.Type.Results, nil) {
		issues = append(issues, "mutation test signature is not runnable/exact")
	} else {
		issues = append(issues, l8D2ExactLocalPolicyCompositionMutationBodyIssues(testFunction.Body)...)
	}
	issues = append(issues, l8D2ExactPolicyCompositionFixtureHelperIssues(parsed)...)
	assertion := l8D2TopLevelFunction(parsed, "assertL8PolicyCompositionCorrelationMismatch")
	wantAssertion := `{
		t.Helper()
		var resolverError *Error
		if !errors.As(err, &resolverError) { t.Fatal("missing typed resolver error") }
		if resolverError.Code != ErrorCodeAssetLockMismatch || resolverError.Field != "processComposition" || resolverError.Role != "" || resolverError.Message != "L8 policy composition correlation mismatch" { t.Fatal("unexpected resolver error") }
		if !errors.Is(err, ErrAssetLockMismatch) { t.Fatal("missing asset-lock sentinel") }
		if err.Error() != "local asset resolver failed (asset_lock_mismatch) field=processComposition: L8 policy composition correlation mismatch" { t.Fatal("unsafe resolver error text") }
	}`
	if assertion == nil || assertion.Recv != nil || assertion.Type.TypeParams != nil || !l8D2ExactNamedFields(assertion.Type.Params, []string{"t:*testing.T", "err:error"}) || !l8D2ExactNamedFields(assertion.Type.Results, nil) || assertion.Body == nil || l8D2CompactGo(l8D2RenderNode(assertion.Body)) != l8D2CompactGo(wantAssertion) {
		issues = append(issues, "mutation test does not enforce the exact sanitized typed mismatch result")
	}
	return issues
}

func l8D2ExpectedPolicyCompositionMutationPairs() []string {
	documents := []string{"manifest", "provenance", "finalInspection"}
	fields := []string{"workloadSnapshotSha256", "runtimeProfileSha256", "policyArtifactSha256", "policySourceLockSha256", "policyBinaryBindingSetSha256", "pinnedCallsiteEvidenceSha256"}
	result := make([]string, 0, len(documents)*len(fields))
	for _, document := range documents {
		for _, field := range fields {
			result = append(result, `{document: "`+document+`", field: "`+field+`"}`)
		}
	}
	return result
}

func l8D2PolicyCompositionExternalReferenceIssues(path, source string) []string {
	return l8D2PolicyCompositionExternalReferenceIssuesWithTypes(path, source, l8D2PolicyCompositionAuthorityTypesForSources(map[string]string{path: source}))
}

func l8D2PolicyCompositionExternalReferenceIssuesWithTypes(path, source string, authorityTypes map[string]struct{}) []string {
	if strings.EqualFold(filepath.Ext(path), ".s") {
		return []string{"assembly is forbidden in the policy-composition authority/test package"}
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	base := filepath.Base(path)
	var issues []string
	if l8D2FileContainsTestTermination(source, parsed) {
		issues = append(issues, "localresolver source may not skip or terminate fixture execution")
	}
	if l8D2FileHasLinknameOrUnsafePolicyCompositionMechanism(parsed) || (l8D2FileImports(parsed, "reflect") && l8D2FileContainsProtectedPolicyCompositionReference(parsed)) {
		issues = append(issues, "forbidden directive, unsafe/reflection alias, or initialization mechanism")
	}
	parents := l8D2ASTParents(parsed)
	allowedIssuerCalls := map[string]string{
		"buildL8EvidenceFingerprint":                  "buildL8EvidenceFingerprint(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, derivedPolicyComposition)",
		"sealVerifiedL8Profile":                       "sealVerifiedL8Profile(descriptorFingerprint, evidenceFingerprint, imageSHA256, derivedPolicyComposition)",
		"sealVerifiedL8Distribution":                  "sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir)",
		"classifyL8PolicyCompositionCorrelationError": "classifyL8PolicyCompositionCorrelationError(err)",
	}
	allowedCounts := make(map[string]int, len(allowedIssuerCalls))
	isProduction := !strings.HasSuffix(base, "_test.go")
	for _, declaration := range parsed.Decls {
		if general, ok := declaration.(*ast.GenDecl); ok {
			for _, specification := range general.Specs {
				typeSpec, typeOK := specification.(*ast.TypeSpec)
				if typeOK {
					if l8D2PolicyCompositionAuthorityTypeName(typeSpec.Type) != "" {
						issues = append(issues, "L8 authority types may not be aliased or used as derived-type underlays")
					}
					if _, containsAuthority := authorityTypes[typeSpec.Name.Name]; containsAuthority && l8D2PolicyCompositionAuthorityTypeName(typeSpec.Name) == "" {
						issues = append(issues, "additional named wrappers around the closed L8 authority-owner graph are forbidden: "+typeSpec.Name.Name)
					}
				}
				valueSpec, valueOK := specification.(*ast.ValueSpec)
				if valueOK {
					containsAuthority := l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(valueSpec.Type, authorityTypes)
					for _, value := range valueSpec.Values {
						containsAuthority = containsAuthority || l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(value, authorityTypes)
					}
					if containsAuthority {
						issues = append(issues, "L8 authority is stored in package-level data or a generic/container value")
					}
				}
			}
			ast.Inspect(general, func(node ast.Node) bool {
				if literal, literalOK := node.(*ast.CompositeLit); literalOK {
					if authorityType := l8D2PolicyCompositionAuthorityTypeName(literal.Type); authorityType != "" && l8D2AuthorityLiteralCarriesL8Authority(literal, authorityType) {
						issues = append(issues, "L8 authority value is constructed in package-level data")
					} else if l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(literal.Type, authorityTypes) {
						issues = append(issues, "nested L8 authority-owner value is constructed in package-level data")
					}
				}
				if call, callOK := node.(*ast.CallExpr); callOK {
					if l8D2CompactGo(l8D2RenderNode(call.Fun)) == "new" && len(call.Args) == 1 {
						if l8D2PolicyCompositionAuthorityTypeName(call.Args[0]) != "" {
							issues = append(issues, "L8 authority value is allocated in package-level data")
						}
					} else if l8D2PolicyCompositionAuthorityTypeName(call.Fun) != "" {
						issues = append(issues, "L8 authority value is converted in package-level data")
					}
				}
				_, protected := l8D2ProtectedPolicyCompositionReferenceName(node)
				if protected {
					if _, nested := parents[node].(*ast.SelectorExpr); nested {
						if _, identifierOK := node.(*ast.Ident); identifierOK {
							return true
						}
					}
					issues = append(issues, "protected L8 authority or mutation reference exists in package-level data")
				}
				return true
			})
		}
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if l8D2NamesL8PolicyCompositionAuthority(function.Name.Name) && l8D2ForbiddenPolicyCompositionAuthorityAPI(function.Name.Name) && !l8D2PolicyCompositionAuthorityDefinitionAllowed(function) {
			issues = append(issues, "noncanonical L8 authority API declaration exists in localresolver")
		}
		switch function.Name.Name {
		case "sealVerifiedL8Profile":
			if !l8D2ExactDirectAuthorityReturn(function, "VerifiedL8Profile", true) {
				issues = append(issues, "profile sealer is not one exact direct authority return")
			}
		case "sealVerifiedL8Distribution":
			if !l8D2ExactDirectAuthorityReturn(function, "VerifiedDistribution", false) {
				issues = append(issues, "distribution sealer is not one exact direct authority return")
			}
		case "AcquireL8AssetLease":
			if l8D2ExactReceiverType(function, "VerifiedDistribution") && !l8D2AllAuthoritySuccessReturnsDirect(function, "VerifiedL8AssetLease") {
				issues = append(issues, "lease acquisition has a staged, cached, or factory-produced success result")
			}
		}
		issues = append(issues, l8D2PolicyCompositionAuthorityEscapeIssues(function, parents, authorityTypes)...)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if literal, literalOK := node.(*ast.CompositeLit); literalOK {
				if authorityType := l8D2PolicyCompositionAuthorityTypeName(literal.Type); authorityType != "" && l8D2AuthorityLiteralCarriesL8Authority(literal, authorityType) && !l8D2PolicyCompositionAuthorityLiteralAllowed(function, authorityType) {
					issues = append(issues, "L8 authority value is constructed outside its exact private sealing/acquisition function")
				} else if authorityType == "" && l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(literal.Type, authorityTypes) {
					issues = append(issues, "nested L8 authority-owner value is constructed outside the closed direct-return graph")
				}
			}
			if call, callOK := node.(*ast.CallExpr); callOK {
				if l8D2CompactGo(l8D2RenderNode(call.Fun)) == "new" && len(call.Args) == 1 {
					if authorityType := l8D2PolicyCompositionAuthorityTypeName(call.Args[0]); authorityType != "" && !l8D2PolicyCompositionAuthorityLiteralAllowed(function, authorityType) {
						issues = append(issues, "L8 authority value is allocated outside its exact private sealing/acquisition function")
					}
				} else if authorityType := l8D2PolicyCompositionAuthorityTypeName(call.Fun); authorityType != "" && !l8D2PolicyCompositionAuthorityLiteralAllowed(function, authorityType) {
					issues = append(issues, "L8 authority value is converted outside its exact private sealing/acquisition function")
				}
			}
			name, protected := l8D2ProtectedPolicyCompositionReferenceName(node)
			if !protected {
				return true
			}
			if _, nested := parents[node].(*ast.SelectorExpr); nested {
				if _, identifierOK := node.(*ast.Ident); identifierOK {
					return true
				}
			}
			if name == "l8PolicyCompositionMutationCases" {
				if base != "l8_distribution_verifier_test.go" || function.Name.Name != "TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations" {
					issues = append(issues, "policy-composition mutation cases escape the exact local runnable test")
				}
				return true
			}
			if !isProduction {
				return true
			}
			if l8D2ForbiddenPolicyCompositionAuthorityAPI(name) {
				issues = append(issues, "lease/profile/distribution authority API is reachable inside localresolver production")
				return true
			}
			want, issuerOnly := allowedIssuerCalls[name]
			if !issuerOnly {
				return true
			}
			call, direct := parents[node].(*ast.CallExpr)
			if !direct || call.Fun != node || base != "l8_distribution_verifier.go" || function.Name.Name != "VerifyL8DistributionBundle" || l8D2CompactGo(l8D2RenderNode(call)) != l8D2CompactGo(want) {
				issues = append(issues, "protected L8 authority reference is not the exact direct call in VerifyL8DistributionBundle")
				return true
			}
			allowedCounts[name]++
			return true
		})
	}
	if base == "l8_distribution_verifier_test.go" {
		testFunction := l8D2TopLevelFunction(parsed, "TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations")
		var allowedBody *ast.BlockStmt
		if testFunction != nil {
			allowedBody = testFunction.Body
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Name != "l8PolicyCompositionMutationCases" {
				return true
			}
			if allowedBody == nil || identifier.Pos() < allowedBody.Pos() || identifier.End() > allowedBody.End() {
				issues = append(issues, "policy-composition mutation cases are addressable outside the exact local test body")
			}
			return true
		})
	}
	if isProduction && base == "l8_distribution_verifier.go" && l8D2TopLevelFunction(parsed, "VerifyL8DistributionBundle") != nil {
		for name := range allowedIssuerCalls {
			if allowedCounts[name] != 1 {
				issues = append(issues, "protected L8 issuer call count is not exactly one: "+name)
			}
		}
	}
	return issues
}

func l8D2AuthorityLiteralCarriesL8Authority(literal *ast.CompositeLit, authorityType string) bool {
	if literal == nil {
		return false
	}
	if authorityType != "VerifiedDistribution" {
		return len(literal.Elts) != 0
	}
	for _, element := range literal.Elts {
		keyed, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		identifier, ok := keyed.Key.(*ast.Ident)
		if !ok {
			return true
		}
		switch identifier.Name {
		case "l8Profile", "l8EvidenceFingerprint", "l8PolicyComposition":
			return true
		}
	}
	return false
}

func l8D2ExactLocalPolicyCompositionMutationBodyIssues(body *ast.BlockStmt) []string {
	if body == nil || len(body.List) != 6 {
		return []string{"mutation test must have the exact baseline, local-array, counter, range, and count-check statements"}
	}
	var issues []string
	if l8D2CompactGo(l8D2RenderNode(body.List[0])) != "baseline:=validL8DistributionRequest(t)" {
		issues = append(issues, "mutation test does not construct the exact baseline request")
	}
	wantBaseline := `if _, err := VerifyL8DistributionBundle(baseline); err != nil { t.Fatalf("valid L8 baseline rejected: %v", err) }`
	if l8D2CompactGo(l8D2RenderNode(body.List[1])) != l8D2CompactGo(wantBaseline) {
		issues = append(issues, "mutation test does not prove the real baseline succeeds before mutation")
	}
	definition, ok := body.List[2].(*ast.AssignStmt)
	if !ok || definition.Tok != token.DEFINE || len(definition.Lhs) != 1 || len(definition.Rhs) != 1 || l8D2RenderNode(definition.Lhs[0]) != "l8PolicyCompositionMutationCases" {
		issues = append(issues, "mutation cases are not a function-local immutable definition")
	} else if cases, literalOK := definition.Rhs[0].(*ast.CompositeLit); !literalOK {
		issues = append(issues, "mutation cases are not a closed array literal")
	} else {
		arrayType, arrayOK := cases.Type.(*ast.ArrayType)
		lengthOK := arrayOK && arrayType.Len != nil && l8D2RenderNode(arrayType.Len) == "18"
		var structure *ast.StructType
		var structOK bool
		if arrayOK {
			structure, structOK = arrayType.Elt.(*ast.StructType)
		}
		if !lengthOK || !structOK || !l8D2ExactNamedFields(structure.Fields, []string{"document:string", "field:string"}) {
			issues = append(issues, "mutation cases must be one non-addressable [18]struct{document string; field string}")
		}
		expectedPairs := l8D2ExpectedPolicyCompositionMutationPairs()
		if len(cases.Elts) != len(expectedPairs) {
			issues = append(issues, "mutation array count is not exactly 18")
		} else {
			for index, element := range cases.Elts {
				if l8D2CompactGo(l8D2RenderNode(element)) != l8D2CompactGo(expectedPairs[index]) {
					issues = append(issues, "mutation array tuple order/uniqueness is not exact")
					break
				}
			}
		}
	}
	if l8D2CompactGo(l8D2RenderNode(body.List[3])) != "executed:=0" {
		issues = append(issues, "mutation execution counter is not initialized exactly once")
	}
	wantRange := `for mutationIndex, mutation := range l8PolicyCompositionMutationCases {
		t.Run(mutation.document+"/"+mutation.field, func(t *testing.T) {
			request := validL8DistributionRequest(t)
			if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("valid per-case L8 baseline rejected: %v", err) }
			before, beforeNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			mutateL8PolicyCompositionFixture(t, &request, mutation.document, mutation.field)
			after, afterNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			assertExactlyOneL8PolicyCompositionFieldChanged(t, before, after, beforeNonPolicy, afterNonPolicy, mutationIndex)
			_, err := VerifyL8DistributionBundle(request)
			assertL8PolicyCompositionCorrelationMismatch(t, err)
			executed++
		})
	}`
	if l8D2CompactGo(l8D2RenderNode(body.List[4])) != l8D2CompactGo(wantRange) {
		issues = append(issues, "each mutation must execute the real issuer and exact mismatch assertion once")
	}
	wantCount := `if executed != 18 { t.Fatalf("executed %d policy-composition mutations, want 18", executed) }`
	if l8D2CompactGo(l8D2RenderNode(body.List[5])) != l8D2CompactGo(wantCount) {
		issues = append(issues, "mutation test must assert exactly 18 executed issuer cases")
	}
	return issues
}

func l8D2ExactPolicyCompositionFixtureHelperIssues(file *ast.File) []string {
	var issues []string
	checks := []struct {
		name    string
		params  []string
		results []string
		body    string
	}{
		{
			name: "validL8DistributionRequest", params: []string{"t:*testing.T"}, results: []string{"<unnamed>:L8DistributionRequest"},
			body: `{
				t.Helper()
				return materializeValidL8DistributionRequestFixture(t)
			}`,
		},
		{
			name: "mutateL8PolicyCompositionFixture", params: []string{"t:*testing.T", "request:*L8DistributionRequest", "document:string", "field:string"}, results: nil,
			body: `{
				t.Helper()
				if err := replaceL8DistributionPolicyCompositionField(request.DistributionRequest, document, field, "0101010101010101010101010101010101010101010101010101010101010101"); err != nil { t.Fatalf("mutate L8 policy composition: %v", err) }
			}`,
		},
		{
			name: "snapshotL8PolicyCompositionFields", params: []string{"t:*testing.T", "request:L8DistributionRequest"}, results: []string{"<unnamed>:[18]string", "<unnamed>:[3][32]byte"},
			body: `{
				t.Helper()
				manifest, err := decodeL8DistributionManifest(request.DistributionRequest)
				if err != nil { t.Fatalf("decode L8 manifest snapshot: %v", err) }
				provenance, err := decodeL8Provenance(request.DistributionRequest)
				if err != nil { t.Fatalf("decode L8 provenance snapshot: %v", err) }
				finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)
				if err != nil { t.Fatalf("decode L8 final-inspection snapshot: %v", err) }
				fields := [18]string{ manifest.L8Profile.ProcessComposition.WorkloadSnapshotSHA256, manifest.L8Profile.ProcessComposition.RuntimeProfileSHA256, manifest.L8Profile.ProcessComposition.PolicyArtifactSHA256, manifest.L8Profile.ProcessComposition.PolicySourceLockSHA256, manifest.L8Profile.ProcessComposition.PolicyBinaryBindingSetSHA256, manifest.L8Profile.ProcessComposition.PinnedCallsiteEvidenceSHA256, provenance.L8Profile.ProcessComposition.WorkloadSnapshotSHA256, provenance.L8Profile.ProcessComposition.RuntimeProfileSHA256, provenance.L8Profile.ProcessComposition.PolicyArtifactSHA256, provenance.L8Profile.ProcessComposition.PolicySourceLockSHA256, provenance.L8Profile.ProcessComposition.PolicyBinaryBindingSetSHA256, provenance.L8Profile.ProcessComposition.PinnedCallsiteEvidenceSHA256, finalInspection.ProcessComposition.WorkloadSnapshotSHA256, finalInspection.ProcessComposition.RuntimeProfileSHA256, finalInspection.ProcessComposition.PolicyArtifactSHA256, finalInspection.ProcessComposition.PolicySourceLockSHA256, finalInspection.ProcessComposition.PolicyBinaryBindingSetSHA256, finalInspection.ProcessComposition.PinnedCallsiteEvidenceSHA256 }
				manifest.L8Profile.ProcessComposition = L8ProcessCompositionFacts{}
				provenance.L8Profile.ProcessComposition = L8ProcessCompositionFacts{}
				finalInspection.ProcessComposition = L8ProcessCompositionFacts{}
				nonPolicy := [3][32]byte{ canonicalL8NonPolicyDocumentSHA256(t, manifest), canonicalL8NonPolicyDocumentSHA256(t, provenance), canonicalL8NonPolicyDocumentSHA256(t, finalInspection) }
				return fields, nonPolicy
			}`,
		},
		{
			name: "canonicalL8NonPolicyDocumentSHA256", params: []string{"t:*testing.T", "value:any"}, results: []string{"<unnamed>:[32]byte"},
			body: `{
				t.Helper()
				encoded, err := json.Marshal(value)
				if err != nil { t.Fatalf("canonicalize non-policy L8 document: %v", err) }
				return sha256.Sum256(encoded)
			}`,
		},
		{
			name: "assertExactlyOneL8PolicyCompositionFieldChanged", params: []string{"t:*testing.T", "before:[18]string", "after:[18]string", "beforeNonPolicy:[3][32]byte", "afterNonPolicy:[3][32]byte", "selected:int"}, results: nil,
			body: `{
				t.Helper()
				if beforeNonPolicy != afterNonPolicy { t.Fatal("non-policy L8 document semantics changed") }
				for index := range before {
					if index == selected {
						if before[index] == after[index] { t.Fatal("selected policy-composition field did not change") }
						if after[index] != "0101010101010101010101010101010101010101010101010101010101010101" { t.Fatal("selected policy-composition field is not the exact valid replacement digest") }
						continue
					}
					if before[index] != after[index] { t.Fatal("non-selected policy-composition field changed") }
				}
			}`,
		},
	}
	for _, check := range checks {
		function := l8D2TopLevelFunction(file, check.name)
		if function == nil || function.Recv != nil || function.Type.TypeParams != nil || !l8D2ExactNamedFields(function.Type.Params, check.params) || !l8D2ExactNamedFields(function.Type.Results, check.results) || function.Body == nil || l8D2CompactGo(l8D2RenderNode(function.Body)) != l8D2CompactGo(check.body) {
			issues = append(issues, "policy-composition fixture helper is absent, aliased, or semantically open: "+check.name)
		}
	}
	return issues
}

func l8D2FileHasForbiddenPolicyCompositionMechanism(file *ast.File) bool {
	return l8D2FileHasLinknameOrUnsafePolicyCompositionMechanism(file) || l8D2FileImports(file, "reflect")
}

func l8D2FileHasLinknameOrUnsafePolicyCompositionMechanism(file *ast.File) bool {
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		if path == "unsafe" {
			return true
		}
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.Contains(comment.Text, "go:linkname") {
				return true
			}
		}
	}
	return false
}

func l8D2FileImports(file *ast.File, importPath string) bool {
	for _, imported := range file.Imports {
		if strings.Trim(imported.Path.Value, `"`) == importPath {
			return true
		}
	}
	return false
}

func l8D2FileContainsProtectedPolicyCompositionReference(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if _, protected := l8D2ProtectedPolicyCompositionReferenceName(node); protected {
			found = true
			return false
		}
		return !found
	})
	return found
}

func l8D2ASTParents(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	stack := make([]ast.Node, 0, 32)
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func l8D2ProtectedPolicyCompositionReferenceName(node ast.Node) (string, bool) {
	var name string
	switch typed := node.(type) {
	case *ast.Ident:
		name = typed.Name
	case *ast.SelectorExpr:
		name = typed.Sel.Name
	default:
		return "", false
	}
	switch name {
	case "buildL8EvidenceFingerprint", "sealVerifiedL8Profile", "sealVerifiedL8Distribution", "classifyL8PolicyCompositionCorrelationError",
		"mintVerifiedL8Profile", "newVerifiedL8Profile", "createVerifiedL8Profile", "constructVerifiedL8Profile",
		"MintVerifiedL8Profile", "NewVerifiedL8Profile", "CreateVerifiedL8Profile", "ConstructVerifiedL8Profile",
		"mintVerifiedL8Distribution", "newVerifiedL8Distribution", "createVerifiedL8Distribution", "constructVerifiedL8Distribution",
		"MintVerifiedL8Distribution", "NewVerifiedL8Distribution", "CreateVerifiedL8Distribution", "ConstructVerifiedL8Distribution",
		"mintVerifiedL8AssetLease", "newVerifiedL8AssetLease", "createVerifiedL8AssetLease", "constructVerifiedL8AssetLease",
		"MintVerifiedL8AssetLease", "NewVerifiedL8AssetLease", "CreateVerifiedL8AssetLease", "ConstructVerifiedL8AssetLease",
		"AcquireL8AssetLease", "PrepareLaunch", "l8PolicyCompositionMutationCases":
		return name, true
	default:
		return name, l8D2ForbiddenPolicyCompositionAuthorityAPI(name)
	}
}

func l8D2ForbiddenPolicyCompositionAuthorityAPI(name string) bool {
	switch name {
	case "sealVerifiedL8Profile", "sealVerifiedL8Distribution":
		return false
	}
	if name == "AcquireL8AssetLease" || name == "PrepareLaunch" {
		return true
	}
	lower := strings.ToLower(name)
	for _, authority := range []string{"verifiedl8profile", "verifiedl8distribution", "verifieddistribution", "verifiedl8assetlease"} {
		if !strings.Contains(lower, authority) {
			continue
		}
		for _, verb := range []string{"mint", "new", "create", "construct", "make", "build", "issue", "seal", "acquire", "prepare", "remint"} {
			if strings.HasPrefix(lower, verb) {
				return true
			}
		}
	}
	return false
}

func l8D2NamesL8PolicyCompositionAuthority(name string) bool {
	lower := strings.ToLower(name)
	for _, authority := range []string{"verifiedl8profile", "verifiedl8distribution", "verifieddistribution", "verifiedl8assetlease"} {
		if strings.Contains(lower, authority) {
			return true
		}
	}
	return false
}

func l8D2PolicyCompositionAuthorityDefinitionAllowed(function *ast.FuncDecl) bool {
	if function == nil {
		return false
	}
	switch function.Name.Name {
	case "sealVerifiedL8Profile":
		return function.Recv == nil &&
			l8D2ExactNamedFields(function.Type.Params, []string{"descriptorFingerprint:[32]byte", "evidenceFingerprint:[32]byte", "imageSHA256:[32]byte", "policyComposition:l8VerifiedPolicyCompositionDigests"}) &&
			l8D2ExactNamedFields(function.Type.Results, []string{"<unnamed>:VerifiedL8Profile", "<unnamed>:error"})
	case "sealVerifiedL8Distribution":
		return function.Recv == nil &&
			l8D2ExactNamedFields(function.Type.Params, []string{"profile:VerifiedL8Profile", "evidenceFingerprint:[32]byte", "policyComposition:l8VerifiedPolicyCompositionDigests", "manifest:assetbuild.DistributionManifest", "provenance:assetbuild.Provenance", "descriptor:assets.LaunchDescriptor", "rootDir:string"}) &&
			l8D2ExactNamedFields(function.Type.Results, []string{"<unnamed>:VerifiedDistribution"})
	case "AcquireL8AssetLease":
		return l8D2ExactReceiverType(function, "VerifiedDistribution") &&
			l8D2ExactNamedFields(function.Type.Params, nil) &&
			l8D2ExactNamedFields(function.Type.Results, []string{"<unnamed>:*VerifiedL8AssetLease", "<unnamed>:error"})
	case "PrepareLaunch":
		return l8D2ExactPointerReceiverType(function, "VerifiedL8AssetLease")
	default:
		return false
	}
}

func l8D2PolicyCompositionAuthorityEscapeIssues(function *ast.FuncDecl, parents map[ast.Node]ast.Node, authorityTypes map[string]struct{}) []string {
	if function == nil || function.Body == nil {
		return nil
	}
	var issues []string
	if l8D2FieldListContainsPolicyCompositionAuthority(function.Type.Results, authorityTypes) && !l8D2PolicyCompositionAuthorityResultAllowed(function) {
		issues = append(issues, "L8 authority is returned from an alternate function or getter")
	}
	if (l8D2FieldListContainsPolicyCompositionAuthority(function.Type.Params, authorityTypes) || l8D2FieldListContainsPolicyCompositionAuthority(function.Recv, authorityTypes)) && !l8D2PolicyCompositionAuthorityParameterAllowed(function) {
		issues = append(issues, "L8 authority is accepted by an arbitrary helper")
	}
	authorityNames := l8D2PolicyCompositionAuthorityParameterNames(function, authorityTypes)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for _, right := range typed.Rhs {
				if l8D2ExpressionCarriesPolicyCompositionAuthority(right, authorityNames, authorityTypes) && !l8D2ExactIssuerProfileAssignment(function, typed) {
					issues = append(issues, "L8 authority is staged, copied, aliased, or assigned")
				}
			}
			for _, left := range typed.Lhs {
				if identifier, ok := left.(*ast.Ident); ok {
					for _, right := range typed.Rhs {
						if l8D2ExpressionCarriesPolicyCompositionAuthority(right, authorityNames, authorityTypes) {
							authorityNames[identifier.Name] = struct{}{}
						}
					}
				}
			}
		case *ast.DeclStmt:
			general, ok := typed.Decl.(*ast.GenDecl)
			if !ok {
				break
			}
			for _, specification := range general.Specs {
				value, valueOK := specification.(*ast.ValueSpec)
				if !valueOK {
					continue
				}
				carries := l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(value.Type, authorityTypes)
				for _, expression := range value.Values {
					carries = carries || l8D2ExpressionCarriesPolicyCompositionAuthority(expression, authorityNames, authorityTypes)
				}
				if carries {
					issues = append(issues, "L8 authority is staged in a local declaration")
					for _, name := range value.Names {
						authorityNames[name.Name] = struct{}{}
					}
				}
			}
		case *ast.SendStmt:
			if l8D2ExpressionCarriesPolicyCompositionAuthority(typed.Value, authorityNames, authorityTypes) {
				issues = append(issues, "L8 authority is sent through a channel")
			}
		case *ast.FuncLit:
			if l8D2NodeReferencesPolicyCompositionAuthority(typed.Body, authorityNames, authorityTypes) {
				issues = append(issues, "L8 authority is captured or returned through a closure")
			}
		case *ast.CallExpr:
			if selector, ok := typed.Fun.(*ast.SelectorExpr); ok && l8D2ExpressionCarriesPolicyCompositionAuthority(selector.X, authorityNames, authorityTypes) && !l8D2AllowedPolicyCompositionAuthorityCall(function, typed) {
				issues = append(issues, "L8 authority is used as the receiver of an arbitrary helper: "+function.Name.Name+":"+l8D2CompactGo(l8D2RenderNode(typed)))
			}
			for _, argument := range typed.Args {
				if l8D2ExpressionCarriesPolicyCompositionAuthority(argument, authorityNames, authorityTypes) && !l8D2AllowedPolicyCompositionAuthorityCall(function, typed) {
					issues = append(issues, "L8 authority is passed to an arbitrary helper or container: "+function.Name.Name+":"+l8D2CompactGo(l8D2RenderNode(typed)))
				}
			}
		case *ast.CompositeLit:
			if l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(typed.Type, authorityTypes) && !l8D2PolicyCompositionAuthorityConstructionDirectlyReturned(typed, parents) {
				issues = append(issues, "L8 authority construction is not the exact direct returned result")
			}
		case *ast.ReturnStmt:
			for _, result := range typed.Results {
				if l8D2ExpressionCarriesPolicyCompositionAuthority(result, authorityNames, authorityTypes) && !l8D2PolicyCompositionAuthorityResultAllowed(function) {
					issues = append(issues, "L8 authority is returned through an interface, selector, or alternate result")
				}
			}
		}
		return true
	})
	return issues
}

func l8D2ExactDirectAuthorityReturn(function *ast.FuncDecl, authorityType string, withError bool) bool {
	if function == nil || function.Body == nil || len(function.Body.List) != 1 || !l8D2PolicyCompositionAuthorityDefinitionAllowed(function) {
		return false
	}
	returned, ok := function.Body.List[0].(*ast.ReturnStmt)
	wantResults := 1
	if withError {
		wantResults = 2
	}
	if !ok || len(returned.Results) != wantResults || !l8D2DirectAuthorityComposite(returned.Results[0], authorityType) {
		return false
	}
	return !withError || l8D2CompactGo(l8D2RenderNode(returned.Results[1])) == "nil"
}

func l8D2AllAuthoritySuccessReturnsDirect(function *ast.FuncDecl, authorityType string) bool {
	valid := true
	foundSuccess := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		returned, ok := node.(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 2 {
			return true
		}
		first := l8D2CompactGo(l8D2RenderNode(returned.Results[0]))
		if first == "nil" {
			return true
		}
		if l8D2CompactGo(l8D2RenderNode(returned.Results[1])) != "nil" || !l8D2DirectAuthorityComposite(returned.Results[0], authorityType) {
			valid = false
			return false
		}
		foundSuccess = true
		return true
	})
	return valid && foundSuccess
}

func l8D2DirectAuthorityComposite(expression ast.Expr, authorityType string) bool {
	if address, ok := expression.(*ast.UnaryExpr); ok && address.Op == token.AND {
		expression = address.X
	}
	literal, ok := expression.(*ast.CompositeLit)
	return ok && l8D2PolicyCompositionAuthorityTypeName(literal.Type) == authorityType
}

func l8D2PolicyCompositionAuthorityResultAllowed(function *ast.FuncDecl) bool {
	if function == nil {
		return false
	}
	switch function.Name.Name {
	case "VerifyL8DistributionBundle", "sealVerifiedL8Profile", "sealVerifiedL8Distribution":
		return function.Recv == nil
	case "L8Profile", "AcquireL8AssetLease":
		return l8D2ExactReceiverType(function, "VerifiedDistribution")
	case "PrepareLaunch":
		return l8D2ExactPointerReceiverType(function, "VerifiedL8AssetLease")
	default:
		return false
	}
}

func l8D2PolicyCompositionAuthorityParameterAllowed(function *ast.FuncDecl) bool {
	if function == nil {
		return false
	}
	switch function.Name.Name {
	case "VerifyL8DistributionBundle":
		return function.Recv == nil
	case "sealVerifiedL8Distribution", "VerifiedL8ProfileMatches", "VerifiedL8ProfileMatchesLease":
		return function.Recv == nil
	case "L8Profile", "AcquireL8AssetLease":
		return l8D2ExactReceiverType(function, "VerifiedDistribution")
	case "ConfirmCurrent", "PrepareLaunch", "Close", "confirmCurrentLocked", "confirmSourceLocked":
		return l8D2ExactPointerReceiverType(function, "VerifiedL8AssetLease")
	default:
		return false
	}
}

func l8D2FieldListContainsPolicyCompositionAuthority(fields *ast.FieldList, authorityTypes map[string]struct{}) bool {
	if fields == nil {
		return false
	}
	for _, field := range fields.List {
		if l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(field.Type, authorityTypes) {
			return true
		}
	}
	return false
}

func l8D2PolicyCompositionAuthorityParameterNames(function *ast.FuncDecl, authorityTypes map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for _, fields := range []*ast.FieldList{function.Recv, function.Type.Params} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			if !l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(field.Type, authorityTypes) {
				continue
			}
			for _, name := range field.Names {
				result[name.Name] = struct{}{}
			}
		}
	}
	return result
}

func l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(expression ast.Expr, authorityTypes map[string]struct{}) bool {
	if expression == nil {
		return false
	}
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok {
			_, found = authorityTypes[identifier.Name]
			if found {
				return false
			}
		}
		return !found
	})
	return found
}

func l8D2ExpressionCarriesPolicyCompositionAuthority(expression ast.Expr, names map[string]struct{}, authorityTypes map[string]struct{}) bool {
	if expression == nil || l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(expression, authorityTypes) {
		return expression != nil && l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(expression, authorityTypes)
	}
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok {
			_, found = names[identifier.Name]
		}
		return !found
	})
	return found
}

func l8D2NodeReferencesPolicyCompositionAuthority(node ast.Node, names map[string]struct{}, authorityTypes map[string]struct{}) bool {
	found := false
	ast.Inspect(node, func(current ast.Node) bool {
		if expression, ok := current.(ast.Expr); ok && l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(expression, authorityTypes) {
			found = true
			return false
		}
		identifier, ok := current.(*ast.Ident)
		if ok {
			_, found = names[identifier.Name]
		}
		return !found
	})
	return found
}

func l8D2PolicyCompositionAuthorityConstructionDirectlyReturned(node ast.Node, parents map[ast.Node]ast.Node) bool {
	for current := node; current != nil; current = parents[current] {
		switch parent := parents[current].(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.CompositeLit, *ast.KeyValueExpr, *ast.UnaryExpr, *ast.ParenExpr:
			continue
		case nil:
			return false
		default:
			_ = parent
			return false
		}
	}
	return false
}

func l8D2ExactIssuerProfileAssignment(function *ast.FuncDecl, assignment *ast.AssignStmt) bool {
	return function != nil && function.Name.Name == "VerifyL8DistributionBundle" && function.Recv == nil && l8D2CompactGo(l8D2RenderNode(assignment)) == "verifiedL8Profile,err:=sealVerifiedL8Profile(descriptorFingerprint,evidenceFingerprint,imageSHA256,derivedPolicyComposition)"
}

func l8D2AllowedPolicyCompositionAuthorityCall(function *ast.FuncDecl, call *ast.CallExpr) bool {
	name := l8D2CompactGo(l8D2RenderNode(call.Fun))
	if function != nil && function.Name.Name == "VerifyL8DistributionBundle" && name == "sealVerifiedL8Distribution" {
		return true
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if l8D2ExactPointerReceiverType(function, "VerifiedL8AssetLease") {
			rendered := l8D2CompactGo(l8D2RenderNode(call))
			switch function.Name.Name {
			case "ConfirmCurrent":
				if rendered == "lease.confirmCurrentLocked(descriptor)" {
					return true
				}
			case "PrepareLaunch":
				if rendered == "lease.confirmCurrentLocked(descriptor)" || rendered == "lease.confirmSourceLocked()" {
					return true
				}
			case "confirmCurrentLocked":
				if rendered == "lease.confirmSourceLocked()" {
					return true
				}
			}
		}
		switch selector.Sel.Name {
		case "L8Profile", "AcquireL8AssetLease", "ConfirmCurrent", "PrepareLaunch", "Close":
			return true
		}
	}
	switch name {
	case "VerifiedL8ProfileMatches", "VerifiedL8ProfileMatchesLease":
		return true
	default:
		return false
	}
}

func l8D2PolicyCompositionAuthorityTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		switch typed.Name {
		case "VerifiedL8Profile", "VerifiedDistribution", "VerifiedL8AssetLease",
			"verifiedL8ProfileSeal", "verifiedL8PolicyAuthorityBindings", "verifiedL8ProfileCorrelation",
			"verifiedL8LeaseCorrelation", "verifiedL8AssetLeaseState":
			return typed.Name
		}
	case *ast.StarExpr:
		return l8D2PolicyCompositionAuthorityTypeName(typed.X)
	}
	return ""
}

func l8D2BasePolicyCompositionAuthorityTypes() map[string]struct{} {
	result := make(map[string]struct{})
	for _, name := range []string{
		"VerifiedL8Profile", "VerifiedL8AssetLease",
		"verifiedL8ProfileSeal", "verifiedL8PolicyAuthorityBindings", "verifiedL8ProfileCorrelation",
		"verifiedL8LeaseCorrelation", "verifiedL8AssetLeaseState",
	} {
		result[name] = struct{}{}
	}
	return result
}

func l8D2PolicyCompositionAuthorityTypesForSources(sources map[string]string) map[string]struct{} {
	result := l8D2BasePolicyCompositionAuthorityTypes()
	definitions := make(map[string][]ast.Expr)
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		source := sources[path]
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			continue
		}
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				if typeSpec, ok := specification.(*ast.TypeSpec); ok {
					definitions[typeSpec.Name.Name] = append(definitions[typeSpec.Name.Name], typeSpec.Type)
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		names := make([]string, 0, len(definitions))
		for name := range definitions {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if name == "VerifiedDistribution" {
				continue
			}
			if _, alreadyKnown := result[name]; alreadyKnown {
				continue
			}
			for _, definition := range definitions[name] {
				if l8D2ExpressionContainsPolicyCompositionAuthorityTypeWithTypes(definition, result) {
					result[name] = struct{}{}
					changed = true
					break
				}
			}
		}
	}
	return result
}

func l8D2PolicyCompositionPackageDeclarationIssues(sources map[string]string) []string {
	counts := map[string]int{
		"sealVerifiedL8Profile":      0,
		"sealVerifiedL8Distribution": 0,
		"AcquireL8AssetLease":        0,
	}
	var issues []string
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if strings.HasSuffix(filepath.Base(path), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, sources[path], parser.ParseComments)
		if err != nil {
			issues = append(issues, "parse package declaration source: "+filepath.Base(path))
			continue
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, protected := counts[function.Name.Name]; !protected {
				continue
			}
			counts[function.Name.Name]++
			if !l8D2PolicyCompositionAuthorityDefinitionAllowed(function) {
				issues = append(issues, "designated L8 authority declaration signature/receiver is not exact: "+function.Name.Name)
			}
		}
	}
	for _, name := range []string{"sealVerifiedL8Profile", "sealVerifiedL8Distribution", "AcquireL8AssetLease"} {
		if counts[name] != 1 {
			issues = append(issues, "designated L8 authority declaration count across all build contexts is not exactly one: "+name)
		}
	}
	return issues
}

func l8D2UnderlyingPolicyCompositionFixtureIssues(source string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), "l8_distribution_policy_composition_fixture_test.go", source, parser.ParseComments)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var issues []string
	if len(parsed.Imports) != 1 || !l8D2HasExactImport(parsed, "testing", "testing") {
		issues = append(issues, "underlying fixture source imports are not exact")
	}
	if len(parsed.Decls) != 3 {
		issues = append(issues, "underlying fixture declaration topology is not exact")
	}
	builder := l8D2TopLevelFunction(parsed, "materializeValidL8DistributionRequestFixture")
	wantBuilder := `{
		t.Helper()
		request := buildCompleteValidL8DistributionRequestFixture(t)
		if _, err := VerifyL8DistributionBundle(request); err != nil { t.Fatalf("materialized L8 fixture is invalid: %v", err) }
		return request
	}`
	if builder == nil || builder.Recv != nil || builder.Type.TypeParams != nil || !l8D2ExactNamedFields(builder.Type.Params, []string{"t:*testing.T"}) || !l8D2ExactNamedFields(builder.Type.Results, []string{"<unnamed>:L8DistributionRequest"}) || builder.Body == nil || l8D2CompactGo(l8D2RenderNode(builder.Body)) != l8D2CompactGo(wantBuilder) {
		issues = append(issues, "underlying valid L8 fixture builder is absent, skippable, aliased, or unchecked")
	}
	mutator := l8D2TopLevelFunction(parsed, "replaceL8DistributionPolicyCompositionField")
	wantMutator := `{ return rewriteExactL8PolicyCompositionField(request, document, field, replacement) }`
	if mutator == nil || mutator.Recv != nil || mutator.Type.TypeParams != nil || !l8D2ExactNamedFields(mutator.Type.Params, []string{"request:DistributionRequest", "document:string", "field:string", "replacement:string"}) || !l8D2ExactNamedFields(mutator.Type.Results, []string{"<unnamed>:error"}) || mutator.Body == nil || l8D2CompactGo(l8D2RenderNode(mutator.Body)) != l8D2CompactGo(wantMutator) {
		issues = append(issues, "underlying L8 policy-composition mutator is absent, no-op, fixed-field, aliased, or argument-disconnected")
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := l8D2CompactGo(l8D2RenderNode(call.Fun))
			if name == "t.Skip" || name == "t.Skipf" || name == "t.SkipNow" || name == "runtime.Goexit" {
				issues = append(issues, "underlying L8 fixture helper may not skip or terminate its test")
			}
			return true
		})
	}
	return issues
}

func l8D2FileContainsTestTermination(source string, file *ast.File) bool {
	if strings.Contains(source, "go:linkname") {
		return true
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow" || (l8D2CompactGo(l8D2RenderNode(selector.X)) == "runtime" && selector.Sel.Name == "Goexit") {
				found = true
				return false
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return !found
		}
		name := l8D2CompactGo(l8D2RenderNode(call.Fun))
		if name == "runtime.Goexit" || strings.HasSuffix(name, ".Skip") || strings.HasSuffix(name, ".Skipf") || strings.HasSuffix(name, ".SkipNow") {
			found = true
		}
		return !found
	})
	return found
}

func l8D2PolicyCompositionSourcesContainPartialLanding(sources map[string]string) bool {
	protected := map[string]struct{}{
		"sealVerifiedL8Profile":                        {},
		"sealVerifiedL8Distribution":                   {},
		"AcquireL8AssetLease":                          {},
		"materializeValidL8DistributionRequestFixture": {},
		"replaceL8DistributionPolicyCompositionField":  {},
	}
	for path, source := range sources {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			continue
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				if _, matched := protected[function.Name.Name]; matched {
					return true
				}
			}
		}
	}
	return false
}

func l8D2PolicyCompositionPackageFixtureDeclarationIssues(sources map[string]string) []string {
	counts := map[string]int{
		"materializeValidL8DistributionRequestFixture": 0,
		"replaceL8DistributionPolicyCompositionField":  0,
	}
	var issues []string
	for path, source := range sources {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			issues = append(issues, "parse package fixture declaration source: "+filepath.Base(path))
			continue
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, protected := counts[function.Name.Name]; protected {
				counts[function.Name.Name]++
			}
		}
	}
	for _, name := range []string{"materializeValidL8DistributionRequestFixture", "replaceL8DistributionPolicyCompositionField"} {
		if counts[name] != 1 {
			issues = append(issues, "underlying L8 fixture declaration count across all build contexts is not exactly one: "+name)
		}
	}
	return issues
}

func l8D2PolicyCompositionAuthorityLiteralAllowed(function *ast.FuncDecl, authorityType string) bool {
	if function == nil {
		return false
	}
	switch authorityType {
	case "VerifiedL8Profile", "verifiedL8ProfileSeal", "verifiedL8ProfileCorrelation":
		return l8D2PolicyCompositionAuthorityDefinitionAllowed(function) && (function.Name.Name == "sealVerifiedL8Profile" || function.Name.Name == "PrepareLaunch")
	case "verifiedL8PolicyAuthorityBindings":
		return l8D2PolicyCompositionAuthorityDefinitionAllowed(function) && (function.Name.Name == "sealVerifiedL8Profile" || function.Name.Name == "AcquireL8AssetLease")
	case "VerifiedDistribution":
		return l8D2PolicyCompositionAuthorityDefinitionAllowed(function) && function.Name.Name == "sealVerifiedL8Distribution"
	case "VerifiedL8AssetLease", "verifiedL8LeaseCorrelation", "verifiedL8AssetLeaseState":
		return l8D2PolicyCompositionAuthorityDefinitionAllowed(function) && function.Name.Name == "AcquireL8AssetLease"
	default:
		return false
	}
}

func l8D2ExactReceiverType(function *ast.FuncDecl, want string) bool {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 {
		return false
	}
	identifier, ok := function.Recv.List[0].Type.(*ast.Ident)
	return ok && identifier.Name == want
}

func l8D2ExactPointerReceiverType(function *ast.FuncDecl, want string) bool {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 {
		return false
	}
	pointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	identifier, ok := pointer.X.(*ast.Ident)
	return ok && identifier.Name == want
}

func l8D2TopLevelFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name {
			return function
		}
	}
	return nil
}

func l8D2CompactGo(value string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(value)
}

func l8D2HasExactImport(file *ast.File, name, path string) bool {
	count := 0
	for _, imported := range file.Imports {
		if strings.Trim(imported.Path.Value, `"`) != path {
			continue
		}
		count++
		effectiveName := filepath.Base(path)
		if imported.Name != nil {
			effectiveName = imported.Name.Name
		}
		if effectiveName != name {
			return false
		}
	}
	return count == 1
}

func l8D2FindExactTopLevelStatementAfter(body *ast.BlockStmt, expected string, after int) int {
	for index, statement := range body.List {
		if index > after && l8D2CompactGo(l8D2RenderNode(statement)) == l8D2CompactGo(expected) {
			return index
		}
	}
	return -1
}

func l8D2StatementCanIssueL8Authority(statement ast.Stmt) bool {
	canIssue := false
	ast.Inspect(statement, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.ReturnStmt:
			if len(typed.Results) != 2 || l8D2CompactGo(l8D2RenderNode(typed.Results[0])) != "VerifiedDistribution{}" || l8D2CompactGo(l8D2RenderNode(typed.Results[1])) == "nil" {
				canIssue = true
			}
		case *ast.CallExpr:
			name := l8D2CompactGo(l8D2RenderNode(typed.Fun))
			switch name {
			case "buildL8EvidenceFingerprint", "sealVerifiedL8Profile", "mintVerifiedL8AssetLease", "sealVerifiedL8Distribution", "AcquireL8AssetLease", "PrepareLaunch":
				canIssue = true
			}
		}
		return !canIssue
	})
	return canIssue
}

func l8D2ExactPolicyCompositionMutationDeclarations(file *ast.File) bool {
	if len(file.Decls) != 8 {
		return false
	}
	importDecl, ok := file.Decls[0].(*ast.GenDecl)
	if !ok || importDecl.Tok != token.IMPORT {
		return false
	}
	wantFunctions := []string{
		"TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations",
		"validL8DistributionRequest",
		"mutateL8PolicyCompositionFixture",
		"snapshotL8PolicyCompositionFields",
		"canonicalL8NonPolicyDocumentSHA256",
		"assertExactlyOneL8PolicyCompositionFieldChanged",
		"assertL8PolicyCompositionCorrelationMismatch",
	}
	for index, name := range wantFunctions {
		function, functionOK := file.Decls[index+1].(*ast.FuncDecl)
		if !functionOK || function.Name.Name != name {
			return false
		}
	}
	return true
}

func l8D2AssignmentCount(body *ast.BlockStmt, name string) int {
	count := 0
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, left := range assignment.Lhs {
			if identifier, ok := left.(*ast.Ident); ok && identifier.Name == name {
				count++
			}
		}
		return true
	})
	return count
}

func l8D2CheckPolicyCompositionProductTopology(t *testing.T) {
	t.Helper()
	productRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "syscallpolicy")
	correlationPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "l8_policy_composition_correlation.go")
	issuerPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "l8_distribution_verifier.go")
	mutationPath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "l8_distribution_verifier_test.go")
	fixturePath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "l8_distribution_policy_composition_fixture_test.go")
	resolverRoot := filepath.Dir(issuerPath)
	sources := make(map[string]string)
	if err := filepath.WalkDir(resolverRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != resolverRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".s") {
			t.Errorf("localresolver policy-composition authority/reference topology violation in %s: assembly is forbidden", filepath.ToSlash(path))
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sources[path] = string(payload)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, productErr := os.Stat(productRoot)
	_, correlationErr := os.Stat(correlationPath)
	_, issuerErr := os.Stat(issuerPath)
	_, mutationErr := os.Stat(mutationPath)
	_, fixtureErr := os.Stat(fixturePath)
	productExists := productErr == nil
	correlationExists := correlationErr == nil
	issuerExists := issuerErr == nil
	mutationExists := mutationErr == nil
	fixtureExists := fixtureErr == nil
	for name, statErr := range map[string]error{"syscallpolicy": productErr, "correlation helper": correlationErr, "issuer": issuerErr, "mutation test": mutationErr, "fixture helpers": fixtureErr} {
		if statErr != nil && !os.IsNotExist(statErr) {
			t.Fatalf("stat %s: %v", name, statErr)
		}
	}
	if !productExists && !correlationExists && !issuerExists && !mutationExists && !fixtureExists && !l8D2PolicyCompositionSourcesContainPartialLanding(sources) {
		return
	}
	if !productExists || !correlationExists || !issuerExists || !mutationExists || !fixtureExists {
		t.Fatal("syscallpolicy, exact correlation helper, exact L8 issuer, exact policy-composition mutation test, and exact underlying fixture helper file must appear together")
	}
	issuerSource, err := os.ReadFile(issuerPath)
	if err != nil {
		t.Fatal(err)
	}
	if issues := l8D2PolicyCompositionIssuerASTIssues(string(issuerSource)); len(issues) != 0 {
		t.Fatalf("production L8 issuer violates policy-composition dataflow closure: %v", issues)
	}
	mutationSource, err := os.ReadFile(mutationPath)
	if err != nil {
		t.Fatal(err)
	}
	if issues := l8D2PolicyCompositionMutationASTIssues(string(mutationSource)); len(issues) != 0 {
		t.Fatalf("production L8 mutation test violates policy-composition matrix closure: %v", issues)
	}
	fixtureSource, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if issues := l8D2UnderlyingPolicyCompositionFixtureIssues(string(fixtureSource)); len(issues) != 0 {
		t.Fatalf("production L8 underlying fixture helpers violate semantic closure: %v", issues)
	}
	if issues := l8D2PolicyCompositionPackageDeclarationIssues(sources); len(issues) != 0 {
		t.Errorf("localresolver all-build-context L8 authority declaration topology violation: %v", issues)
	}
	if issues := l8D2PolicyCompositionPackageFixtureDeclarationIssues(sources); len(issues) != 0 {
		t.Errorf("localresolver all-build-context L8 fixture declaration topology violation: %v", issues)
	}
	authorityTypes := l8D2PolicyCompositionAuthorityTypesForSources(sources)
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if issues := l8D2PolicyCompositionExternalReferenceIssuesWithTypes(path, sources[path], authorityTypes); len(issues) != 0 {
			t.Errorf("localresolver policy-composition authority/reference topology violation in %s: %v", filepath.ToSlash(path), issues)
		}
	}
}

func l8D2PolicyCompositionASTIssues(source string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), "policy_composition.go", source, 0)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	functions := make(map[string]*ast.FuncDecl)
	typesByName := make(map[string]ast.Expr)
	imports := make(map[string]string)
	for _, imported := range parsed.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		imports[name] = path
	}
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
			functions[function.Name.Name] = function
		}
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			if typeSpec, ok := specification.(*ast.TypeSpec); ok {
				typesByName[typeSpec.Name.Name] = typeSpec.Type
			}
		}
	}

	var issues []string
	if len(parsed.Imports) != 3 || imports["subtle"] != "crypto/subtle" || imports["assetbuild"] != "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build" || imports["syscallpolicy"] != "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy" {
		issues = append(issues, "correlation source imports are not authority-bound")
	}
	structure, ok := typesByName["l8VerifiedPolicyCompositionDigests"].(*ast.StructType)
	if !ok || !l8D2ExactNamedFields(structure.Fields, []string{
		"workloadSnapshotSHA256:[32]byte",
		"runtimeProfileSHA256:[32]byte",
		"policyArtifactSHA256:[32]byte",
		"policySourceLockSHA256:[32]byte",
		"policyBinaryBindingSetSHA256:[32]byte",
		"pinnedCallsiteEvidenceSHA256:[32]byte",
	}) {
		issues = append(issues, "policy-composition digest layout/order is not exact")
	}
	derive := functions["deriveL8PolicyCompositionDigests"]
	if derive == nil || !l8D2ExactNamedFields(derive.Type.Params, []string{"artifact:syscallpolicy.VerifiedPolicyArtifact", "evidence:syscallpolicy.PinnedCallsiteEvidenceSet"}) || !l8D2ExactNamedFields(derive.Type.Results, []string{"<unnamed>:l8VerifiedPolicyCompositionDigests"}) {
		issues = append(issues, "derivation signature is not exact")
	} else if derive.Body == nil || len(derive.Body.List) != 1 {
		issues = append(issues, "derivation must be one direct return")
	} else if returned, ok := derive.Body.List[0].(*ast.ReturnStmt); !ok || len(returned.Results) != 1 {
		issues = append(issues, "derivation must directly return one value")
	} else if literal, ok := returned.Results[0].(*ast.CompositeLit); !ok || l8D2RenderNode(literal.Type) != "l8VerifiedPolicyCompositionDigests" {
		issues = append(issues, "derivation must return the canonical digest record")
	} else {
		expectedFields := []string{
			"workloadSnapshotSHA256:artifact.Workload().SHA256()",
			"runtimeProfileSHA256:artifact.Runtime().SHA256()",
			"policyArtifactSHA256:artifact.SHA256()",
			"policySourceLockSHA256:artifact.SourceLockSHA256()",
			"policyBinaryBindingSetSHA256:evidence.BinaryBindings().SHA256()",
			"pinnedCallsiteEvidenceSHA256:evidence.SHA256()",
		}
		if len(literal.Elts) != len(expectedFields) {
			issues = append(issues, "derivation field count/order is not exact")
		} else {
			for index, element := range literal.Elts {
				if strings.ReplaceAll(l8D2RenderNode(element), " ", "") != expectedFields[index] {
					issues = append(issues, "derivation field chain/order is not exact")
					break
				}
			}
		}
	}

	equal := functions["l8PolicyCompositionDigestsEqual"]
	expectedComparisons := []string{
		"matches &= subtle.ConstantTimeCompare(left.workloadSnapshotSHA256[:], right.workloadSnapshotSHA256[:])",
		"matches &= subtle.ConstantTimeCompare(left.runtimeProfileSHA256[:], right.runtimeProfileSHA256[:])",
		"matches &= subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])",
		"matches &= subtle.ConstantTimeCompare(left.policySourceLockSHA256[:], right.policySourceLockSHA256[:])",
		"matches &= subtle.ConstantTimeCompare(left.policyBinaryBindingSetSHA256[:], right.policyBinaryBindingSetSHA256[:])",
		"matches &= subtle.ConstantTimeCompare(left.pinnedCallsiteEvidenceSHA256[:], right.pinnedCallsiteEvidenceSHA256[:])",
	}
	if equal == nil || equal.Body == nil || len(equal.Body.List) != 8 {
		issues = append(issues, "equality must have one accumulator, six comparisons, and one return")
	} else {
		if l8D2RenderNode(equal.Body.List[0]) != "matches := 1" {
			issues = append(issues, "equality accumulator is not exact")
		}
		for index, expected := range expectedComparisons {
			if l8D2RenderNode(equal.Body.List[index+1]) != expected {
				issues = append(issues, "constant-time comparison chain/order is not exact")
				break
			}
		}
		if l8D2RenderNode(equal.Body.List[7]) != "return matches == 1" {
			issues = append(issues, "equality result is not the accumulated result")
		}
	}

	validate := functions["validateL8PolicyCompositionCorrelation"]
	wantValidation := []string{
		"if !l8PolicyCompositionDigestsEqual(derived, manifest) {\n\treturn l8PolicyCompositionCorrelationMismatch()\n}",
		"if !l8PolicyCompositionDigestsEqual(derived, provenance) {\n\treturn l8PolicyCompositionCorrelationMismatch()\n}",
		"if !l8PolicyCompositionDigestsEqual(derived, finalInspection) {\n\treturn l8PolicyCompositionCorrelationMismatch()\n}",
		"return nil",
	}
	if validate == nil || !l8D2ExactNamedFields(validate.Type.Params, []string{"derived:l8VerifiedPolicyCompositionDigests", "manifest:l8VerifiedPolicyCompositionDigests", "provenance:l8VerifiedPolicyCompositionDigests", "finalInspection:l8VerifiedPolicyCompositionDigests"}) || !l8D2ExactNamedFields(validate.Type.Results, []string{"<unnamed>:error"}) {
		issues = append(issues, "correlation validation signature is not exact")
	} else if validate.Body == nil || len(validate.Body.List) != len(wantValidation) {
		issues = append(issues, "correlation validation statement count/order is not exact")
	} else {
		for index, want := range wantValidation {
			if l8D2RenderNode(validate.Body.List[index]) != want {
				issues = append(issues, "correlation validation operands/order/error are not exact")
				break
			}
		}
	}
	mismatch := functions["l8PolicyCompositionCorrelationMismatch"]
	wantMismatch := `return &assetbuild.L8ValidationError{Code: assetbuild.L8ValidationCode("correlation_mismatch"), Field: "processComposition"}`
	if mismatch == nil || mismatch.Type.TypeParams != nil || !l8D2ExactNamedFields(mismatch.Type.Params, nil) || !l8D2ExactNamedFields(mismatch.Type.Results, []string{"<unnamed>:error"}) || mismatch.Body == nil || len(mismatch.Body.List) != 1 || l8D2CompactGo(l8D2RenderNode(mismatch.Body.List[0])) != l8D2CompactGo(wantMismatch) {
		issues = append(issues, "correlation mismatch constructor is not the exact sanitized typed error")
	}
	return issues
}

func l8D2ExactNamedFields(fields *ast.FieldList, want []string) bool {
	if fields == nil {
		return len(want) == 0
	}
	var got []string
	for _, field := range fields.List {
		fieldType := l8D2RenderNode(field.Type)
		if len(field.Names) == 0 {
			got = append(got, "<unnamed>:"+fieldType)
			continue
		}
		for _, name := range field.Names {
			got = append(got, name.Name+":"+fieldType)
		}
	}
	return strings.Join(got, ",") == strings.Join(want, ",")
}

func l8D2RenderNode(node any) string {
	var rendered bytes.Buffer
	if err := printer.Fprint(&rendered, token.NewFileSet(), node); err != nil {
		return "<render-error>"
	}
	return rendered.String()
}

type l8DocField struct {
	name string
	typ  string
	tag  string
}

func assertL8DocStruct(t *testing.T, doc, typeName string, expected []l8DocField) {
	t.Helper()
	start := strings.Index(doc, "type "+typeName+" struct {")
	if start < 0 {
		t.Fatalf("L8 contract omits exact %s declaration", typeName)
	}
	rest := doc[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("L8 contract has unterminated %s declaration", typeName)
	}
	source := "package contract\n" + rest[:end+2]
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, typeName+".go", source, 0)
	if err != nil {
		t.Fatalf("parse L8 %s contract: %v", typeName, err)
	}
	declaration, ok := parsed.Decls[0].(*ast.GenDecl)
	if !ok || len(declaration.Specs) != 1 {
		t.Fatalf("L8 %s declaration is not one type spec", typeName)
	}
	typeSpec, ok := declaration.Specs[0].(*ast.TypeSpec)
	if !ok || typeSpec.Name.Name != typeName {
		t.Fatalf("L8 %s declaration has unexpected type spec", typeName)
	}
	structure, ok := typeSpec.Type.(*ast.StructType)
	if !ok || len(structure.Fields.List) != len(expected) {
		t.Fatalf("L8 %s fields=%d, want %d", typeName, len(structure.Fields.List), len(expected))
	}
	for index, field := range structure.Fields.List {
		var rendered bytes.Buffer
		if err := printer.Fprint(&rendered, fileSet, field.Type); err != nil {
			t.Fatalf("render L8 %s field %d: %v", typeName, index, err)
		}
		if rendered.String() != expected[index].typ {
			t.Fatalf("L8 %s field %s type=%q, want %q", typeName, expected[index].name, rendered.String(), expected[index].typ)
		}
		actualName := rendered.String()
		if len(field.Names) == 1 {
			actualName = field.Names[0].Name
		} else if len(field.Names) != 0 {
			t.Fatalf("L8 %s field %d has multiple names", typeName, index)
		}
		if actualName != expected[index].name {
			t.Fatalf("L8 %s field %d name=%q, want %q", typeName, index, actualName, expected[index].name)
		}
		tag := ""
		if field.Tag != nil {
			tag = strings.Trim(field.Tag.Value, "`")
		}
		if tag != expected[index].tag {
			t.Fatalf("L8 %s field %s tag=%q, want %q", typeName, expected[index].name, tag, expected[index].tag)
		}
	}
}

func TestL8D2ImageProfileMintAuthorityStaysNarrow(t *testing.T) {
	buildRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "build")
	issuerRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver")
	firecrackerRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker")
	firecrackerHostRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost")
	rules := []struct {
		marker string
		roots  []string
	}{
		{marker: "ImageProfileL8ProductionCredentials", roots: []string{buildRoot, issuerRoot}},
		{marker: "l8-production-credentials-v1", roots: []string{buildRoot, issuerRoot}},
		{marker: "VerifiedL8Profile", roots: []string{issuerRoot, firecrackerRoot, firecrackerHostRoot}},
		{marker: "VerifiedL8AssetLease", roots: []string{issuerRoot, firecrackerRoot, firecrackerHostRoot}},
	}
	allowed := func(path string, roots []string) bool {
		for _, root := range roots {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	err := filepath.WalkDir("..", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		clean := filepath.Clean(path)
		text := string(payload)
		for _, rule := range rules {
			if strings.Contains(text, rule.marker) && !allowed(clean, rule.roots) {
				t.Errorf("unapproved production file %s contains L8 image-profile marker %q", filepath.ToSlash(path), rule.marker)
			}
		}
		if allowed(clean, []string{issuerRoot}) {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, payload, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "VerifyL8DistributionBundle" {
				t.Errorf("unapproved production file %s references the sole L8 profile issuer", filepath.ToSlash(path))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan L8 image-profile authority: %v", err)
	}
}
