//go:build l8_verified_policy_artifact && l8_verified_pinned_callsite_evidence

package localresolver

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations(t *testing.T) {
	baseline := validL8DistributionRequest(t)
	if _, err := VerifyL8DistributionBundle(baseline); err != nil {
		t.Fatalf("valid L8 baseline rejected: %v", err)
	}
	l8PolicyCompositionMutationCases := [18]struct {
		document string
		field    string
	}{
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
			if _, err := VerifyL8DistributionBundle(request); err != nil {
				t.Fatalf("valid per-case L8 baseline rejected: %v", err)
			}
			before, beforeNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			mutateL8PolicyCompositionFixture(t, &request, mutation.document, mutation.field)
			after, afterNonPolicy := snapshotL8PolicyCompositionFields(t, request)
			assertExactlyOneL8PolicyCompositionFieldChanged(t, before, after, beforeNonPolicy, afterNonPolicy, mutationIndex)
			_, err := VerifyL8DistributionBundle(request)
			assertL8PolicyCompositionCorrelationMismatch(t, err)
			executed++
		})
	}
	if executed != 18 {
		t.Fatalf("executed %d policy-composition mutations, want 18", executed)
	}
}

func validL8DistributionRequest(t *testing.T) L8DistributionRequest {
	t.Helper()
	return materializeValidL8DistributionRequestFixture(t)
}

func mutateL8PolicyCompositionFixture(t *testing.T, request *L8DistributionRequest, document, field string) {
	t.Helper()
	if err := replaceL8DistributionPolicyCompositionField(request.DistributionRequest, document, field, "0101010101010101010101010101010101010101010101010101010101010101"); err != nil {
		t.Fatalf("mutate L8 policy composition: %v", err)
	}
}

func snapshotL8PolicyCompositionFields(t *testing.T, request L8DistributionRequest) ([18]string, [3][32]byte) {
	t.Helper()
	manifest, err := decodeL8DistributionManifest(request.DistributionRequest)
	if err != nil {
		t.Fatalf("decode L8 manifest snapshot: %v", err)
	}
	provenance, err := decodeL8Provenance(request.DistributionRequest)
	if err != nil {
		t.Fatalf("decode L8 provenance snapshot: %v", err)
	}
	finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)
	if err != nil {
		t.Fatalf("decode L8 final-inspection snapshot: %v", err)
	}
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
	if err != nil {
		t.Fatalf("canonicalize non-policy L8 document: %v", err)
	}
	return sha256.Sum256(encoded)
}

func assertExactlyOneL8PolicyCompositionFieldChanged(t *testing.T, before, after [18]string, beforeNonPolicy, afterNonPolicy [3][32]byte, selected int) {
	t.Helper()
	if beforeNonPolicy != afterNonPolicy {
		t.Fatal("non-policy L8 document semantics changed")
	}
	for index := range before {
		if index == selected {
			if before[index] == after[index] {
				t.Fatal("selected policy-composition field did not change")
			}
			if after[index] != "0101010101010101010101010101010101010101010101010101010101010101" {
				t.Fatal("selected policy-composition field is not the exact valid replacement digest")
			}
			continue
		}
		if before[index] != after[index] {
			t.Fatal("non-selected policy-composition field changed")
		}
	}
}

func assertL8PolicyCompositionCorrelationMismatch(t *testing.T, err error) {
	t.Helper()
	var resolverError *Error
	if !errors.As(err, &resolverError) {
		t.Fatal("missing typed resolver error")
	}
	if resolverError.Code != ErrorCodeAssetLockMismatch || resolverError.Field != "processComposition" || resolverError.Role != "" || resolverError.Message != "L8 policy composition correlation mismatch" {
		t.Fatal("unexpected resolver error")
	}
	if !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatal("missing asset-lock sentinel")
	}
	if err.Error() != "local asset resolver failed (asset_lock_mismatch) field=processComposition: L8 policy composition correlation mismatch" {
		t.Fatal("unsafe resolver error text")
	}
}
