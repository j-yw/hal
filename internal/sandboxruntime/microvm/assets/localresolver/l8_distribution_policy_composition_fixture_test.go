//go:build l8_verified_policy_artifact && l8_verified_pinned_callsite_evidence

package localresolver

import "testing"

func materializeValidL8DistributionRequestFixture(t *testing.T) L8DistributionRequest {
	t.Helper()
	request := buildCompleteValidL8DistributionRequestFixture(t)
	if _, err := VerifyL8DistributionBundle(request); err != nil {
		t.Fatalf("materialized L8 fixture is invalid: %v", err)
	}
	return request
}

func replaceL8DistributionPolicyCompositionField(request DistributionRequest, document, field, replacement string) error {
	return rewriteExactL8PolicyCompositionField(request, document, field, replacement)
}
