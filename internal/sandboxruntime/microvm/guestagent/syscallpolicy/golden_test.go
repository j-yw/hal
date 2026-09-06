package syscallpolicy

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPolicyGoldenCasesAreCanonicalDefensiveRuleOrderedPositives(t *testing.T) {
	encoded := artifactTestCoherentEnvelopeWithTopology(artifactTestRolesBodyWithPinnedAndExactTransitions(), artifactTestExactAncestryBody(), 9, 1)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{sha256: artifactTestDigest(encoded), issuer: expectedIssuer{issued: true}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(artifact)
	if err != nil {
		t.Fatal(err)
	}

	cases := policy.GoldenCases()
	if len(cases) != len(artifact.Rules()) {
		t.Fatalf("GoldenCases() count = %d, want %d", len(cases), len(artifact.Rules()))
	}
	for index, golden := range cases {
		if !golden.Positive() || golden.Mutation() != 0 || golden.Kind() != GoldenKindSemantic || golden.Expectation() != GoldenExpectationDecision {
			t.Fatalf("case %d is not a semantic positive", index)
		}
		if golden.RuleSHA256() != artifact.Rules()[index].SHA256() || golden.Action() != ActionAllow || golden.Reason() != ReasonExactRule {
			t.Fatalf("case %d does not bind its canonical rule", index)
		}
		if decision := policy.Decide(golden.Input()); !decision.Allowed() || decision.RuleSHA256() != golden.RuleSHA256() {
			t.Fatalf("case %d does not reproduce its decision", index)
		}
		binary := golden.CanonicalBinary()
		if len(binary) < 117 || !bytes.Equal(binary[:5], []byte{'H', 'L', '8', 'G', 2}) || golden.SHA256() == ([32]byte{}) {
			t.Fatalf("case %d canonical encoding is invalid", index)
		}
		digest := golden.SHA256()
		if !strings.HasPrefix(golden.TSV(), hex.EncodeToString(digest[:])) || !strings.HasSuffix(golden.TSV(), "\n") {
			t.Fatalf("case %d TSV is not canonical", index)
		}
	}
	cases[0] = GoldenCase{}
	if !policy.GoldenCases()[0].Positive() {
		t.Fatal("caller mutation changed policy golden cases")
	}
}

func TestGeneratePlusOneIncludesEveryPositiveAndOrderedMutationCatalog(t *testing.T) {
	encoded := artifactTestCoherentEnvelopeWithTopology(artifactTestRolesBodyWithPinnedAndExactTransitions(), artifactTestExactAncestryBody(), 9, 1)
	artifact, err := ImportVerifiedPolicyArtifact(encoded, ExpectedPolicyArtifact{sha256: artifactTestDigest(encoded), issuer: expectedIssuer{issued: true}})
	if err != nil {
		t.Fatal(err)
	}
	cases, err := GeneratePlusOne(artifact)
	if err != nil {
		t.Fatal(err)
	}
	positives := 0
	lastMutation := MutationKind(0)
	for _, golden := range cases {
		if golden.Positive() {
			positives++
			lastMutation = 0
			continue
		}
		if ValidateMutationKind(golden.Mutation()) != nil || golden.Mutation() <= lastMutation {
			t.Fatal("mutations are not in ascending closed-catalog order")
		}
		lastMutation = golden.Mutation()
	}
	if positives < len(artifact.Rules()) {
		t.Fatalf("positive count = %d", positives)
	}
}
