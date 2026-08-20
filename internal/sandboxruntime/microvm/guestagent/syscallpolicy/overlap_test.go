package syscallpolicy

import "testing"

func TestScalarClauseIntersectionIsExactAcrossClosedGrammar(t *testing.T) {
	t.Parallel()

	masked := &scalarClause{operation: ScalarMaskedEqual, mask: 0xf0, values: []uint64{0xa0}}
	for _, test := range []struct {
		name  string
		left  *scalarClause
		right *scalarClause
		want  bool
	}{
		{name: "masked value inside range", left: masked, right: &scalarClause{operation: ScalarUnsignedRange, values: []uint64{0xa5, 0xa5}}, want: true},
		{name: "masked value outside range", left: masked, right: &scalarClause{operation: ScalarUnsignedRange, values: []uint64{0xb0, 0xbf}}, want: false},
		{name: "conflicting masks", left: masked, right: &scalarClause{operation: ScalarMaskedEqual, mask: 0xf0, values: []uint64{0xb0}}, want: false},
		{name: "compatible masks", left: masked, right: &scalarClause{operation: ScalarMaskedEqual, mask: 0x0f, values: []uint64{0x05}}, want: true},
		{name: "nonzero excludes exact zero", left: &scalarClause{operation: ScalarNonzero}, right: &scalarClause{operation: ScalarMaskedEqual, mask: ^uint64(0), values: []uint64{0}}, want: false},
		{name: "nonzero permits unconstrained high bit", left: &scalarClause{operation: ScalarNonzero}, right: &scalarClause{operation: ScalarMaskedEqual, mask: ^uint64(0) >> 1, values: []uint64{0}}, want: true},
		{name: "finite one-of", left: &scalarClause{operation: ScalarOneOf, values: []uint64{1, 4}}, right: &scalarClause{operation: ScalarUnsignedRange, values: []uint64{2, 5}}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scalarClausesIntersect(test.left, test.right); got != test.want {
				t.Fatalf("scalarClausesIntersect() = %v, want %v", got, test.want)
			}
			if got := scalarClausesIntersect(test.right, test.left); got != test.want {
				t.Fatalf("reverse scalarClausesIntersect() = %v, want %v", got, test.want)
			}
		})
	}
}
