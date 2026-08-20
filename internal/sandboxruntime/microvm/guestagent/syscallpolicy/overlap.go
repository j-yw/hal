package syscallpolicy

import (
	"bytes"
	"encoding/binary"
)

func validateVerifiedPolicyRuleOverlaps(artifact *verifiedArtifact) error {
	if artifact == nil {
		return contractError(ErrorCodeOwnership)
	}
	for baseRole := RoleLaunchBootstrap; baseRole <= RoleWorkload; baseRole++ {
		included := map[Role]bool{baseRole: true}
		for _, ancestry := range artifact.ancestry {
			if ancestry.ancestorRole == baseRole {
				for _, role := range ancestry.descendants {
					included[role] = true
				}
			}
		}
		rules := make([]*verifiedRule, 0)
		for _, rule := range artifact.rules {
			if included[rule.role] {
				rules = append(rules, rule)
			}
		}
		for leftIndex := 0; leftIndex < len(rules); leftIndex++ {
			for rightIndex := leftIndex + 1; rightIndex < len(rules); rightIndex++ {
				left, right := rules[leftIndex], rules[rightIndex]
				if left.syscallNumber != right.syscallNumber || !verifiedRulePredicatesIntersect(left, right) {
					continue
				}
				leftAdapter := left.enforcementPath == EnforcementPathAdapter
				rightAdapter := right.enforcementPath == EnforcementPathAdapter
				if leftAdapter != rightAdapter {
					return contractError(ErrorCodeUnsafeWidening)
				}
				if bytes.Equal(verifiedRuleFilterBytes(left), verifiedRuleFilterBytes(right)) {
					continue
				}
				return contractError(ErrorCodeContradiction)
			}
		}
	}
	return nil
}

func verifiedRuleFilterBytes(rule *verifiedRule) []byte {
	result := make([]byte, 8, 8+len(rule.scalarClauses)*policyScalarClauseBytes)
	binary.BigEndian.PutUint32(result[:4], uint32(rule.syscallNumber))
	result[4] = byte(len(rule.scalarClauses))
	for _, clause := range rule.scalarClauses {
		row := make([]byte, policyScalarClauseBytes)
		row[0] = clause.argumentIndex
		row[1] = byte(clause.operation)
		row[2] = byte(len(clause.values))
		binary.BigEndian.PutUint32(row[4:8], uint32(clause.mismatchAction))
		row[8] = byte(clause.mismatchReason)
		binary.BigEndian.PutUint64(row[12:20], clause.mask)
		for index, value := range clause.values {
			binary.BigEndian.PutUint64(row[20+index*8:28+index*8], value)
		}
		result = append(result, row...)
	}
	return result
}

func verifiedRulePredicatesIntersect(left, right *verifiedRule) bool {
	for argument := uint8(0); argument < 6; argument++ {
		if !scalarClausesIntersect(ruleClauseAt(left, argument), ruleClauseAt(right, argument)) {
			return false
		}
	}
	return true
}

func ruleClauseAt(rule *verifiedRule, argument uint8) *scalarClause {
	for _, clause := range rule.scalarClauses {
		if clause.argumentIndex == argument {
			return clause
		}
	}
	return nil
}

func scalarClausesIntersect(left, right *scalarClause) bool {
	if left == nil || right == nil {
		return true
	}
	if values, ok := finiteClauseValues(left); ok {
		for _, value := range values {
			if clauseMatches(right, value) {
				return true
			}
		}
		return false
	}
	if values, ok := finiteClauseValues(right); ok {
		for _, value := range values {
			if clauseMatches(left, value) {
				return true
			}
		}
		return false
	}
	if left.operation == ScalarNonzero {
		return nonzeroClauseIntersects(right)
	}
	if right.operation == ScalarNonzero {
		return nonzeroClauseIntersects(left)
	}
	if left.operation == ScalarUnsignedRange && right.operation == ScalarUnsignedRange {
		return left.values[0] <= right.values[1] && right.values[0] <= left.values[1]
	}
	if left.operation == ScalarMaskedEqual && right.operation == ScalarMaskedEqual {
		return (left.values[0]^right.values[0])&(left.mask&right.mask) == 0
	}
	if left.operation == ScalarUnsignedRange && right.operation == ScalarMaskedEqual {
		return maskedValueInRange(right.mask, right.values[0], left.values[0], left.values[1])
	}
	if right.operation == ScalarUnsignedRange && left.operation == ScalarMaskedEqual {
		return maskedValueInRange(left.mask, left.values[0], right.values[0], right.values[1])
	}
	return false
}

func finiteClauseValues(clause *scalarClause) ([]uint64, bool) {
	switch clause.operation {
	case ScalarEqual, ScalarOneOf:
		return clause.values, true
	case ScalarZero:
		return []uint64{0}, true
	default:
		return nil, false
	}
}

func nonzeroClauseIntersects(clause *scalarClause) bool {
	switch clause.operation {
	case ScalarNonzero:
		return true
	case ScalarUnsignedRange:
		return clause.values[1] > 0
	case ScalarMaskedEqual:
		return clause.values[0] != 0 || clause.mask != ^uint64(0)
	default:
		return false
	}
}

func maskedValueInRange(mask, value, low, high uint64) bool {
	type state struct {
		bit       int8
		aboveLow  bool
		belowHigh bool
	}
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var search func(int8, bool, bool) bool
	search = func(bit int8, aboveLow, belowHigh bool) bool {
		if bit < 0 {
			return true
		}
		key := state{bit: bit, aboveLow: aboveLow, belowHigh: belowHigh}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		lowBit := (low >> bit) & 1
		highBit := (high >> bit) & 1
		for candidate := uint64(0); candidate <= 1; candidate++ {
			if mask&(uint64(1)<<bit) != 0 && candidate != (value>>bit)&1 {
				continue
			}
			if !aboveLow && candidate < lowBit || !belowHigh && candidate > highBit {
				continue
			}
			if search(bit-1, aboveLow || candidate > lowBit, belowHigh || candidate < highBit) {
				memo[key] = true
				return true
			}
		}
		memo[key] = false
		return false
	}
	return search(63, false, false)
}
