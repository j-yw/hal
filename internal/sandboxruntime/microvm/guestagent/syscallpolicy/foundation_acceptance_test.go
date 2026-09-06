package syscallpolicy

import (
	"errors"
	"testing"
)

func TestL8SyscallPolicyCatalogsAndStateAreClosed(t *testing.T) {
	t.Parallel()

	if got := RoleSteadyAgent.String(); got != "steady-agent" {
		t.Fatalf("RoleSteadyAgent.String() = %q, want steady-agent", got)
	}
	if got := Role(0xff).String(); got != "unknown" {
		t.Fatalf("unknown Role.String() = %q, want unknown", got)
	}
	if err := ValidateRole(RoleWorkload); err != nil {
		t.Fatalf("ValidateRole(RoleWorkload) error = %v", err)
	}
	if err := ValidateRole(0); contractErrorCode(err) != ErrorCodeInvalidArgument {
		t.Fatalf("ValidateRole(0) error = %v, want invalid-argument contract error", err)
	}

	checks, err := NewCheckSet(CheckFDKind, CheckPostSuccessReinspection)
	if err != nil {
		t.Fatalf("NewCheckSet() error = %v", err)
	}
	if !checks.Contains(CheckFDKind) || !checks.Contains(CheckPostSuccessReinspection) {
		t.Fatal("NewCheckSet() lost a configured check")
	}
	values := checks.Values()
	values[0] = CheckReservedZero
	if got := checks.Values()[0]; got != CheckFDKind {
		t.Fatalf("CheckSet.Values() mutation escaped: got %v", got)
	}
	if _, err := NewCheckSet(CheckFDKind, CheckFDKind); contractErrorCode(err) != ErrorCodeDuplicate {
		t.Fatalf("duplicate NewCheckSet() error = %v, want duplicate", err)
	}
	if _, err := NewCheckSet(Check(255)); contractErrorCode(err) != ErrorCodeCatalog {
		t.Fatalf("unknown NewCheckSet() error = %v, want catalog", err)
	}
	for _, input := range []struct {
		role  Role
		stage Stage
		facts StateFact
	}{
		{role: 0, stage: StageActive},
		{role: RoleSteadyAgent, stage: 0},
		{role: RoleSteadyAgent, stage: StageActive, facts: StateFact(1 << 63)},
	} {
		if _, err := NewState(input.role, input.stage, input.facts); contractErrorCode(err) != ErrorCodeCatalog {
			t.Fatalf("NewState(%v, %v, %v) error = %v, want catalog", input.role, input.stage, input.facts, err)
		}
	}

	state, err := NewState(RoleSteadyAgent, StageActive, StateFactFilterCommitted|StateFactCompositionAccepted)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	if state.Role() != RoleSteadyAgent || state.Stage() != StageActive || state.Facts() != StateFactFilterCommitted|StateFactCompositionAccepted {
		t.Fatalf("state projection = %v/%v/%v", state.Role(), state.Stage(), state.Facts())
	}
	arguments := [6]uint64{1, 2, 3, 4, 5, 6}
	input, err := NewFilterInput(state, 0xc000003e, 42, arguments)
	if err != nil {
		t.Fatalf("NewFilterInput() error = %v", err)
	}
	arguments[0] = 99
	if got, err := input.Argument(0); err != nil || got != 1 {
		t.Fatalf("Argument(0) = (%d, %v), want (1, nil)", got, err)
	}
	if input.SHA256() == ([32]byte{}) {
		t.Fatal("FilterInput.SHA256() is zero")
	}
	if _, err := input.Argument(6); contractErrorCode(err) != ErrorCodeBounds {
		t.Fatalf("Argument(6) error = %v, want bounds", err)
	}
}

func TestL8SyscallPolicyErrorsAreSafe(t *testing.T) {
	t.Parallel()

	want := &ContractError{code: ErrorCodeCatalog}
	got := &ContractError{code: ErrorCodeCatalog}
	if !errors.Is(got, want) {
		t.Fatal("equal ContractError codes do not match with errors.Is")
	}
	if errors.Is(got, &ContractError{code: ErrorCodeEncoding}) {
		t.Fatal("different ContractError codes matched with errors.Is")
	}
	if got.Error() != "syscall policy contract rejected: catalog" {
		t.Fatalf("ContractError.Error() = %q", got.Error())
	}
}

func contractErrorCode(err error) ErrorCode {
	var contractError *ContractError
	if !errors.As(err, &contractError) {
		return 0
	}
	return contractError.Code()
}
