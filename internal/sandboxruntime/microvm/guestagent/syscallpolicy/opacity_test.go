package syscallpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestL8SyscallPolicyOpaqueValuesFailClosed(t *testing.T) {
	t.Parallel()

	state, err := NewState(RoleSteadyAgent, StageActive, StateFactCompositionAccepted)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewFilterInput(state, 0xc000003e, 1, [6]uint64{1, 2, 3, 4, 5, 6})
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		CheckSet{},
		ExpectedPolicyArtifact{},
		VerifiedPolicyArtifact{},
		ExpectedPinnedCallsiteEvidence{},
		PinnedBinaryBindingSet{},
		PinnedCallsiteEvidenceSet{},
		state,
		input,
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			formatted := fmt.Sprintf(format, value)
			if formatted != opaqueFormat {
				t.Errorf("format %q of %T = %q, want %q", format, value, formatted, opaqueFormat)
			}
		}
		encoded, marshalErr := json.Marshal(value)
		if len(encoded) != 0 || contractErrorCode(marshalErr) != ErrorCodeInvalidArgument {
			t.Errorf("json.Marshal(%T) = (%q, %v), want empty/invalid-argument", value, encoded, marshalErr)
		}
	}

	failure := &ContractError{code: ErrorCodeCatalog}
	if formatted := fmt.Sprintf("%v", failure); formatted != opaqueFormat {
		t.Fatalf("ContractError format = %q", formatted)
	}
	if failure.Error() != "syscall policy contract rejected: catalog" {
		t.Fatalf("ContractError.Error() = %q", failure.Error())
	}
	if encoded, marshalErr := json.Marshal(failure); len(encoded) != 0 || contractErrorCode(marshalErr) != ErrorCodeInvalidArgument {
		t.Fatalf("json.Marshal(ContractError) = (%q, %v)", encoded, marshalErr)
	}
	if !errors.Is(failure, &ContractError{code: ErrorCodeCatalog}) {
		t.Fatal("ContractError errors.Is equality failed")
	}
}

func TestL8SyscallPolicyScalarFormattingIsStatic(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value any
		want  string
	}{
		{RoleSteadyAgent, "steady-agent"},
		{StageNativePostSetns, "native-post-setns"},
		{StateFactFilterCommitted | StateFactClosed, "filter-committed|closed"},
		{ActionErrnoEPERM, "errno-eperm"},
		{DescriptorKindVSOCKConnected, "vsock-connected"},
		{CheckPostSuccessReinspection, "post-success-reinspection"},
		{AdapterReasonPreSyscallAbort, "pre-syscall-abort"},
		{SyscallNumber(450), "450"},
		{ErrorCodeUnsafeWidening, "unsafe-widening"},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if got := fmt.Sprintf(format, test.value); got != test.want {
				t.Errorf("format %q of %T = %q, want %q", format, test.value, got, test.want)
			}
		}
	}
	if got := fmt.Sprintf("%v", Role(0xff)); !strings.Contains(got, "unknown") {
		t.Fatalf("unknown role format = %q", got)
	}
}
