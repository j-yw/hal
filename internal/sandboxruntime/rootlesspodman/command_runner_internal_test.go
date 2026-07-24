package rootlesspodman

import (
	"errors"
	"testing"
)

func TestCancellationProofRequiresExecutedSuccessfulHelper(t *testing.T) {
	helperArgs := []string{"podman", "exec", "target", "cancel"}
	tests := []struct {
		name      string
		attempted bool
		args      []string
		err       error
		want      bool
	}{
		{name: "successful helper", attempted: true, args: helperArgs, want: true},
		{name: "natural completion race", args: helperArgs},
		{name: "missing helper", attempted: true},
		{name: "failed helper", attempted: true, args: helperArgs, err: errors.New("failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cancellationProcessGroupTerminationProven(test.attempted, test.args, test.err); got != test.want {
				t.Fatalf("cancellationProcessGroupTerminationProven() = %v, want %v", got, test.want)
			}
		})
	}
}
