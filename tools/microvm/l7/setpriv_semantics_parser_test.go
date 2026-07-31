//go:build l7_setpriv_semantics && linux

package l7profile

import (
	"fmt"
	"testing"
)

func TestParseL7GetSubIDsSelectsFirstProviderRange(t *testing.T) {
	const username = "semantic-probe-user"
	output := []byte("0: " + username + " 100001 1\n1: " + username + " 200001 32\n")

	got, err := parseL7GetSubIDs(output, username)
	if err != nil {
		t.Fatalf("parse configured provider output: %v", err)
	}
	if got != 100001 {
		t.Fatal("configured provider parser did not select the first safe subordinate ID")
	}
}

func TestParseL7GetSubIDsRejectsInvalidProviderOutput(t *testing.T) {
	const username = "semantic-probe-user"
	tests := []struct {
		name   string
		output string
	}{
		{name: "empty"},
		{name: "missing field", output: "0: " + username + " 100001\n"},
		{name: "malformed index", output: "zero: " + username + " 100001 1\n"},
		{name: "unexpected index", output: "1: " + username + " 100001 1\n"},
		{name: "wrong user", output: "0: another-user 100001 1\n"},
		{name: "malformed start", output: "0: " + username + " invalid 1\n"},
		{name: "malformed count", output: "0: " + username + " 100001 invalid\n"},
		{name: "zero range", output: "0: " + username + " 100001 0\n"},
		{name: "start overflow", output: "0: " + username + " 4294967295 1\n"},
		{name: "range overflow", output: "0: " + username + " 4294967294 2\n"},
		{name: "integer overflow", output: "0: " + username + " 18446744073709551616 1\n"},
		{name: "malformed later entry", output: "0: " + username + " 100001 1\ninvalid\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseL7GetSubIDs([]byte(tt.output), username); err == nil {
				t.Fatal("configured provider parser accepted invalid output")
			}
		})
	}
}

func TestL7SubordinateIDMapUsesOneOuterIDAtNamespaceID1000(t *testing.T) {
	const outerID = uint64(100001)
	want := fmt.Sprintf("1000:%d:1", outerID)
	if got := l7SubordinateIDMap(outerID); got != want {
		t.Fatal("subordinate ID map must map exactly one outer ID at namespace ID 1000")
	}
}
