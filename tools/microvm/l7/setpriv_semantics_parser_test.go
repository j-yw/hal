//go:build l7_setpriv_semantics && linux

package l7profile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
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

func TestL7ConfiguredProviderQueryBoundsOversizedStdout(t *testing.T) {
	const outputLimit = 64
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		time.Second,
		outputLimit,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "oversized",
	)
	if err == nil {
		t.Fatal("configured provider query accepted oversized stdout")
	}
	if len(output) != outputLimit {
		t.Fatal("configured provider query did not hard-bound captured stdout")
	}
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider query error exposed child output")
	}
}

func TestL7ConfiguredProviderQueryCancelsHungChild(t *testing.T) {
	const timeout = 50 * time.Millisecond
	started := time.Now()
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		timeout,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "hang",
	)
	if err == nil {
		t.Fatal("configured provider query accepted a hung child")
	}
	if len(output) != 0 {
		t.Fatal("configured provider query captured unexpected hung-child output")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatal("configured provider query did not terminate its hung child by the deadline")
	}
}

func TestL7ConfiguredProviderQueryRejectsNonzeroExitWithoutStderrDisclosure(t *testing.T) {
	output, err := runL7ConfiguredProviderQuery(
		context.Background(),
		time.Second,
		64,
		os.Args[0],
		"-test.run=^TestL7ConfiguredProviderHelperProcess$", "--", "nonzero",
	)
	if err == nil {
		t.Fatal("configured provider query accepted a nonzero exit")
	}
	if len(output) != 0 {
		t.Fatal("configured provider query captured unexpected nonzero-exit stdout")
	}
	if strings.Contains(err.Error(), "provider-sensitive") {
		t.Fatal("configured provider query error exposed child stderr")
	}
}

func TestL7ConfiguredProviderHelperProcess(t *testing.T) {
	mode := ""
	for index, argument := range os.Args {
		if argument == "--" && index+1 < len(os.Args) {
			mode = os.Args[index+1]
			break
		}
	}
	switch mode {
	case "oversized":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("provider-sensitive-output"), 16))
		_, _ = os.Stderr.WriteString("provider-sensitive-stderr")
	case "hang":
		time.Sleep(time.Minute)
	case "nonzero":
		_, _ = os.Stderr.WriteString("provider-sensitive-stderr")
		os.Exit(7)
	}
}
