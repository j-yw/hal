package sandboxruntime

import (
	"regexp"
	"strings"
	"testing"
)

func TestMinimalLaunchIDSyntaxMatchesSelectedGrammar(t *testing.T) {
	grammar := regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z`)
	check := func(value string) {
		t.Helper()
		if got, want := ValidMinimalLaunchID(value), grammar.MatchString(value); got != want {
			t.Fatalf("syntax(%q) = %v, want %v", value, got, want)
		}
	}
	// Exercise every byte as both a first and an interior character, including
	// controls, invalid UTF-8 and DEL; syntax is ASCII, not Unicode categories.
	for value := range 256 {
		ch := string([]byte{byte(value)})
		check(ch)
		check(ch + "id")
		check("id" + ch)
	}
	for _, value := range []string{"", "A", "0", "a._-", strings.Repeat("x", 64), strings.Repeat("x", 65), "é", "aé", "漢字", "x\n", " x", "x "} {
		check(value)
	}
}
