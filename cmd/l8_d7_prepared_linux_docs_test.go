package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

const l8D7PreparedLinuxAcceptanceDoc = "sandbox-runtime-v2-l8-d7-prepared-linux-acceptance.md"

func TestL8D7PreparedLinuxAcceptanceDocument(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PreparedLinuxAcceptanceDoc))
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, required := range []string{
		"D7 prepared-Linux acceptance remains unaccepted",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"fixture-as-strict",
		"never treat a fixture as a passing live proof",
		"sealed PID1 expected digests",
		"live helper transport",
		"durable handle store",
		"production L7 session factory",
		"loadPID1StartGateExpected",
		"L8ProcessCompositionFacts",
		"dependency_unaccepted",
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"TestL8PreparedLinuxCredentialDeliveryE2E",
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
		"tools/microvm/l8/verify-selected-live.sh prerequisites",
		"tools/microvm/l8/verify-selected-live.sh e2e",
		"never t.Skip after the selected live test is discovered",
		"default go test ./... does not run D7 live tests",
		"`golangci-lint` reported only when `command -v golangci-lint` succeeds",
		"go test ./cmd -run '^TestL8D7PreparedLinux' -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8D7PreparedLinux' -count=1",
		"go vet ./cmd ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
		"environment delivery as strict proof",
		"t.Fatal",
		"VerifiedL8Profile",
		"verified-syscall-policy.hl8q",
		"verified-pinned-callsites.hl8e",
		"non-serializable authenticated packet and capability contracts",
		"Helper lifecycle exchange",
		"still fail-closes",
		"not a production listener",
		"`SCM_RIGHTS` transport adapter",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("D7 prepared-Linux acceptance document omits %q", required)
		}
	}
}

func TestL8D7PreparedLinuxAcceptanceDocumentForbidsCompleteClaims(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PreparedLinuxAcceptanceDoc))
	words := l8D7DocumentationWords(doc)
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
	} {
		if l8D7DocumentationContainsPhrase(words, forbidden) {
			t.Fatalf("D7 prepared-Linux acceptance document contains forbidden claim %q", forbidden)
		}
	}
	if err := l8D7ValidateFixtureAsStrictDocumentation(doc); err != nil {
		t.Fatal(err)
	}
}

func TestL8D7PreparedLinuxAcceptanceDocumentRejectsContradictoryFixtureClaims(t *testing.T) {
	allowed := "The wrapper must never treat a fixture as a passing live proof; `fixture-as-strict` is a forbidden practice."
	for _, test := range []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{name: "exact prohibition", doc: allowed},
		{name: "affirmative after prohibition", doc: allowed + " Operators may treat a fixture as a passing live proof.", wantErr: true},
		{name: "affirmative before prohibition", doc: "We treat a fixture as a passing live proof. " + allowed, wantErr: true},
		{name: "markdown formatted affirmative", doc: allowed + " Operators may treat a fixture as **a passing live proof**.", wantErr: true},
		{name: "fixture as strict accepted", doc: allowed + " The fixture-as-strict shortcut is accepted.", wantErr: true},
		{name: "markdown formatted acceptance", doc: allowed + " D7 prepared-Linux acceptance is **accepted**.", wantErr: true},
		{name: "missing exact prohibition", doc: "Fixtures are not live proof.", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := l8D7ValidateFixtureAsStrictDocumentation(test.doc)
			if (err != nil) != test.wantErr {
				t.Fatalf("validation error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func l8D7ValidateFixtureAsStrictDocumentation(doc string) error {
	const prohibition = "The wrapper must never treat a fixture as a passing live proof; `fixture-as-strict` is a forbidden practice."
	normalized := strings.Join(strings.Fields(doc), " ")
	if strings.Count(normalized, prohibition) != 1 {
		return fmt.Errorf("D7 prepared-Linux acceptance document must contain the exact fixture-as-strict prohibition once")
	}
	remainder := l8D7DocumentationWords(strings.Replace(normalized, prohibition, "", 1))
	for _, forbidden := range []string{
		"treat a fixture as a passing live proof",
		"fixture-as-strict",
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
	} {
		if l8D7DocumentationContainsPhrase(remainder, forbidden) {
			return fmt.Errorf("D7 prepared-Linux acceptance document contains contradictory fixture claim %q", forbidden)
		}
	}
	return nil
}

func l8D7DocumentationWords(value string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " ")
}

func l8D7DocumentationContainsPhrase(words, phrase string) bool {
	want := l8D7DocumentationWords(phrase)
	return strings.Contains(" "+words+" ", " "+want+" ")
}
