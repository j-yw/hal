package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	l11FinalClosureDocPath          = "sandbox-runtime-v2-l11-final-closure.md"
	l11FinalClosureSelectedTest     = "TestL11PreparedLinuxFinalClosure"
	l11FinalClosureIntegrationTag   = "l11_final_closure_integration"
	l11FinalClosureCurrentStateLine = "Current closure state: `blocked`."
)

type l11FinalClosureMatrixRow struct {
	ordinal int
	id      string
	state   string
}

func TestL11FinalClosureDocumentationIsNormative(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	for _, required := range []string{
		"# Sandbox Runtime v2 L11 Final Closure",
		"## 1. Inputs, outputs, states, and failure codes",
		"## 2. Package ownership and import boundaries",
		"## 3. Durable and machine-contract schema changes",
		"## 4. Redaction and containment rules",
		"## 5. Crash, retry, cancellation, and cleanup semantics",
		"## 6. Red-first fake and live acceptance tests",
		"### Exact nine-phase final matrix",
		"## 7. Non-goals and final handoff",
		l11FinalClosureCurrentStateLine,
		"No L11 production live wiring is added by this contract-only slice.",
		"Accepted L8 live credential authority",
		"accepted L10 strict-composition authority",
		"A durable L10 decision cannot recreate live authority.",
		"All nine rows are unmet and `blocked`.",
		"A selected required live test that skips is a blocker, never a pass.",
		"Hetzner, Lightsail, and every other billed cloud call remain unauthorized.",
		"No acceptance is claimed by this document.",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L11 final-closure document omits %q", required)
		}
	}
}

func TestL11FinalClosureNinePhaseMatrixIsExactAndBlocked(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	rows, err := l11ParseFinalClosureMatrix(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := l11ValidateFinalClosureMatrix(rows); err != nil {
		t.Fatal(err)
	}
}

func TestL11FinalClosureMatrixGuardRejectsMutations(t *testing.T) {
	baseline := l11ExpectedFinalClosureMatrix()
	mutations := []struct {
		name   string
		mutate func([]l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow
	}{
		{name: "missing", mutate: func(rows []l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow {
			return rows[:len(rows)-1]
		}},
		{name: "duplicate", mutate: func(rows []l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow {
			rows[len(rows)-1] = rows[len(rows)-2]
			return rows
		}},
		{name: "renamed", mutate: func(rows []l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow {
			rows[3].id = "strict_success"
			return rows
		}},
		{name: "passed before acceptance", mutate: func(rows []l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow {
			rows[0].state = "passed"
			return rows
		}},
		{name: "completed before acceptance", mutate: func(rows []l11FinalClosureMatrixRow) []l11FinalClosureMatrixRow {
			rows[0].state = "completed"
			return rows
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			rows := append([]l11FinalClosureMatrixRow(nil), baseline...)
			if err := l11ValidateFinalClosureMatrix(mutation.mutate(rows)); err == nil {
				t.Fatal("mutated L11 matrix passed validation")
			}
		})
	}
}

func TestL11FinalClosureVerificationCommandsAreExact(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	commands := l11FinalClosureDocumentedShellCommands(doc)
	for _, command := range []string{
		"go test -count=1 ./cmd -run '^TestL11FinalClosure'",
		"go test -race -count=1 ./cmd -run '^TestL11FinalClosure'",
		"go test -count=20 ./cmd -run '^TestL11FinalClosure'",
		"tools/microvm/l11/verify-selected-live.sh matrix",
		"go test -count=1 ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[command] {
			t.Errorf("L11 final-closure document omits command %q", command)
		}
	}
	for _, required := range []string{
		l11FinalClosureSelectedTest,
		l11FinalClosureIntegrationTag,
		"exactly one run and one pass event for the selected top-level test",
		"exactly one run and one pass event for each of the nine required rows",
		"reject every skip event",
		"do not exist in this contract-only slice",
	} {
		if !l11FinalClosureContains(doc, required) {
			t.Errorf("L11 final-closure live verification contract omits %q", required)
		}
	}
}

func TestL11FinalClosureReleaseEvidenceIsBlockedAndRedactionSafe(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	for _, required := range []string{
		"exact aggregate base, L11 head and tree, accepted aggregate merge",
		"zero selected-test skips",
		"zero owned-resource leaks",
		"safe scenario IDs, stable failure codes, counts, and content digests",
		"must not contain endpoints, sockets, hostnames, IP addresses, ports, URLs",
		"credentials, secret values, environment values, PIDs, inode/device IDs",
		"rule bodies, provider handles, or identifying host paths",
	} {
		if !l11FinalClosureContains(doc, required) {
			t.Errorf("L11 release-evidence contract omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"Current closure state: `passed`.",
		"Current closure state: `complete`.",
		"Current closure state: `accepted`.",
		"All nine rows passed.",
		"L11 is complete.",
	} {
		if strings.Contains(doc, forbidden) {
			t.Errorf("L11 contract-only document makes premature completion claim %q", forbidden)
		}
	}
}

func l11ReadFinalClosureDoc(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "docs", "design", l11FinalClosureDocPath))
	if err != nil {
		t.Fatalf("read L11 final-closure document: %v", err)
	}
	return string(payload)
}

func l11FinalClosureContains(doc, required string) bool {
	return strings.Contains(doc, required) || strings.Contains(strings.Join(strings.Fields(doc), " "), required)
}

func l11ExpectedFinalClosureMatrix() []l11FinalClosureMatrixRow {
	ids := []string{
		"rootless_advisory_success",
		"rootless_client_loss_reconnect",
		"rootless_daemon_restart_recovery",
		"strict_firecracker_success",
		"strict_remove_one_proof",
		"strict_runtime_loss_reconnect",
		"strict_credential_loss_recovery",
		"artifact_integrity_and_safe_handoff",
		"zero_resource_leaks",
	}
	rows := make([]l11FinalClosureMatrixRow, len(ids))
	for index, id := range ids {
		rows[index] = l11FinalClosureMatrixRow{ordinal: index + 1, id: id, state: "blocked"}
	}
	return rows
}

func l11ParseFinalClosureMatrix(doc string) ([]l11FinalClosureMatrixRow, error) {
	var rows []l11FinalClosureMatrixRow
	inMatrix := false
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "### Exact nine-phase final matrix" {
			inMatrix = true
			continue
		}
		if inMatrix && strings.HasPrefix(line, "#") {
			break
		}
		if !inMatrix {
			continue
		}
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 5 {
			continue
		}
		ordinal, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			continue
		}
		rows = append(rows, l11FinalClosureMatrixRow{
			ordinal: ordinal,
			id:      strings.Trim(strings.TrimSpace(cells[1]), "`"),
			state:   strings.Trim(strings.TrimSpace(cells[4]), "`"),
		})
	}
	if len(rows) == 0 {
		return nil, &l11FinalClosureGuardError{message: "L11 final matrix is missing"}
	}
	return rows, nil
}

func l11ValidateFinalClosureMatrix(rows []l11FinalClosureMatrixRow) error {
	want := l11ExpectedFinalClosureMatrix()
	if len(rows) != len(want) {
		return &l11FinalClosureGuardError{message: "L11 final matrix row count changed"}
	}
	seen := make(map[string]bool, len(rows))
	for index, row := range rows {
		if seen[row.id] {
			return &l11FinalClosureGuardError{message: "L11 final matrix contains a duplicate row"}
		}
		seen[row.id] = true
		if row != want[index] {
			return &l11FinalClosureGuardError{message: "L11 final matrix identity or blocked state changed"}
		}
	}
	return nil
}

type l11FinalClosureGuardError struct{ message string }

func (err *l11FinalClosureGuardError) Error() string { return err.message }

func l11FinalClosureDocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	inShellBlock := false
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "```sh":
			inShellBlock = true
		case "```":
			inShellBlock = false
		default:
			if inShellBlock && line != "" && !strings.HasPrefix(line, "#") {
				commands[line] = true
			}
		}
	}
	return commands
}
