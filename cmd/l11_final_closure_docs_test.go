package cmd

import (
	"os"
	"path/filepath"
	"regexp"
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
	ordinal         int
	id              string
	runtimeBoundary string
	observation     string
	state           string
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

func TestL11FinalClosureMatrixParserRejectsMarkdownMutations(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	lastRow := "| 9 | `zero_resource_leaks` | Both runtime classes | Repeated terminal recovery and cleanup leave the exact owned-resource census at zero | `blocked` |"
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{name: "backtick ordinal", old: "| 1 | `rootless_advisory_success`", new: "| `1` | `rootless_advisory_success`"},
		{name: "leading zero ordinal", old: "| 1 | `rootless_advisory_success`", new: "| 01 | `rootless_advisory_success`"},
		{name: "double backtick scenario ID", old: "`rootless_advisory_success`", new: "``rootless_advisory_success``"},
		{name: "unquoted blocked state", old: "| `blocked` |", new: "| blocked |"},
		{name: "double backtick blocked state", old: "| `blocked` |", new: "| ``blocked`` |"},
		{name: "spaced backtick blocked state", old: "| `blocked` |", new: "| ` blocked ` |"},
		{name: "malformed header", old: "| Phase | Scenario ID | Runtime boundary | Required live observation | Initial state |", new: "| Phase | Scenario | Runtime boundary | Required live observation | Initial state |"},
		{name: "malformed separator", old: "|---|---|---|---|---|", new: "|---|---|---|---|"},
		{name: "runtime boundary drift", old: "| Rootless Podman |", new: "| Rootless Other |"},
		{name: "observation drift", old: "Production execution succeeds, remains advisory, and cannot obtain strict selection", new: "Production execution is simulated"},
		{name: "extra malformed row", old: lastRow, new: lastRow + "\n| extra | malformed | row |"},
		{name: "extra skipped row", old: lastRow, new: lastRow + "\n| neighbor | `ignored_by_old_parser` | Both | observation | `blocked` |"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(doc, mutation.old, mutation.new, 1)
			if mutated == doc {
				t.Fatal("matrix markdown mutation did not change the document")
			}
			rows, err := l11ParseFinalClosureMatrix(mutated)
			if err == nil {
				err = l11ValidateFinalClosureMatrix(rows)
			}
			if err == nil {
				t.Fatal("malformed L11 matrix markdown passed validation")
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
	if err := l11ValidateFinalClosureDocumentSafety(doc); err != nil {
		t.Fatal(err)
	}
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

func TestL11FinalClosureReleaseEvidenceGuardRejectsMutations(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	mutations := []struct {
		name   string
		marker string
	}{
		{name: "premature production live acceptance", marker: "\nProduction-live acceptance: accepted.\n"},
		{name: "premature live pass", marker: "\nThe L11 production live lane passed.\n"},
		{name: "release URL", marker: "\nRelease endpoint: https://release.invalid/result/1\n"},
		{name: "release token", marker: "\nRelease token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"},
		{name: "release environment value", marker: "\nHCLOUD_TOKEN=release-secret\n"},
		{name: "release host path", marker: "\nRelease artifact: /private/l11/result.json\n"},
		{name: "home-relative host path", marker: "\nRelease artifact: ~/.ssh/release-key\n"},
		{name: "windows host path", marker: "\nRelease artifact: C:\\private\\l11\\result.json\n"},
		{name: "windows UNC host path", marker: "\nRelease artifact: \\\\release-host\\private\\result.json\n"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := l11ValidateFinalClosureDocumentSafety(doc + mutation.marker); err == nil {
				t.Fatal("unsafe or prematurely accepted release evidence passed validation")
			}
		})
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
	return []l11FinalClosureMatrixRow{
		{ordinal: 1, id: "rootless_advisory_success", runtimeBoundary: "Rootless Podman", observation: "Production execution succeeds, remains advisory, and cannot obtain strict selection", state: "blocked"},
		{ordinal: 2, id: "rootless_client_loss_reconnect", runtimeBoundary: "Rootless Podman", observation: "Initiating client is lost after durable admission; reconnect observes one continuing job with no rerun", state: "blocked"},
		{ordinal: 3, id: "rootless_daemon_restart_recovery", runtimeBoundary: "Rootless Podman", observation: "Worker daemon restarts; durable recovery, artifacts, lease release, and teardown converge once", state: "blocked"},
		{ordinal: 4, id: "strict_firecracker_success", runtimeBoundary: "Strict Firecracker", observation: "Exact live L5/L7/L8/L9/L10 conjunction selects strict, executes, and reaches terminal complete", state: "blocked"},
		{ordinal: 5, id: "strict_remove_one_proof", runtimeBoundary: "Strict Firecracker", observation: "Each required live proof is independently removed or corrupted and strict selection fails closed", state: "blocked"},
		{ordinal: 6, id: "strict_runtime_loss_reconnect", runtimeBoundary: "Strict Firecracker", observation: "Client, worker, guest/Firecracker, and retained-network loss paths reconnect or recover without rerun", state: "blocked"},
		{ordinal: 7, id: "strict_credential_loss_recovery", runtimeBoundary: "Strict Firecracker", observation: "Proxy/helper/relay/credential loss revokes authority, proves absence, and never retains strict active state", state: "blocked"},
		{ordinal: 8, id: "artifact_integrity_and_safe_handoff", runtimeBoundary: "Both runtime classes", observation: "Durable artifacts, recovery, sync-out, digest validation, and explicit safe handoff remain contained and exact", state: "blocked"},
		{ordinal: 9, id: "zero_resource_leaks", runtimeBoundary: "Both runtime classes", observation: "Repeated terminal recovery and cleanup leave the exact owned-resource census at zero", state: "blocked"},
	}
}

func l11ParseFinalClosureMatrix(doc string) ([]l11FinalClosureMatrixRow, error) {
	const (
		heading   = "### Exact nine-phase final matrix"
		headerRow = "| Phase | Scenario ID | Runtime boundary | Required live observation | Initial state |"
		separator = "|---|---|---|---|---|"
	)
	lines := strings.Split(doc, "\n")
	headingIndex := -1
	for index, line := range lines {
		if line != heading {
			continue
		}
		if headingIndex >= 0 {
			return nil, &l11FinalClosureGuardError{message: "L11 final matrix heading is duplicated"}
		}
		headingIndex = index
	}
	if headingIndex < 0 {
		return nil, &l11FinalClosureGuardError{message: "L11 final matrix is missing"}
	}
	rowStart := headingIndex + 4
	wantRows := l11ExpectedFinalClosureMatrix()
	if headingIndex+3 >= len(lines) || lines[headingIndex+1] != "" || lines[headingIndex+2] != headerRow || lines[headingIndex+3] != separator {
		return nil, &l11FinalClosureGuardError{message: "L11 final matrix header is malformed"}
	}
	if rowStart+len(wantRows) >= len(lines) {
		return nil, &l11FinalClosureGuardError{message: "L11 final matrix row count changed"}
	}
	rows := make([]l11FinalClosureMatrixRow, 0, len(wantRows))
	for index := range wantRows {
		row, err := l11ParseFinalClosureMatrixRow(lines[rowStart+index])
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	afterRows := rowStart + len(wantRows)
	if lines[afterRows] != "" {
		return nil, &l11FinalClosureGuardError{message: "L11 final matrix contains an extra or malformed row"}
	}
	for _, line := range lines[afterRows+1:] {
		if strings.HasPrefix(line, "## ") {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			return nil, &l11FinalClosureGuardError{message: "L11 final matrix contains an extra or malformed row"}
		}
	}
	return rows, nil
}

func l11ParseFinalClosureMatrixRow(line string) (l11FinalClosureMatrixRow, error) {
	if !strings.HasPrefix(line, "| ") || !strings.HasSuffix(line, " |") {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix row is malformed"}
	}
	cells := strings.Split(line[2:len(line)-2], " | ")
	if len(cells) != 5 {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix row is malformed"}
	}
	ordinal, err := strconv.Atoi(cells[0])
	if err != nil || strconv.Itoa(ordinal) != cells[0] {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix ordinal is malformed"}
	}
	id, ok := l11ExactSingleBacktickCell(cells[1])
	if !ok {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix scenario ID is malformed"}
	}
	state, ok := l11ExactSingleBacktickCell(cells[4])
	if !ok || state != "blocked" {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix blocked state is malformed"}
	}
	if cells[2] == "" || cells[3] == "" {
		return l11FinalClosureMatrixRow{}, &l11FinalClosureGuardError{message: "L11 final matrix row is incomplete"}
	}
	return l11FinalClosureMatrixRow{ordinal: ordinal, id: id, runtimeBoundary: cells[2], observation: cells[3], state: state}, nil
}

func l11ExactSingleBacktickCell(cell string) (string, bool) {
	if len(cell) < 3 || cell[0] != '`' || cell[len(cell)-1] != '`' {
		return "", false
	}
	value := cell[1 : len(cell)-1]
	return value, value != "" && value == strings.TrimSpace(value) && !strings.Contains(value, "`")
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

var (
	l11PrematureProductionLiveAcceptance = regexp.MustCompile(`(?im)(?:^|\n)\s*(?:production[- ]live acceptance\s*:\s*(?:accepted|passed|complete|completed)|(?:the\s+)?L11 production[- ]live (?:lane|closure)\s+(?:is\s+|was\s+|has been\s+)?(?:accepted|passed|complete|completed))\b`)
	l11UnsafeReleaseURL                  = regexp.MustCompile(`(?i)\b(?:https?|ssh|file)://\S+`)
	l11UnsafeReleaseToken                = regexp.MustCompile(`(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|hcloud_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	l11UnsafeReleaseEnvironmentValue     = regexp.MustCompile(`(?im)\b(?:HCLOUD_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|DIGITALOCEAN_ACCESS_TOKEN|GOOGLE_APPLICATION_CREDENTIALS)\s*=\s*\S+`)
	l11UnsafeReleaseUnixPath             = regexp.MustCompile("(?m)(?:^|[\\s\"'(])(?:~/(?:[^\\s`|,;)]+)?|/(?:home|root|tmp|var|run|private|etc|opt|srv|mnt|Users)(?:/[^\\s`|,;)]*)?)")
	l11UnsafeReleaseWindowsPath          = regexp.MustCompile("(?im)(?:^|[\\s\"'(])(?:[A-Z]:\\\\|\\\\\\\\)[^\\s`|,;)]+")
)

func l11ValidateFinalClosureDocumentSafety(doc string) error {
	for _, required := range []string{
		l11FinalClosureCurrentStateLine,
		"No acceptance is claimed by this document.",
		"All nine rows are unmet and `blocked`.",
		"No L11 production live wiring is added by this contract-only slice.",
	} {
		if strings.Count(doc, required) != 1 {
			return &l11FinalClosureGuardError{message: "L11 blocked contract marker changed"}
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "current closure state:") && strings.TrimSpace(line) != l11FinalClosureCurrentStateLine {
			return &l11FinalClosureGuardError{message: "L11 closure state is not exactly blocked"}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		l11PrematureProductionLiveAcceptance,
		l11UnsafeReleaseURL,
		l11UnsafeReleaseToken,
		l11UnsafeReleaseEnvironmentValue,
		l11UnsafeReleaseUnixPath,
		l11UnsafeReleaseWindowsPath,
	} {
		if pattern.MatchString(doc) {
			return &l11FinalClosureGuardError{message: "L11 release evidence contains a premature acceptance or unsafe value"}
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
