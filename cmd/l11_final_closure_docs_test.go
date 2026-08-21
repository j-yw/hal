package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	l11FinalClosureBlockedDocSHA256 = "12183fe75a9dfb264af2e287d74cfebbc8e611e6bd48360511a7755b3c4e7515"
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
		"same-repository SHA-256 tripwire",
		"cannot defend against a coordinated edit",
		"external branch protection",
	} {
		if !l11FinalClosureContains(doc, required) {
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
		{name: "release hostname", marker: "\nRelease worker: sandbox-17.corp.example\n"},
		{name: "release port", marker: "\nRelease listener port: 48217\n"},
		{name: "release IPv4 address", marker: "\nRelease worker IP: 192.0.2.42\n"},
		{name: "release IPv6 address", marker: "\nRelease worker IP: 2001:db8::42\n"},
		{name: "release abstract socket", marker: "\nRelease socket: @hal-l11-worker\n"},
		{name: "release PID", marker: "\nRelease PID: 4242\n"},
		{name: "release provider handle", marker: "\nProvider handle: srv-01HZX8W9\n"},
		{name: "release bearer credential", marker: "\nAuthorization: Bearer release-secret-value\n"},
		{name: "contradictory release success", marker: "\nRelease result: passed.\n"},
		{name: "release host and port", marker: "\nRelease endpoint: sandbox-17:48217\n"},
		{name: "release compressed IPv6", marker: "\nRelease worker IP: ::1\n"},
		{name: "release arbitrary absolute path", marker: "\nRelease artifact: /data/l11/result.json\n"},
		{name: "release process ID", marker: "\nProcess ID: process-01HZX8W9\n"},
		{name: "release server ID", marker: "\nServer ID: server-01HZX8W9\n"},
		{name: "release generic bearer", marker: "\nBearer release-secret-value\n"},
		{name: "release generic service token", marker: "\nSERVICE_TOKEN=release-secret-value\n"},
		{name: "contradictory L11 release success", marker: "\nL11 release passed.\n"},
		{name: "contradictory scenario success", marker: "\nAll nine scenarios passed.\n"},
		{name: "unrecognized blocked-document appendix", marker: "\nHarmless appendix.\n"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := l11ValidateFinalClosureDocumentSafety(doc + mutation.marker); err == nil {
				t.Fatal("unsafe or prematurely accepted release evidence passed validation")
			}
		})
	}
}

func TestL11FinalClosureRepositoryRejectsSecondaryDocuments(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	root := t.TempDir()
	canonical := filepath.Join(root, "docs", "design", l11FinalClosureDocPath)
	if err := os.MkdirAll(filepath.Dir(canonical), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonical, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	secondary := filepath.Join(root, "docs", "l11-final-release.md")
	if err := os.WriteFile(secondary, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l11ValidateFinalClosureRepository(root); err == nil {
		t.Fatal("secondary L11 final/release document passed repository validation")
	}
}

func TestL11FinalClosureRepositoryHasOneCanonicalDocument(t *testing.T) {
	if err := l11ValidateFinalClosureRepository(".."); err != nil {
		t.Fatal(err)
	}
}

func TestL11FinalClosureCanonicalDocumentRejectsSymlinkAndNonregularFiles(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	for _, test := range []struct {
		name  string
		build func(string, string) error
	}{
		{name: "symlink", build: func(root, canonical string) error {
			target := filepath.Join(root, "blocked-contract.md")
			if err := os.WriteFile(target, []byte(doc), 0o600); err != nil {
				return err
			}
			return os.Symlink(target, canonical)
		}},
		{name: "directory", build: func(_ string, canonical string) error {
			return os.Mkdir(canonical, 0o700)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			canonical := filepath.Join(root, "docs", "design", l11FinalClosureDocPath)
			if err := os.MkdirAll(filepath.Dir(canonical), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := test.build(root, canonical); err != nil {
				t.Fatal(err)
			}
			if err := l11ValidateFinalClosureRepository(root); err == nil {
				t.Fatal("symlink or nonregular canonical L11 document passed repository validation")
			}
		})
	}
}

func TestL11FinalClosureCanonicalDocumentRejectsSymlinkedAncestors(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	for _, test := range []struct {
		name  string
		build func(string, string) (string, error)
	}{
		{name: "repository root", build: func(base, canonical string) (string, error) {
			realRoot := filepath.Join(base, "real-repository")
			if err := os.MkdirAll(filepath.Join(realRoot, "docs", "design"), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(realRoot, "docs", "design", l11FinalClosureDocPath), []byte(doc), 0o600); err != nil {
				return "", err
			}
			return canonical, os.Symlink(realRoot, canonical)
		}},
		{name: "docs directory", build: func(base, canonical string) (string, error) {
			realDocs := filepath.Join(base, "outside-docs")
			if err := os.MkdirAll(filepath.Join(realDocs, "design"), 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(realDocs, "design", l11FinalClosureDocPath), []byte(doc), 0o600); err != nil {
				return "", err
			}
			if err := os.Mkdir(canonical, 0o700); err != nil {
				return "", err
			}
			return canonical, os.Symlink(realDocs, filepath.Join(canonical, "docs"))
		}},
		{name: "design directory", build: func(base, canonical string) (string, error) {
			realDesign := filepath.Join(base, "outside-design")
			if err := os.MkdirAll(realDesign, 0o700); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(realDesign, l11FinalClosureDocPath), []byte(doc), 0o600); err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Join(canonical, "docs"), 0o700); err != nil {
				return "", err
			}
			return canonical, os.Symlink(realDesign, filepath.Join(canonical, "docs", "design"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			repoRoot := filepath.Join(base, "repository")
			repoRoot, err := test.build(base, repoRoot)
			if err != nil {
				t.Skipf("symlink fixture is unavailable: %v", err)
			}
			if err := l11ValidateFinalClosureRepository(repoRoot); err == nil {
				t.Fatal("canonical L11 document below a symlinked ancestor passed repository validation")
			}
		})
	}
}

func TestL11FinalClosureRepositoryInventoryRejectsEveryContradictoryDocument(t *testing.T) {
	doc := l11ReadFinalClosureDoc(t)
	for _, test := range []struct {
		name  string
		build func(string) error
	}{
		{name: "innocuous markdown filename", build: func(root string) error {
			return os.WriteFile(filepath.Join(root, "notes.md"), []byte("# Notes\n\nL11 release passed.\n"), 0o600)
		}},
		{name: "long markdown extension", build: func(root string) error {
			return os.WriteFile(filepath.Join(root, "notes.markdown"), []byte("# Notes\n\nAll nine scenarios passed.\n"), 0o600)
		}},
		{name: "secondary document symlink", build: func(root string) error {
			target := filepath.Join(filepath.Dir(root), "outside-release.md")
			if err := os.WriteFile(target, []byte("L11 release passed.\n"), 0o600); err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(root, "notes.md"))
		}},
		{name: "secondary document nonregular", build: func(root string) error {
			return os.Mkdir(filepath.Join(root, "notes.markdown"), 0o700)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			canonical := filepath.Join(root, "docs", "design", l11FinalClosureDocPath)
			if err := os.MkdirAll(filepath.Dir(canonical), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(canonical, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.build(root); err != nil {
				t.Skipf("secondary document fixture is unavailable: %v", err)
			}
			if err := l11ValidateFinalClosureRepository(root); err == nil {
				t.Fatal("unsafe secondary L11 release document passed repository validation")
			}
		})
	}
}

func l11ReadFinalClosureDoc(t *testing.T) string {
	t.Helper()
	payload, err := l11ReadFinalClosureCanonical("..")
	if err != nil {
		t.Fatalf("read L11 final-closure document: %v", err)
	}
	return string(payload)
}

func l11ValidateFinalClosureRepository(repoRoot string) error {
	payload, err := l11ReadFinalClosureCanonical(repoRoot)
	if err != nil {
		return err
	}
	if err := l11ValidateFinalClosureDocumentSafety(string(payload)); err != nil {
		return err
	}
	canonical := filepath.Clean(filepath.Join("docs", "design", l11FinalClosureDocPath))
	return filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.Clean(relative)
		if relative == "." || relative == canonical || entry.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(relative)) != ".md" {
			return nil
		}
		if l11FinalClosureSecondaryDocumentPath(relative) {
			return &l11FinalClosureGuardError{message: "secondary L11 final-closure or release document is forbidden"}
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		candidate, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(candidate)
		if strings.Contains(text, "# Sandbox Runtime v2 L11 Final Closure") ||
			strings.Contains(text, l11FinalClosureCurrentStateLine) {
			return &l11FinalClosureGuardError{message: "duplicate L11 final-closure document is forbidden"}
		}
		return nil
	})
}

func l11ReadFinalClosureCanonical(repoRoot string) ([]byte, error) {
	const maxDocumentBytes = 1 << 20
	path := filepath.Join(repoRoot, "docs", "design", l11FinalClosureDocPath)
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat canonical L11 final-closure document: %w", err)
	}
	if !linkInfo.Mode().IsRegular() {
		return nil, &l11FinalClosureGuardError{message: "canonical L11 final-closure document is not a regular file"}
	}
	file, err := l11OpenFinalClosureNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open canonical L11 final-closure document without following links: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		_ = file.Close()
		return nil, &l11FinalClosureGuardError{message: "canonical L11 final-closure document identity changed"}
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
	afterInfo, afterErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || closeErr != nil {
		return nil, &l11FinalClosureGuardError{message: "canonical L11 final-closure document read was not exact"}
	}
	if len(payload) > maxDocumentBytes || !afterInfo.Mode().IsRegular() || !os.SameFile(openedInfo, afterInfo) || afterInfo.Size() != int64(len(payload)) {
		return nil, &l11FinalClosureGuardError{message: "canonical L11 final-closure document bytes changed during read"}
	}
	return payload, nil
}

func l11FinalClosureSecondaryDocumentPath(relative string) bool {
	lower := strings.ToLower(filepath.ToSlash(relative))
	normalized := strings.NewReplacer("_", "-", " ", "-").Replace(lower)
	if !strings.Contains(normalized, "l11") {
		return false
	}
	return strings.Contains(normalized, "final-closure") ||
		strings.Contains(normalized, "final-release") ||
		strings.Contains(normalized, "release-evidence")
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
	// This slice has no release record. Its only valid state is the exact reviewed
	// blocked contract; any added field or prose is an unreviewed evidence shape.
	digest := sha256.Sum256([]byte(doc))
	if hex.EncodeToString(digest[:]) != l11FinalClosureBlockedDocSHA256 {
		return &l11FinalClosureGuardError{message: "L11 blocked document is not the exact source-locked contract"}
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
