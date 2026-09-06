package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var factoryRecoveryFixtureInput = strings.Repeat("a", 40)
var factoryRecoveryFixtureOutput = strings.Repeat("c", 40)

// This fake models each new local proof explicitly. Calls retain their host
// versus analysis scope and immutable object IDs; unknown operations fail.
func factoryRecoveryFixtureGit(t *testing.T, host string, destinationExists bool, calls *[][]string) func(context.Context, string, ...string) (string, error) {
	t.Helper()
	var snapshot, analysis string
	head, currentRef, destination := factoryRecoveryFixtureInput, "refs/heads/source", ""
	if destinationExists {
		destination = factoryRecoveryFixtureInput
	}
	return func(ctx context.Context, dir string, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if len(args) == 0 {
			t.Fatal("empty recovery Git operation")
		}
		if args[0] == "bundle" && len(args) == 3 && args[1] == "verify" {
			snapshot = args[2]
			if filepath.Base(snapshot) != "recovery.bundle" || filepath.Dir(snapshot) == host {
				t.Fatal("recovery did not use private bundle snapshot")
			}
			if data, err := os.ReadFile(snapshot); err != nil || len(data) == 0 {
				t.Fatal("bundle snapshot unavailable")
			}
		}
		if args[0] == "clone" && len(args) == 7 {
			analysis = args[6]
		}
		normalized := append([]string(nil), args...)
		for i, arg := range normalized {
			switch arg {
			case snapshot:
				if snapshot != "" {
					normalized[i] = "<bundle>"
				}
			case analysis:
				if analysis != "" {
					normalized[i] = "<analysis>"
				}
			case host:
				normalized[i] = "<host>"
			}
		}
		if dir != host {
			if analysis == "" || dir != analysis {
				t.Fatalf("unexpected Git directory %q", dir)
			}
			normalized = append([]string{"@analysis"}, normalized...)
		}
		*calls = append(*calls, normalized)
		switch args[0] {
		case "check-ref-format":
			if len(args) == 3 && args[1] == "--branch" {
				return args[2], nil
			}
		case "rev-parse":
			if reflect.DeepEqual(args, []string{"rev-parse", "--show-toplevel"}) {
				return host, nil
			}
			if len(args) == 4 && args[1] == "--verify" && args[2] == "--end-of-options" && strings.HasSuffix(args[3], "^{commit}") {
				if args[3] == "HEAD^{commit}" {
					return head, nil
				}
				if args[3] == currentRef+"^{commit}" {
					return destination, nil
				}
				return factoryRecoveryFixtureInput, nil
			}
		case "symbolic-ref":
			if reflect.DeepEqual(args, []string{"symbolic-ref", "--quiet", "HEAD"}) {
				return currentRef, nil
			}
		case "status":
			if reflect.DeepEqual(args, []string{"status", "--porcelain=v1", "--untracked-files=all"}) {
				return "", nil
			}
		case "show-ref":
			if len(args) == 4 && args[1] == "--verify" && args[2] == "--quiet" && strings.HasPrefix(args[3], "refs/heads/") {
				if destination != "" {
					return "", nil
				}
				return "", factoryVerificationSafetyExit(1)
			}
		case "bundle":
			if len(args) == 3 && args[2] == snapshot {
				if args[1] == "verify" {
					return "", nil
				}
				if args[1] == "list-heads" {
					return factoryRecoveryFixtureOutput + " HEAD", nil
				}
			}
		case "clone":
			if reflect.DeepEqual(args, []string{"clone", "--bare", "--shared", "--no-hardlinks", "--", host, analysis}) {
				return "", nil
			}
		case "fetch":
			if reflect.DeepEqual(args, []string{"fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", snapshot, "HEAD"}) {
				return "", nil
			}
		case "merge-base":
			if dir == analysis && reflect.DeepEqual(args, []string{"merge-base", "--is-ancestor", factoryRecoveryFixtureInput, factoryRecoveryFixtureOutput}) {
				return "", nil
			}
		case "diff-tree":
			if dir == analysis && reflect.DeepEqual(args, []string{"diff-tree", "--no-commit-id", "--raw", "--diff-filter=A", "-r", "-z", factoryRecoveryFixtureInput, factoryRecoveryFixtureOutput}) {
				return "", nil
			}
		case "checkout":
			if len(args) == 3 && args[1] == "--no-overwrite-ignore" && destinationExists {
				head, currentRef = destination, "refs/heads/"+args[2]
				return "", nil
			}
			if len(args) == 5 && args[1] == "--no-overwrite-ignore" && args[2] == "-b" && args[4] == factoryRecoveryFixtureOutput && !destinationExists {
				head, currentRef, destination = factoryRecoveryFixtureOutput, "refs/heads/"+args[3], factoryRecoveryFixtureOutput
				return "", nil
			}
		case "merge":
			if reflect.DeepEqual(args, []string{"merge", "--ff-only", "--no-overwrite-ignore", factoryRecoveryFixtureOutput}) {
				head, destination = factoryRecoveryFixtureOutput, factoryRecoveryFixtureOutput
				return "", nil
			}
		case "push":
			if dir == host && len(args) == 4 && args[1] == "-u" && args[2] == "origin" {
				return "", nil
			}
		}
		t.Errorf("unexpected recovery Git request: %v", normalized)
		return "", errors.New("unexpected fixture Git request")
	}
}

func factoryRecoveryFixtureCalls(branch, base string, exists bool) [][]string {
	state := [][]string{
		{"status", "--porcelain=v1", "--untracked-files=all"},
		{"rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"},
		{"symbolic-ref", "--quiet", "HEAD"},
		{"rev-parse", "--verify", "--end-of-options", "refs/heads/" + base + "^{commit}"},
		{"show-ref", "--verify", "--quiet", "refs/heads/" + branch},
	}
	if exists {
		state = append(state, []string{"rev-parse", "--verify", "--end-of-options", "refs/heads/" + branch + "^{commit}"})
	}
	calls := [][]string{{"check-ref-format", "--branch", branch}, {"check-ref-format", "--branch", base}, {"rev-parse", "--show-toplevel"}}
	calls = append(calls, state...)
	calls = append(calls, []string{"bundle", "verify", "<bundle>"}, []string{"bundle", "list-heads", "<bundle>"}, []string{"clone", "--bare", "--shared", "--no-hardlinks", "--", "<host>", "<analysis>"}, []string{"@analysis", "fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "<bundle>", "HEAD"}, []string{"@analysis", "merge-base", "--is-ancestor", factoryRecoveryFixtureInput, factoryRecoveryFixtureOutput})
	if exists {
		calls = append(calls, []string{"@analysis", "merge-base", "--is-ancestor", factoryRecoveryFixtureInput, factoryRecoveryFixtureOutput})
	}
	calls = append(calls, []string{"@analysis", "diff-tree", "--no-commit-id", "--raw", "--diff-filter=A", "-r", "-z", factoryRecoveryFixtureInput, factoryRecoveryFixtureOutput})
	calls = append(calls, state...)
	calls = append(calls, []string{"fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance", "<bundle>", "HEAD"})
	calls = append(calls, state...)
	if exists {
		calls = append(calls, []string{"checkout", "--no-overwrite-ignore", branch})
		calls = append(calls, state...)
		calls = append(calls, []string{"merge", "--ff-only", "--no-overwrite-ignore", factoryRecoveryFixtureOutput})
	} else {
		calls = append(calls, []string{"checkout", "--no-overwrite-ignore", "-b", branch, factoryRecoveryFixtureOutput})
		state = append(state, []string{"rev-parse", "--verify", "--end-of-options", "refs/heads/" + branch + "^{commit}"})
	}
	return append(calls, state...)
}

func factoryRecoveryFixturePreflightCalls(branch, base string) [][]string {
	calls := factoryRecoveryFixtureCalls(branch, base, false)
	for i, call := range calls {
		if call[0] == "bundle" {
			return calls[:i]
		}
	}
	panic("fixture preflight boundary missing")
}
