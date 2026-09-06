package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestFactoryRecoverySafetyJSONFailureReturnsError(t *testing.T) {
	cause := errors.New("private-recovery-canary /operator/private/store")
	for _, renderFailure := range []bool{false, true} {
		var out bytes.Buffer
		var writer io.Writer = &out
		if renderFailure {
			writer = factoryRecoverySafetyFailWriter{cause}
		}
		err := runFactoryRecoverWithDeps(context.Background(), writer, "missing-run", true, factoryRecoverDeps{
			defaultStore: func() (factory.Store, error) { return factory.Store{}, cause },
			workingDir:   func() (string, error) { return t.TempDir(), nil },
			runGit:       func(context.Context, string, ...string) (string, error) { t.Fatal("unexpected Git"); return "", nil },
		})
		if !errors.Is(err, cause) {
			t.Errorf("JSON failure lost nonzero original error: %v", err)
		}
		if !renderFailure {
			var response FactoryRecoverResponse
			if json.Unmarshal(out.Bytes(), &response) != nil || response.OK || response.ContractVersion != FactoryRecoverContractVersion {
				t.Fatalf("invalid recovery failure document: %s", out.String())
			}
			if strings.Contains(out.String(), "private-recovery-canary") || strings.Contains(out.String(), "/operator/private") {
				t.Error("JSON recovery failure leaked private error detail")
			}
		}
	}
}

type factoryRecoverySafetyFailWriter struct{ err error }

func (w factoryRecoverySafetyFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestFactoryRecoverySafetyPreflightRejectsWithoutHostMutation(t *testing.T) {
	for _, scenario := range []string{"staged", "unstaged", "untracked", "checkout expression", "lock contention", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			record := factory.RunRecord{RunID: "recovery-safety", BranchName: "hal/safety", BaseBranch: "main"}
			if scenario == "checkout expression" {
				record.BranchName = "@{-1}"
			}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			record = saveFactoryRecoveryBundleArtifact(t, store, record)
			if scenario == "lock contention" {
				lock, err := sandboxworkspace.NewLockManager(filepath.Join(os.TempDir(), "hal-workspace-locks")).Acquire("workspace:" + dir)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := lock.Release(); err != nil {
						t.Error(err)
					}
				})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			mutations := 0
			_, _, err := applyFactorySandboxRecoveryBundle(ctx, store, dir, record, factoryRunDeps{runGit: func(_ context.Context, gotDir string, args ...string) (string, error) {
				if len(args) == 0 {
					t.Fatal("empty Git request")
				}
				switch args[0] {
				case "rev-parse":
					if args[len(args)-1] == "--show-toplevel" {
						return dir, nil
					}
					return strings.Repeat("a", 40), nil
				case "check-ref-format":
					if scenario == "checkout expression" {
						return "hal/previous", nil
					}
					return args[len(args)-1], nil
				case "status":
					return map[string]string{"staged": "M  private-canary", "unstaged": " M private-canary", "untracked": "?? private-canary"}[scenario], nil
				case "fetch", "checkout", "merge":
					if gotDir == dir {
						mutations++
					}
				}
				return "", nil
			}})
			if err == nil || mutations != 0 {
				t.Errorf("unsafe recovery accepted: error=%v host mutations=%d", err, mutations)
			}
			if err != nil && strings.Contains(err.Error(), "private-canary") {
				t.Error("dirty filename leaked")
			}
		})
	}
}
