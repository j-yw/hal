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
	renderCause := errors.New("private-render-canary /operator/private/output")
	for _, renderFailure := range []bool{false, true} {
		var out bytes.Buffer
		var writer io.Writer = &out
		if renderFailure {
			writer = factoryRecoverySafetyFailWriter{renderCause}
		}
		err := runFactoryRecoverWithDeps(context.Background(), writer, "missing-run", true, factoryRecoverDeps{
			defaultStore: func() (factory.Store, error) { return factory.Store{}, cause },
			workingDir:   func() (string, error) { return t.TempDir(), nil },
			runGit:       func(context.Context, string, ...string) (string, error) { t.Fatal("unexpected Git"); return "", nil },
		})
		if !errors.Is(err, cause) {
			t.Errorf("JSON failure lost nonzero original error: %v", err)
		}
		if renderFailure && !errors.Is(err, renderCause) {
			t.Error("render failure identity lost")
		}
		if err != nil && (strings.Contains(err.Error(), "private-recovery-canary") || strings.Contains(err.Error(), "private-render-canary")) {
			t.Error("returned error leaked original details")
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

func TestFactoryRecoverySafetySnapshotBoundsAndContainment(t *testing.T) {
	for _, scenario := range []string{"oversize", "zero size", "size mismatch", "cancelled", "outside run", "symlink directory", "directory payload"} {
		t.Run(scenario, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			record := factory.RunRecord{RunID: "bounded-recovery"}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			record = saveFactoryRecoveryBundleArtifact(t, store, record)
			artifact := record.Artifacts[0]
			path := mustFactoryRecoveryBundleStoredPath(t, store, record)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "oversize", "zero size":
				size := int64(0)
				if scenario == "oversize" {
					size = factoryRecoveryBundleLimit + 1
				}
				if err := os.Truncate(path, size); err != nil {
					t.Fatal(err)
				}
				artifact.SizeBytes = &size
			case "size mismatch":
				size := *artifact.SizeBytes + 1
				artifact.SizeBytes = &size
			case "cancelled":
				cancel()
			case "outside run":
				artifact.StoredPath = "artifacts/another-run/bundle"
			case "symlink directory":
				directory := filepath.Dir(path)
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.Rename(directory, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, directory); err != nil {
					t.Fatal(err)
				}
			case "directory payload":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := snapshotFactoryRecoveryBundle(ctx, store, record.RunID, artifact, filepath.Join(t.TempDir(), "snapshot")); err == nil {
				t.Error("unsafe snapshot accepted")
			}
		})
	}
}

func TestFactoryRecoverySafetySnapshotRejectsReplacementAtOpen(t *testing.T) {
	for _, scenario := range []string{"regular leaf replacement", "internal leaf symlink", "run directory replacement"} {
		t.Run(scenario, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			record := factory.RunRecord{RunID: "retained-run"}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			record = saveFactoryRecoveryBundleArtifact(t, store, record)
			path := mustFactoryRecoveryBundleStoredPath(t, store, record)
			replacement := filepath.Join(filepath.Dir(path), "replacement.bundle")
			if err := os.WriteFile(replacement, []byte("other  payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			triggered := false
			err := snapshotFactoryRecoveryBundleWithOpen(context.Background(), store, record.RunID, record.Artifacts[0], filepath.Join(t.TempDir(), "snapshot"), func(root *os.Root, name string) (*os.File, error) {
				triggered = true
				switch scenario {
				case "regular leaf replacement":
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "internal leaf symlink":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("replacement.bundle", path); err != nil {
						t.Fatal(err)
					}
				case "run directory replacement":
					if err := os.Rename(filepath.Dir(path), filepath.Join(store.Root(), "artifacts", "different-run")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("different-run", filepath.Dir(path)); err != nil {
						t.Fatal(err)
					}
				}
				return root.Open(name)
			})
			if !triggered || err == nil {
				t.Errorf("replacement accepted: triggered=%t error=%v", triggered, err)
			}
		})
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
