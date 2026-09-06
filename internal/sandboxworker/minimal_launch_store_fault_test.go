package sandboxworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Fault seams perform ordinary local file operations only. No provider launch
// or runtime cleanup proof is synthesized by these persistence observations.
func TestMinimalLaunchStoreFaultRetainsUncertainDispatch(t *testing.T) {
	for _, fault := range []string{"rename after commit", "first directory sync", "dispatch directory sync", "dispatch readback bytes", "dispatch symlink"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalLaunchDispatchFixture(t)
			s := f.service(t)
			ops := s.jobs.store.minimalOps
			rename, sync := ops.rename, ops.sync
			fired, syncCalls := false, 0
			var successor string
			var before os.FileInfo
			ops.rename = func(old, new string) error {
				if err := rename(old, new); err != nil {
					return err
				}
				path := filepath.Join(f.stateDir, new)
				switch fault {
				case "rename after commit":
					fired = true
					return errors.New("test-only uncertain rename")
				case "dispatch readback bytes":
					fired = true
					payload, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					changed := bytes.Replace(payload, []byte("runtime-generation-minimal"), []byte("runtime-generation-foreign"), 1)
					if bytes.Equal(changed, payload) {
						t.Fatal("readback mutation did not match")
					}
					if err := os.WriteFile(path, changed, 0o600); err != nil {
						t.Fatal(err)
					}
				case "dispatch symlink":
					fired = true
					successor = filepath.Join(t.TempDir(), "successor")
					if err := os.Rename(path, successor); err != nil {
						t.Fatal(err)
					}
					var err error
					before, err = os.Lstat(successor)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(successor, path); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			ops.sync = func() error {
				syncCalls++
				if fault == "first directory sync" && syncCalls == 1 || fault == "dispatch directory sync" && syncCalls == 3 {
					fired = true
					return errors.New("test-only directory sync failure")
				}
				return sync()
			}
			response := s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if !fired || response.OK || f.provider.startCalls != 0 {
				t.Fatalf("fault=%t provider starts=%d responseOK=%t", fired, f.provider.startCalls, response.OK)
			}
			s.jobs.mu.Lock()
			poisoned, retained := s.jobs.minimalPoisoned, len(s.jobs.minimalLive)
			s.jobs.mu.Unlock()
			if !poisoned || retained != 1 || len(minimalLaunchRecordFiles(t, f.stateDir)) != 1 {
				t.Fatal("uncertain publication forgot its reservation or durable record")
			}
			if successor != "" {
				after, err := os.Lstat(successor)
				if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
					t.Fatal("readback followed or replaced successor")
				}
			}
			_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
			if f.provider.startCalls != 0 || f.provider.resolveCalls != 1 {
				t.Fatal("uncertain retry re-entered selection or launch")
			}
			s.Close()
			fresh, err := NewL8DurableService(f.options())
			if fresh != nil {
				fresh.Close()
			}
			if err == nil || fresh != nil || f.provider.recoverCalls != 0 {
				t.Fatal("uncertain restart launched or used legacy recovery")
			}
		})
	}
}

func TestMinimalLaunchRetainsOriginalDirectoryAndClosesHandles(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	s := f.service(t)
	ops := s.jobs.store.minimalOps
	held, err := ops.directory.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := ops.root.Stat(".")
	if err != nil || !os.SameFile(held, root) {
		t.Fatal("root was not tied to independently retained directory")
	}
	if err := s.jobs.store.checkMinimalAuthority(s.jobs.stateLock); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := ops.directory.Stat(); err == nil {
		t.Fatal("original directory descriptor leaked after joined close")
	}
	if _, err := ops.root.Stat("."); err == nil {
		t.Fatal("original Root descriptor leaked after joined close")
	}
	if s.jobs.store.checkMinimalAuthority(ops.lock) == nil {
		t.Fatal("closed store retained admission authority")
	}
}
