//go:build linux

package firecrackerhost

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalPreparationInitializerRejectsExpiredBeforeAssemblyControl(t *testing.T) {
	f := newMinimalControlAdmissionFixture(t)
	f.config.EnablePCI = true
	f.config.Control.PreparationDeadlineUnixNano = time.Now().Add(-time.Second).UnixNano()
	f.reseal(nil)
	if code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		_, prep, err := beginMinimalControlPreparation(admission)
		if prep != nil {
			_ = prep.close()
		}
		if err == nil || prep != nil {
			t.Error("expired actual admission created pre-assembly lifetime")
		}
		// No runtime constructor or fake assembly is called on this path.
		if _, err := unix.FcntlInt(uintptr(admission.borrowed[0]), unix.F_GETFD, 0); err != nil {
			t.Error("initializer rejection closed borrowed original endpoint")
		}
		return nil
	}); code != 0 || f.admissions != 1 || len(f.closed) != 8 {
		t.Fatal("expired-init actual admission prerequisite/cleanup failed")
	}
}

func TestMinimalPreparationMissingBindingControls(t *testing.T) {
	for _, name := range []string{"owner", "selected"} {
		t.Run(name, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				prep := f.owned.minimalPreparation
				if name == "owner" {
					f.owned.minimalPreparation = nil
					defer func() { f.owned.minimalPreparation = prep }()
				} else {
					f.owned.selected.minimalPreparation = nil
					defer func() { f.owned.selected.minimalPreparation = prep }()
				}
				if err := minimalPreparationJoin(t, f.start(t)); err == nil || len(f.order) != 0 || f.owned.selected.attempted {
					t.Fatal("missing selected preparation lazily initialized or entered bootstrap")
				}
			})
		})
	}
}

func TestMinimalPreparationSetupLifetimeSurvivesReplyControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("actual bootstrap prerequisite", err)
		}
		prep := f.owned.minimalPreparation
		if prep.ctx.Err() != nil {
			t.Fatal("bootstrap return disposed explicit owner lifetime")
		}
		if _, err := unix.FcntlInt(prep.original.Fd(), unix.F_GETFD, 0); err != nil {
			t.Fatal("bootstrap return closed retained original endpoint")
		}
		if f.owned.shutdownMinimalControlPreparation() != nil || prep.ctx.Err() == nil {
			t.Fatal("explicit outside-lock shutdown did not cancel/join its lifetime")
		}
		if _, err := unix.FcntlInt(uintptr(f.admission.borrowed[0]), unix.F_GETFD, 0); err != nil {
			t.Fatal("owned shutdown closed borrowed admission endpoint")
		}
		// The RED has no P observer or monitor; this is only retained setup
		// lifetime/FD ownership, not proof of those later goroutines surviving.
	})
}
