//go:build linux

package firecrackerhost

import (
	"os"
	"testing"
)

func TestMinimalRuntimeAssemblyRejectsAbsentAdmission(t *testing.T) {
	if owned, err := newMinimalControlLinuxRuntime(nil); err == nil || owned != nil {
		t.Fatal("absent admission constructed a selected runtime")
	}
}

func TestMinimalRuntimeAssemblyPreservesActualRootRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged refusal requires an actual non-root caller; not positive constructor coverage")
	}
	f := newMinimalControlAdmissionFixture(t)
	f.config.EnablePCI = true
	f.reseal(nil)
	code := f.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		if owned, err := newMinimalControlLinuxRuntime(admission); err == nil || owned != nil {
			t.Fatal("actual unprivileged caller crossed the selected constructor root gate")
		}
		return nil
	})
	if code != 0 || f.admissions != 1 || f.legacy != 0 {
		t.Fatal("ordinary admission prerequisite failed before root refusal")
	}
}
