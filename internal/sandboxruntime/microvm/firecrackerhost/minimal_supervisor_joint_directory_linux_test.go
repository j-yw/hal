//go:build linux

package firecrackerhost

import "testing"

func TestMinimalSupervisorJointPrivateRecordDirectory(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		if validateL8RuntimeOwnerDirectoryFD(f.owned.store.directoryFD) != nil {
			t.Fatal("original private record directory did not survive bootstrap")
		}
	})
}
