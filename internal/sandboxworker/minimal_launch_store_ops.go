package sandboxworker

import "os"

// Private per-store operation seam; callers cannot configure it. The RED
// scaffold delegates the original rename unchanged, so tests can reproduce a
// successor arriving exactly after the old temporary name was consumed.
type minimalLaunchStoreOps struct {
	owner  *jobStoreV2
	rename func(string, string) error
}

func newMinimalLaunchStoreOps(store *jobStoreV2) *minimalLaunchStoreOps {
	return &minimalLaunchStoreOps{owner: store, rename: os.Rename}
}
