//go:build !linux && !darwin

package sandboxworker

import "os"

func openMinimalLaunchNoFollow(string, bool) (*os.File, error) { return nil, errMinimalLaunchState }
func minimalLaunchFileOwned(os.FileInfo) bool                  { return false }
