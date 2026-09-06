//go:build !linux && !windows

package localresolver

import (
	"errors"
	"os"
)

var errDistributionNoFollowUnsupported = errors.New("secure distribution resolution is unsupported on this platform")

func openDistributionRootNoFollow(string) (*os.File, error) {
	return nil, errDistributionNoFollowUnsupported
}

func openDistributionFileNoFollow(*os.File, string) (*os.File, error) {
	return nil, errDistributionNoFollowUnsupported
}

func duplicateDistributionRoot(*os.File) (*os.File, error) {
	return nil, errDistributionNoFollowUnsupported
}
