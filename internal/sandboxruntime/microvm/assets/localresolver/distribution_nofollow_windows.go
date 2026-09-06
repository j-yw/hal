//go:build windows

package localresolver

import (
	"errors"
	"os"
)

var errDistributionWindowsSecurityProofUnavailable = errors.New("Windows distribution owner and DACL proof is unavailable")

func openDistributionRootNoFollow(string) (*os.File, error) {
	return nil, errDistributionWindowsSecurityProofUnavailable
}

func openDistributionFileNoFollow(*os.File, string) (*os.File, error) {
	return nil, errDistributionWindowsSecurityProofUnavailable
}

func duplicateDistributionRoot(*os.File) (*os.File, error) {
	return nil, errDistributionWindowsSecurityProofUnavailable
}
