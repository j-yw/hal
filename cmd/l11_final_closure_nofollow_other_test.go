//go:build !unix && !windows

package cmd

import (
	"errors"
	"os"
)

func l11OpenFinalClosureNoFollow(string) (*os.File, error) {
	return nil, errors.New("no no-follow file open is available on this platform")
}
