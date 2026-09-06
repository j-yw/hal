//go:build !linux

package l7network

import (
	"errors"
	"os"
)

var errLockContended = errors.New("host topology lock contended")

func journalPlatformSupported() bool { return false }

func lockFile(*os.File) error   { return ErrUnsupported }
func unlockFile(*os.File) error { return nil }
