//go:build windows

package l7network

import "os"

func privateFileOwned(os.FileInfo) bool { return true }
