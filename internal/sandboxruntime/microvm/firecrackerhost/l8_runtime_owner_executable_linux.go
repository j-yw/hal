//go:build linux

package firecrackerhost

import "os"

func runPrivateL8RuntimeOwnerExecutable([]string, func(uintptr, string) *os.File) int {
	return 127
}
