//go:build !linux

package main

import "os"

// A network-enabled guest image is Linux-only. Unsupported guest platforms
// fail closed instead of reporting a successful no-op bootstrap.
func main() {
	os.Exit(127)
}
