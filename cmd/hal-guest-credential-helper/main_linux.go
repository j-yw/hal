//go:build linux

package main

import "os"

func main() {
	os.Exit(productionRun(os.Args[1:]))
}
