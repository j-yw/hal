//go:build !unix

package cmd

import "os"

func openFactoryRecoveryFile(root *os.Root, name string) (*os.File, error) {
	// Containment and retained before/after SameFile checks remain mandatory.
	return root.Open(name)
}
