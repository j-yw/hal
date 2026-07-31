//go:build !unix

package linuxtopology

import "os"

func duplicateNamespaceFile(file *os.File) (*os.File, error) {
	return os.Open(file.Name())
}
