//go:build !linux

package firecrackerhost

import (
	"errors"
	"os"
)

func (osStrictJailerHostInspectionFilesystem) OpenNoFollow(string) (strictJailerHostInspectionFile, error) {
	return nil, errors.New("strict Jailer host inspection is unsupported")
}

func (osStrictJailerHostInspectionFilesystem) OwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}
