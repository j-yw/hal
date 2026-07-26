//go:build !linux

package localresolver

import (
	"errors"
	"os"
)

func openDistributionRootNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("distribution root is not a real directory")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("distribution root changed while opening")
	}
	return file, nil
}

func openDistributionFileNoFollow(root *os.File, name string) (*os.File, error) {
	rootFS := os.DirFS(root.Name())
	info, err := os.Lstat(root.Name() + string(os.PathSeparator) + name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("distribution file is not a real regular file")
	}
	file, err := rootFS.Open(name)
	if err != nil {
		return nil, err
	}
	osFile, ok := file.(*os.File)
	if !ok {
		file.Close()
		return nil, errors.New("distribution file handle is unsupported")
	}
	opened, err := osFile.Stat()
	if err != nil || !os.SameFile(info, opened) {
		osFile.Close()
		return nil, errors.New("distribution file changed while opening")
	}
	return osFile, nil
}

func duplicateDistributionRoot(root *os.File) (*os.File, error) {
	return os.Open(root.Name())
}
