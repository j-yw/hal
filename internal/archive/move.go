package archive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// moveFile moves a file from src to dst. It tries os.Rename first as the fast
// path and falls back to copy-and-remove when the rename fails with EXDEV
// (cross-device link).
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Only fall back on cross-device errors
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || !errors.Is(linkErr.Err, syscall.EXDEV) {
		return err
	}

	return copyAndRemove(src, dst)
}

// moveDir moves an entire directory tree from src to dst. It tries os.Rename
// first as the fast path and falls back to walking and copying individual files
// when the rename fails with EXDEV (cross-device link).
func moveDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("source directory: %w", err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory: %s", src)
	}

	err = os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Only fall back on cross-device errors
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || !errors.Is(linkErr.Err, syscall.EXDEV) {
		return err
	}

	// Walk source and copy files individually
	if err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		dstPath := filepath.Join(dst, rel)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("dir info: %w", err)
			}
			return os.MkdirAll(dstPath, info.Mode())
		}

		return moveFile(path, dstPath)
	}); err != nil {
		return fmt.Errorf("copy directory tree: %w", err)
	}

	if err := os.RemoveAll(src); err != nil {
		return fmt.Errorf("remove source directory: %w", err)
	}

	return nil
}

// copyAndRemove copies src to dst preserving permissions, then removes src.
func copyAndRemove(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("copy data: %w", err)
	}

	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("close destination: %w", err)
	}

	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		os.Remove(dst)
		return fmt.Errorf("chmod destination: %w", err)
	}

	if err := os.Remove(src); err != nil {
		return fmt.Errorf("remove source: %w", err)
	}

	return nil
}
