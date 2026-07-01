package parallelrun

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
)

var safeRuntimeDirs = []string{
	template.StandardsDir,
	template.CommandsDir,
	"skills",
}

func copyWorkerRuntimeContext(srcRepo, dstRepo string, cfg Config) error {
	srcHal := filepath.Join(srcRepo, cfg.HalDir)
	dstHal := filepath.Join(dstRepo, cfg.HalDir)
	if err := os.MkdirAll(dstHal, 0o755); err != nil {
		return fmt.Errorf("create worker hal dir: %w", err)
	}

	files := uniqueRuntimeFiles([]string{
		cfg.PRDFile,
		cfg.ProgressFile,
		template.PromptFile,
		template.ConfigFile,
	})
	for _, name := range files {
		src := filepath.Join(srcHal, name)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat runtime file %s: %w", name, err)
		}
		if err := copyPath(src, filepath.Join(dstHal, name)); err != nil {
			return fmt.Errorf("copy runtime file %s: %w", name, err)
		}
	}

	for _, name := range safeRuntimeDirs {
		src := filepath.Join(srcHal, name)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat runtime dir %s: %w", name, err)
		}
		if err := copyPath(src, filepath.Join(dstHal, name)); err != nil {
			return fmt.Errorf("copy runtime dir %s: %w", name, err)
		}
	}
	return nil
}

func uniqueRuntimeFiles(values []string) []string {
	seen := map[string]struct{}{}
	var unique []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return copySymlink(src, dst)
	}
	if info.IsDir() {
		return copyDir(src, dst)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file mode %s", info.Mode())
	}
	return copyFile(src, dst, info.Mode().Perm())
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return copySymlink(path, target)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copySymlink(src, dst string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, dst)
}
