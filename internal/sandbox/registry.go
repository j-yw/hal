package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sandboxStateFileExt = ".json"

var (
	renameRegistryFile = os.Rename
	removeRegistryFile = os.Remove
)

// SaveInstance persists a sandbox instance in the global registry.
//
// The write is atomic (temp file + rename) and will fail if an entry already
// exists for the same sandbox name.
func SaveInstance(instance *SandboxState) error {
	return writeInstance(instance, false)
}

// ForceWriteInstance persists a sandbox instance in the global registry,
// replacing any existing entry with the same sandbox name.
func ForceWriteInstance(instance *SandboxState) error {
	return writeInstance(instance, true)
}

func writeInstance(instance *SandboxState, overwrite bool) error {
	if instance == nil {
		return fmt.Errorf("sandbox instance is required")
	}
	if strings.TrimSpace(instance.Name) == "" {
		return fmt.Errorf("sandbox name is required")
	}

	path, err := instancePath(instance.Name)
	if err != nil {
		return err
	}

	if err := EnsureGlobalDir(); err != nil {
		return err
	}

	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("sandbox %q already exists", instance.Name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("check sandbox %q: %w", instance.Name, err)
		}
	}

	data, err := json.MarshalIndent(instance, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox %q: %w", instance.Name, err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write sandbox %q: %w", instance.Name, err)
	}
	if err := saveRegistryFile(tmpPath, path, overwrite); err != nil {
		_ = removeRegistryFile(tmpPath)
		return fmt.Errorf("save sandbox %q: %w", instance.Name, err)
	}

	return nil
}

// saveRegistryFile persists a prepared temp file to its final path. Overwrite
// writes fall back to a backup/restore flow on platforms where rename cannot
// replace an existing file.
func saveRegistryFile(tmpPath, path string, overwrite bool) error {
	if !overwrite {
		return renameRegistryFile(tmpPath, path)
	}

	if err := renameRegistryFile(tmpPath, path); err == nil {
		return nil
	} else if !isRenameNoReplaceError(err) {
		return err
	}

	backupPath := path + ".bak"
	if err := removeRegistryFile(backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := renameRegistryFile(path, backupPath); err != nil {
		return err
	}
	if err := renameRegistryFile(tmpPath, path); err != nil {
		if restoreErr := renameRegistryFile(backupPath, path); restoreErr != nil {
			return fmt.Errorf("%w (restore failed: %v)", err, restoreErr)
		}
		return err
	}

	_ = removeRegistryFile(backupPath)
	return nil
}

func isRenameNoReplaceError(err error) bool {
	return errors.Is(err, fs.ErrExist) || os.IsExist(err)
}

// LoadInstance loads a sandbox instance from the global registry.
func LoadInstance(name string) (*SandboxState, error) {
	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return nil, fmt.Errorf("read sandbox %q: %w", name, err)
	}

	var instance SandboxState
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("parse sandbox %q: %w", name, err)
	}
	if strings.TrimSpace(instance.Name) == "" {
		instance.Name = name
	}

	return &instance, nil
}

// ListInstances returns all sandbox instances in the global registry,
// sorted by sandbox name.
func ListInstances() ([]*SandboxState, error) {
	entries, err := os.ReadDir(SandboxesDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandboxes dir: %w", err)
	}

	instances := make([]*SandboxState, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}

		path := filepath.Join(SandboxesDir(), entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read sandbox file %q: %w", entry.Name(), err)
		}

		var instance SandboxState
		if err := json.Unmarshal(data, &instance); err != nil {
			return nil, fmt.Errorf("parse sandbox file %q: %w", entry.Name(), err)
		}
		if strings.TrimSpace(instance.Name) == "" {
			instance.Name = strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		}

		instances = append(instances, &instance)
	}

	sort.Slice(instances, func(i, j int) bool {
		return instances[i].Name < instances[j].Name
	})

	return instances, nil
}

// ResolveDefault resolves the default sandbox when commands are invoked
// without an explicit sandbox name.
//
// It applies the optional filter and expects exactly one match.
//
// Returns:
//   - the matching sandbox + hint when exactly one match exists
//   - "no sandboxes found" when there are no matches
//   - "no running sandboxes" when there are no matches and the filter appears
//     to target running status
//   - "multiple sandboxes found: ..." with sorted names when ambiguous
func ResolveDefault(filter func(*SandboxState) bool) (*SandboxState, string, error) {
	instances, err := ListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("list sandboxes: %w", err)
	}

	matches := make([]*SandboxState, 0, len(instances))
	for _, instance := range instances {
		if filter != nil && !filter(instance) {
			continue
		}
		matches = append(matches, instance)
	}

	switch len(matches) {
	case 0:
		return nil, "", errors.New(defaultResolveNoMatchError(filter))
	case 1:
		match := matches[0]
		return match, fmt.Sprintf("connecting to only active sandbox %q", match.Name), nil
	default:
		names := make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, match.Name)
		}
		return nil, "", fmt.Errorf("multiple sandboxes found: %s", strings.Join(names, ", "))
	}
}

func defaultResolveNoMatchError(filter func(*SandboxState) bool) string {
	if isRunningOnlyFilter(filter) {
		return "no running sandboxes"
	}
	return "no sandboxes found"
}

func isRunningOnlyFilter(filter func(*SandboxState) bool) bool {
	if filter == nil {
		return false
	}

	running := filter(&SandboxState{Status: StatusRunning})
	stopped := filter(&SandboxState{Status: StatusStopped})
	return running && !stopped
}

// RemoveInstance deletes a sandbox instance from the global registry.
func RemoveInstance(name string) error {
	path, err := instancePath(name)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return fmt.Errorf("remove sandbox %q: %w", name, err)
	}
	return nil
}

func instancePath(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", fmt.Errorf("invalid sandbox name: %w", err)
	}
	return filepath.Join(SandboxesDir(), name+sandboxStateFileExt), nil
}
