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
const pendingRemovalRegistryFileExt = ".replacing"

var (
	renameRegistryFile = os.Rename
	removeRegistryFile = os.Remove
)

// PendingInstanceRemoval temporarily hides a registry entry while a caller
// performs a destructive provider operation that may need rollback.
type PendingInstanceRemoval struct {
	name          string
	path          string
	backupPath    string
	active        bool
	alreadyStaged bool
}

// SaveInstance persists a sandbox instance in the global registry.
//
// New entries use exclusive create semantics and will fail if an entry already
// exists for the same sandbox name. Overwrites use an atomic temp-file + rename
// flow.
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
	if err := ensureRegistryInstanceID(instance); err != nil {
		return err
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
		pendingPath := path + pendingRemovalRegistryFileExt
		pendingExists, err := registryFileExists(pendingPath)
		if err != nil {
			return fmt.Errorf("check sandbox %q staged registry entry: %w", instance.Name, err)
		}
		if pendingExists {
			return fmt.Errorf("sandbox %q has a pending removal; resolve the staged deletion before creating a replacement", instance.Name)
		}
	} else {
		if err := prepareRegistryOverwrite(path, instance.Name); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(instance, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox %q: %w", instance.Name, err)
	}
	data = append(data, '\n')

	if !overwrite {
		if err := saveRegistryFileExclusive(path, data); err != nil {
			if isRenameNoReplaceError(err) {
				return fmt.Errorf("sandbox %q already exists", instance.Name)
			}
			return fmt.Errorf("save sandbox %q: %w", instance.Name, err)
		}
		return nil
	}

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

func prepareRegistryOverwrite(path, name string) error {
	pendingPath := path + pendingRemovalRegistryFileExt
	pendingExists, err := registryFileExists(pendingPath)
	if err != nil {
		return fmt.Errorf("check sandbox %q staged registry entry: %w", name, err)
	}
	if !pendingExists {
		return nil
	}

	activeExists, err := registryFileExists(path)
	if err != nil {
		return fmt.Errorf("check sandbox %q registry entry: %w", name, err)
	}

	if activeExists {
		if err := removeRegistryFile(pendingPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("clear sandbox %q staged registry entry: %w", name, err)
		}
		return nil
	}

	return fmt.Errorf("sandbox %q has a pending removal; resolve the staged deletion before overwriting registry state", name)
}

func saveRegistryFileExclusive(path string, data []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = removeRegistryFile(path)
		}
	}()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	cleanup = false
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

// StageInstanceRemoval moves a registry entry out of the active namespace so
// callers can either commit its deletion or roll it back if remote cleanup
// fails.
func StageInstanceRemoval(name string) (*PendingInstanceRemoval, error) {
	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}

	backupPath := path + pendingRemovalRegistryFileExt
	activeExists, err := registryFileExists(path)
	if err != nil {
		return nil, fmt.Errorf("check sandbox %q registry entry: %w", name, err)
	}
	backupExists, err := registryFileExists(backupPath)
	if err != nil {
		return nil, fmt.Errorf("check sandbox %q staged registry entry: %w", name, err)
	}

	switch {
	case backupExists && !activeExists:
		return &PendingInstanceRemoval{
			name:          name,
			path:          path,
			backupPath:    backupPath,
			active:        true,
			alreadyStaged: true,
		}, nil
	case backupExists && activeExists:
		return nil, fmt.Errorf("sandbox %q has both active and staged registry entries; resolve the pending removal before retrying", name)
	case !activeExists:
		return nil, fmt.Errorf("sandbox %q does not exist: %w", name, fs.ErrNotExist)
	}

	if err := renameRegistryFile(path, backupPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return nil, fmt.Errorf("prepare sandbox %q for replacement: %w", name, err)
	}

	return &PendingInstanceRemoval{
		name:       name,
		path:       path,
		backupPath: backupPath,
		active:     true,
	}, nil
}

func registryFileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// AlreadyStaged reports whether the pending removal resumed from an existing
// staged backup rather than moving the active registry entry in this call.
func (p *PendingInstanceRemoval) AlreadyStaged() bool {
	return p != nil && p.alreadyStaged
}

// Commit finalizes a staged removal after the remote sandbox has been deleted.
func (p *PendingInstanceRemoval) Commit() error {
	if p == nil || !p.active {
		return nil
	}
	if err := removeRegistryFile(p.backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("finalize sandbox %q replacement: %w", p.name, err)
	}
	p.active = false
	return nil
}

// Rollback restores a staged registry entry when remote deletion fails.
func (p *PendingInstanceRemoval) Rollback() error {
	if p == nil || !p.active {
		return nil
	}
	if err := renameRegistryFile(p.backupPath, p.path); err != nil {
		return fmt.Errorf("restore sandbox %q registry entry: %w", p.name, err)
	}
	p.active = false
	return nil
}

func loadRegistryInstanceFile(path, name string) (*SandboxState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var instance SandboxState
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("parse sandbox %q: %w", name, err)
	}
	normalizeRegistryInstance(&instance, name)
	if err := repairRegistryInstanceID(path, &instance); err != nil {
		return nil, fmt.Errorf("repair sandbox %q: %w", name, err)
	}

	return &instance, nil
}

// LoadActiveInstance loads only the active registry entry for a sandbox name.
// It intentionally ignores staged-removal backups so callers can make
// create-time availability decisions against the active namespace only.
func LoadActiveInstance(name string) (*SandboxState, error) {
	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}

	instance, err := loadRegistryInstanceFile(path, name)
	if err == nil {
		return instance, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
	}
	return nil, fmt.Errorf("read sandbox %q: %w", name, err)
}

// LoadInstance loads a sandbox instance from the global registry. When a
// delete was interrupted after staging, it falls back to the staged registry
// entry so callers can resume cleanup.
func LoadInstance(name string) (*SandboxState, error) {
	instance, err := LoadActiveInstance(name)
	if err == nil {
		return instance, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}
	stagedPath := path + pendingRemovalRegistryFileExt
	instance, err = loadRegistryInstanceFile(stagedPath, name)
	if err == nil {
		return instance, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
	}
	return nil, fmt.Errorf("read sandbox %q: %w", name, err)
}

// ListInstances returns all sandbox instances in the global registry,
// sorted by sandbox name.
func ListInstances() ([]*SandboxState, error) {
	return listInstances(true)
}

// ListActiveInstances returns only active registry entries, excluding staged
// removal backups that exist solely to support interrupted delete recovery.
func ListActiveInstances() ([]*SandboxState, error) {
	return listInstances(false)
}

func listInstances(includeStagedFallback bool) ([]*SandboxState, error) {
	sandboxesDir, err := sandboxesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandboxes dir: %w", err)
	}
	entries, err := os.ReadDir(sandboxesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandboxes dir: %w", err)
	}

	instances := make([]*SandboxState, 0, len(entries))
	activeNames := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		activeNames[name] = struct{}{}

		path := filepath.Join(sandboxesDir, entry.Name())
		instance, err := loadRegistryInstanceFile(path, name)
		if err != nil {
			if strings.HasPrefix(err.Error(), "parse sandbox ") {
				return nil, fmt.Errorf("parse sandbox file %q: %w", entry.Name(), err)
			}
			return nil, fmt.Errorf("read sandbox file %q: %w", entry.Name(), err)
		}

		instances = append(instances, instance)
	}

	if includeStagedFallback {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), sandboxStateFileExt+pendingRemovalRegistryFileExt) {
				continue
			}

			name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), pendingRemovalRegistryFileExt), sandboxStateFileExt)
			if _, ok := activeNames[name]; ok {
				continue
			}

			path := filepath.Join(sandboxesDir, entry.Name())
			instance, err := loadRegistryInstanceFile(path, name)
			if err != nil {
				if strings.HasPrefix(err.Error(), "parse sandbox ") {
					return nil, fmt.Errorf("parse sandbox file %q: %w", entry.Name(), err)
				}
				return nil, fmt.Errorf("read sandbox file %q: %w", entry.Name(), err)
			}

			instances = append(instances, instance)
		}
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
	instances, err := ListActiveInstances()
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

func normalizeRegistryInstance(instance *SandboxState, defaultName string) {
	if instance == nil {
		return
	}

	if strings.TrimSpace(instance.Name) == "" {
		instance.Name = strings.TrimSpace(defaultName)
	}
	if strings.TrimSpace(instance.Status) == "" {
		instance.Status = StatusUnknown
	}
	provider := strings.TrimSpace(instance.Provider)
	if provider == "" {
		provider = "daytona"
		instance.Provider = provider
	}
	if strings.TrimSpace(instance.WorkspaceID) == "" &&
		provider == "digitalocean" {
		if legacyID := strings.TrimSpace(instance.ID); isLegacyDigitalOceanDropletID(legacyID) {
			instance.WorkspaceID = legacyID
		}
	}
}

func ensureRegistryInstanceID(instance *SandboxState) error {
	if instance == nil {
		return nil
	}

	instance.ID = strings.TrimSpace(instance.ID)
	if !needsGeneratedRegistryID(instance) {
		return nil
	}

	id, err := NewV7()
	if err != nil {
		return fmt.Errorf("generate sandbox id: %w", err)
	}
	instance.ID = id
	return nil
}

func needsGeneratedRegistryID(instance *SandboxState) bool {
	if instance == nil {
		return false
	}

	if instance.ID == "" {
		return true
	}

	return strings.TrimSpace(instance.Provider) == "digitalocean" &&
		isLegacyDigitalOceanDropletID(instance.ID)
}

func repairRegistryInstanceID(path string, instance *SandboxState) error {
	if instance == nil {
		return nil
	}

	originalID := strings.TrimSpace(instance.ID)
	if err := ensureRegistryInstanceID(instance); err != nil {
		return err
	}
	if originalID == instance.ID {
		return nil
	}
	return persistRegistryInstance(path, instance)
}

func persistRegistryInstance(path string, instance *SandboxState) error {
	data, err := json.MarshalIndent(instance, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox %q: %w", instance.Name, err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write sandbox %q: %w", instance.Name, err)
	}
	if err := saveRegistryFile(tmpPath, path, true); err != nil {
		_ = removeRegistryFile(tmpPath)
		return fmt.Errorf("save sandbox %q: %w", instance.Name, err)
	}
	return nil
}

func isLegacyDigitalOceanDropletID(id string) bool {
	if id == "" {
		return false
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func validateRegistryPathName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("sandbox name is required")
	}
	if trimmed != name {
		return fmt.Errorf("must not have leading or trailing whitespace")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("must not be %q or %q", ".", "..")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("must not contain path separators")
	}
	return nil
}

func instancePath(name string) (string, error) {
	// Registry paths must remain compatible with legacy sandbox names that were
	// persisted before strict name validation existed. New-sandbox validation is
	// enforced by higher-level creation flows.
	if err := validateRegistryPathName(name); err != nil {
		return "", fmt.Errorf("invalid sandbox name: %w", err)
	}
	sandboxesDir, err := sandboxesDirPath()
	if err != nil {
		return "", fmt.Errorf("resolve sandboxes dir: %w", err)
	}
	return filepath.Join(sandboxesDir, name+sandboxStateFileExt), nil
}
