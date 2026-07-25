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
const pendingRemovalGenerationFileExt = ".generation"
const sandboxRegistryLockFileName = "sandbox-registry.lock"

var (
	renameRegistryFile         = os.Rename
	removeRegistryFile         = os.Remove
	acquireSandboxRegistryLock = lockSandboxRegistry
)

// PendingInstanceRemoval temporarily hides a registry entry while a caller
// performs a destructive provider operation that may need rollback.
type PendingInstanceRemoval struct {
	name           string
	sandboxID      string
	generation     string
	path           string
	backupPath     string
	generationPath string
	active         bool
	alreadyStaged  bool
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
	normalizeRegistryInstance(instance, instance.Name)
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
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

	return writeInstanceLocked(instance, path, overwrite)
}

func writeInstanceLocked(instance *SandboxState, path string, overwrite bool) error {
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

// UpdateActiveInstanceExact atomically updates the active registry entry only
// while its stable name and ID still match the caller's selected instance.
// The update callback runs while the registry lock is held.
func UpdateActiveInstanceExact(
	name string,
	expectedID string,
	update func(*SandboxState) error,
) error {
	name = strings.TrimSpace(name)
	expectedID = strings.TrimSpace(expectedID)
	if name == "" || expectedID == "" {
		return errors.New("active sandbox identity is unavailable for exact update")
	}
	if update == nil {
		return errors.New("active sandbox update is required")
	}
	path, err := instancePath(name)
	if err != nil {
		return err
	}
	if err := EnsureGlobalDir(); err != nil {
		return err
	}
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

	current, err := loadRegistryInstanceFileLocked(path, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return fmt.Errorf("read sandbox %q: %w", name, err)
	}
	if strings.TrimSpace(current.ID) != expectedID ||
		strings.TrimSpace(current.Name) != name {
		return errors.New("sandbox instance changed during exact update")
	}
	if err := update(current); err != nil {
		return err
	}
	if strings.TrimSpace(current.ID) != expectedID ||
		strings.TrimSpace(current.Name) != name {
		return errors.New("sandbox identity cannot change during exact update")
	}
	return writeInstanceLocked(current, path, true)
}

func lockSandboxRegistry() (*sandboxLeaseStoreFileLock, error) {
	dir, err := sandboxesDirPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return lockSandboxLeaseStoreFile(filepath.Join(dir, sandboxRegistryLockFileName))
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
		generationPath := pendingPath + pendingRemovalGenerationFileExt
		if err := removeRegistryFile(generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("clear sandbox %q staged registry generation: %w", name, err)
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
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

	backupPath := path + pendingRemovalRegistryFileExt
	generationPath := backupPath + pendingRemovalGenerationFileExt
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
		instance, err := loadRegistryInstanceFileLocked(backupPath, name)
		if err != nil {
			return nil, fmt.Errorf("read sandbox %q staged registry entry: %w", name, err)
		}
		generation, err := loadOrCreatePendingRemovalGenerationLocked(generationPath)
		if err != nil {
			return nil, fmt.Errorf("load sandbox %q pending removal generation: %w", name, err)
		}
		return &PendingInstanceRemoval{
			name:           name,
			sandboxID:      strings.TrimSpace(instance.ID),
			generation:     generation,
			path:           path,
			backupPath:     backupPath,
			generationPath: generationPath,
			active:         true,
			alreadyStaged:  true,
		}, nil
	case backupExists && activeExists:
		return nil, fmt.Errorf("sandbox %q has both active and staged registry entries; resolve the pending removal before retrying", name)
	case !activeExists:
		return nil, fmt.Errorf("sandbox %q does not exist: %w", name, fs.ErrNotExist)
	}

	instance, err := loadRegistryInstanceFileLocked(path, name)
	if err != nil {
		return nil, fmt.Errorf("read sandbox %q registry entry: %w", name, err)
	}
	if err := removeRegistryFile(generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("clear sandbox %q stale pending removal generation: %w", name, err)
	}
	generation, err := NewV7()
	if err != nil {
		return nil, fmt.Errorf("generate sandbox %q pending removal generation: %w", name, err)
	}
	if err := renameRegistryFile(path, backupPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return nil, fmt.Errorf("prepare sandbox %q for replacement: %w", name, err)
	}
	if err := writePendingRemovalGenerationExclusive(generationPath, generation); err != nil {
		if restoreErr := renameRegistryFile(backupPath, path); restoreErr != nil {
			return nil, fmt.Errorf(
				"persist sandbox %q pending removal generation: %w (restore failed: %v)",
				name,
				err,
				restoreErr,
			)
		}
		return nil, fmt.Errorf("persist sandbox %q pending removal generation: %w", name, err)
	}

	return &PendingInstanceRemoval{
		name:           name,
		sandboxID:      strings.TrimSpace(instance.ID),
		generation:     generation,
		path:           path,
		backupPath:     backupPath,
		generationPath: generationPath,
		active:         true,
	}, nil
}

func loadOrCreatePendingRemovalGenerationLocked(path string) (string, error) {
	generation, err := readPendingRemovalGeneration(path)
	if err == nil {
		return generation, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	generation, err = NewV7()
	if err != nil {
		return "", err
	}
	if err := writePendingRemovalGenerationExclusive(path, generation); err != nil {
		return "", err
	}
	return generation, nil
}

func writePendingRemovalGenerationExclusive(path, generation string) error {
	generation = strings.TrimSpace(generation)
	if err := validateStorePathID(generation, "pending removal generation"); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(generation + "\n"); err != nil {
		_ = file.Close()
		_ = removeRegistryFile(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = removeRegistryFile(path)
		return err
	}
	return nil
}

func readPendingRemovalGeneration(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	generation := strings.TrimSpace(string(data))
	if err := validateStorePathID(generation, "pending removal generation"); err != nil {
		return "", err
	}
	return generation, nil
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
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()
	staged, active, err := p.validatePendingRemovalGenerationLocked()
	if err != nil {
		return err
	}
	if staged == nil {
		if active != nil {
			return fmt.Errorf("sandbox %q pending removal is stale", p.name)
		}
		if err := removeRegistryFile(p.generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("finalize sandbox %q replacement generation: %w", p.name, err)
		}
		p.active = false
		return nil
	}
	if err := removeRegistryFile(p.backupPath); err != nil {
		return fmt.Errorf("finalize sandbox %q replacement: %w", p.name, err)
	}
	if err := removeRegistryFile(p.generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("finalize sandbox %q replacement generation: %w", p.name, err)
	}
	p.active = false
	return nil
}

// Rollback restores a staged registry entry when remote deletion fails.
func (p *PendingInstanceRemoval) Rollback() error {
	if p == nil || !p.active {
		return nil
	}
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()
	staged, active, err := p.validatePendingRemovalGenerationLocked()
	if err != nil {
		return err
	}
	if staged == nil {
		if active == nil || strings.TrimSpace(active.ID) != strings.TrimSpace(p.sandboxID) {
			return fmt.Errorf("sandbox %q pending removal is stale", p.name)
		}
		if err := removeRegistryFile(p.generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("restore sandbox %q registry generation: %w", p.name, err)
		}
		p.active = false
		return nil
	}
	if active != nil {
		return fmt.Errorf("sandbox %q has both active and staged registry entries", p.name)
	}
	if err := renameRegistryFile(p.backupPath, p.path); err != nil {
		return fmt.Errorf("restore sandbox %q registry entry: %w", p.name, err)
	}
	if err := removeRegistryFile(p.generationPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("restore sandbox %q registry generation: %w", p.name, err)
	}
	p.active = false
	return nil
}

func (p *PendingInstanceRemoval) validatePendingRemovalGenerationLocked() (*SandboxState, *SandboxState, error) {
	if p == nil ||
		strings.TrimSpace(p.sandboxID) == "" ||
		strings.TrimSpace(p.generation) == "" ||
		strings.TrimSpace(p.generationPath) == "" {
		return nil, nil, errors.New("pending sandbox removal identity is unavailable")
	}
	generation, err := readPendingRemovalGeneration(p.generationPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("read sandbox %q pending removal generation: %w", p.name, err)
		}
		generation = ""
	}
	if generation != "" && generation != strings.TrimSpace(p.generation) {
		return nil, nil, fmt.Errorf("sandbox %q pending removal generation changed", p.name)
	}

	staged, stagedErr := readRegistryInstanceFile(p.backupPath, p.name)
	if stagedErr != nil && !errors.Is(stagedErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("read sandbox %q staged registry entry: %w", p.name, stagedErr)
	}
	active, activeErr := readRegistryInstanceFile(p.path, p.name)
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("read sandbox %q active registry entry: %w", p.name, activeErr)
	}
	if stagedErr == nil {
		if generation == "" {
			return nil, nil, fmt.Errorf("sandbox %q pending removal generation is unavailable", p.name)
		}
		if strings.TrimSpace(staged.ID) != strings.TrimSpace(p.sandboxID) {
			return nil, nil, fmt.Errorf("sandbox %q pending removal identity changed", p.name)
		}
	}
	return staged, active, nil
}

func loadRegistryInstanceFileLocked(path, name string) (*SandboxState, error) {
	instance, err := readRegistryInstanceFile(path, name)
	if err != nil {
		return nil, err
	}
	if err := repairRegistryInstanceIDLocked(path, instance); err != nil {
		return nil, fmt.Errorf("repair sandbox %q: %w", name, err)
	}
	return instance, nil
}

func readRegistryInstanceFile(path, name string) (*SandboxState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var instance SandboxState
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("parse sandbox %q: %w", name, err)
	}
	normalizeRegistryInstance(&instance, name)
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

	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

	instance, err := loadRegistryInstanceFileLocked(path, name)
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
	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

	instance, err := loadRegistryInstanceFileLocked(path, name)
	if err == nil {
		return instance, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	stagedPath := path + pendingRemovalRegistryFileExt
	instance, err = loadRegistryInstanceFileLocked(stagedPath, name)
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
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

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
		instance, err := loadRegistryInstanceFileLocked(path, name)
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
			instance, err := loadRegistryInstanceFileLocked(path, name)
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
	lock, err := acquireSandboxRegistryLock()
	if err != nil {
		return fmt.Errorf("acquire sandbox registry lock: %w", err)
	}
	defer lock.Close()

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
		instance.Status = StatusRunning
	}
	provider := strings.TrimSpace(instance.Provider)
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

func repairRegistryInstanceIDLocked(path string, instance *SandboxState) error {
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
