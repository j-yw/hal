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

// SaveHost persists a new sandbox host in the global host registry.
func SaveHost(host *SandboxHost) error {
	return writeHost(host, false)
}

// ForceWriteHost persists a sandbox host, replacing an existing record with
// the same ID.
func ForceWriteHost(host *SandboxHost) error {
	return writeHost(host, true)
}

func writeHost(host *SandboxHost, overwrite bool) error {
	if err := validateHost(host); err != nil {
		return err
	}

	path, err := hostPath(host.ID)
	if err != nil {
		return err
	}
	hostDir, err := sandboxHostsDirPath()
	if err != nil {
		return fmt.Errorf("resolve sandbox hosts dir: %w", err)
	}

	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		return fmt.Errorf("create sandbox hosts dir: %w", err)
	}

	if !overwrite {
		if exists, err := registryFileExists(path); err != nil {
			return fmt.Errorf("check host %q: %w", host.ID, err)
		} else if exists {
			return fmt.Errorf("host %q already exists", host.ID)
		}
	}

	data, err := json.MarshalIndent(host, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal host %q: %w", host.ID, err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write host %q: %w", host.ID, err)
	}
	if !overwrite {
		if exists, err := registryFileExists(path); err != nil {
			_ = removeRegistryFile(tmpPath)
			return fmt.Errorf("check host %q: %w", host.ID, err)
		} else if exists {
			_ = removeRegistryFile(tmpPath)
			return fmt.Errorf("host %q already exists", host.ID)
		}
	}
	if err := saveRegistryFile(tmpPath, path, overwrite); err != nil {
		_ = removeRegistryFile(tmpPath)
		return fmt.Errorf("save host %q: %w", host.ID, err)
	}

	return nil
}

func validateHost(host *SandboxHost) error {
	if host == nil {
		return fmt.Errorf("host is required")
	}
	if strings.TrimSpace(host.ID) == "" {
		return fmt.Errorf("host id is required")
	}
	if strings.TrimSpace(host.Name) == "" {
		return fmt.Errorf("host name is required")
	}
	if err := validateStorePathID(host.ID, "host id"); err != nil {
		return err
	}
	return nil
}

func hostPath(id string) (string, error) {
	if err := validateStorePathID(id, "host id"); err != nil {
		return "", err
	}
	dir, err := sandboxHostsDirPath()
	if err != nil {
		return "", fmt.Errorf("resolve sandbox hosts dir: %w", err)
	}
	return filepath.Join(dir, id+sandboxStateFileExt), nil
}

// LoadHost loads a sandbox host by ID from the global host registry.
func LoadHost(id string) (*SandboxHost, error) {
	path, err := hostPath(id)
	if err != nil {
		return nil, err
	}

	host, err := loadHostFile(path, id)
	if err == nil {
		return host, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("host %q does not exist: %w", id, err)
	}
	return nil, fmt.Errorf("read host %q: %w", id, err)
}

func loadHostFile(path, id string) (*SandboxHost, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var host SandboxHost
	if err := json.Unmarshal(data, &host); err != nil {
		return nil, fmt.Errorf("parse host %q: %w", id, err)
	}
	return &host, nil
}

// ListHosts returns all sandbox hosts sorted by name, then ID.
func ListHosts() ([]*SandboxHost, error) {
	hostDir, err := sandboxHostsDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox hosts dir: %w", err)
	}
	entries, err := os.ReadDir(hostDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandbox hosts dir: %w", err)
	}

	hosts := make([]*SandboxHost, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		path := filepath.Join(hostDir, entry.Name())
		host, err := loadHostFile(path, id)
		if err != nil {
			if strings.HasPrefix(err.Error(), "parse host ") {
				return nil, fmt.Errorf("parse host file %q: %w", entry.Name(), err)
			}
			return nil, fmt.Errorf("read host file %q: %w", entry.Name(), err)
		}
		hosts = append(hosts, host)
	}

	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Name == hosts[j].Name {
			return hosts[i].ID < hosts[j].ID
		}
		return hosts[i].Name < hosts[j].Name
	})

	return hosts, nil
}

// RemoveHost deletes a sandbox host from the global host registry.
func RemoveHost(id string) error {
	path, err := hostPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("host %q does not exist: %w", id, err)
		}
		return fmt.Errorf("remove host %q: %w", id, err)
	}
	return nil
}

func validateStorePathID(id, label string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%s is required", label)
	}
	if trimmed != id {
		return fmt.Errorf("%s must not have leading or trailing whitespace", label)
	}
	if id == "." || id == ".." {
		return fmt.Errorf("%s must not be %q or %q", label, ".", "..")
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return fmt.Errorf("%s must not contain path separators", label)
	}
	return nil
}
