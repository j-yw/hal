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
	"time"
)

// SandboxLeaseAcquireRequest contains the caller-supplied fields for a new
// durable lease. Timestamps and active status are assigned by the store.
type SandboxLeaseAcquireRequest struct {
	ID          string
	SandboxID   string
	SandboxName string
	ResourceKey string
	Holder      string
	Purpose     string
	RunID       string
}

// SandboxLeaseExactReleaseRequest identifies one durable lease transition
// without relying on a prior unlocked read.
type SandboxLeaseExactReleaseRequest struct {
	ID          string
	SandboxID   string
	SandboxName string
	ResourceKey string
	Purpose     string
	RunID       string
	AcquiredAt  time.Time
}

// SandboxLeaseStore provides durable local lease operations.
type SandboxLeaseStore struct {
	now func() time.Time
}

var acquireSandboxLeaseStoreLock = lockSandboxLeaseStoreFile

// SandboxLeaseConflictError reports that a resource already has an active
// lease. Its public message intentionally omits lease and resource identifiers.
type SandboxLeaseConflictError struct{}

func (*SandboxLeaseConflictError) Error() string {
	return "resource already has an active lease"
}

// NewSandboxLeaseStore returns a lease store that uses now for deterministic
// time-dependent operations.
func NewSandboxLeaseStore(now func() time.Time) *SandboxLeaseStore {
	if now == nil {
		now = time.Now
	}
	return &SandboxLeaseStore{now: now}
}

// Acquire validates and persists a new active lease.
func (s *SandboxLeaseStore) Acquire(req SandboxLeaseAcquireRequest, ttl time.Duration) (*SandboxLease, error) {
	if err := validateLeaseAcquireRequest(req); err != nil {
		return nil, err
	}

	path, err := leasePath(req.ID)
	if err != nil {
		return nil, err
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	if exists, err := registryFileExists(path); err != nil {
		return nil, fmt.Errorf("check lease %q: %w", req.ID, err)
	} else if exists {
		return nil, fmt.Errorf("lease %q already exists", req.ID)
	}
	if err := checkActiveLeaseConflict(leaseDir, req.ID, req.ResourceKey); err != nil {
		return nil, err
	}

	now := s.now()
	lease := &SandboxLease{
		ID:          req.ID,
		SandboxID:   req.SandboxID,
		SandboxName: req.SandboxName,
		ResourceKey: req.ResourceKey,
		Holder:      req.Holder,
		Purpose:     req.Purpose,
		RunID:       req.RunID,
		AcquiredAt:  now,
		ExpiresAt:   now.Add(ttl),
		HeartbeatAt: now,
		Status:      SandboxLeaseStatusActive,
	}

	if err := writeLeaseFile(path, lease, false); err != nil {
		return nil, err
	}
	return lease, nil
}

func checkActiveLeaseConflict(leaseDir, requestedID, resourceKey string) error {
	entries, err := os.ReadDir(leaseDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read sandbox leases dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		lease, err := loadLeaseFile(filepath.Join(leaseDir, entry.Name()), id)
		if err != nil {
			if strings.HasPrefix(err.Error(), "parse lease ") {
				return fmt.Errorf("parse lease file %q: %w", entry.Name(), err)
			}
			return fmt.Errorf("read lease file %q: %w", entry.Name(), err)
		}
		if lease.ID == requestedID {
			continue
		}
		if lease.Status == SandboxLeaseStatusActive && lease.ResourceKey == resourceKey {
			return &SandboxLeaseConflictError{}
		}
	}
	return nil
}

func validateLeaseAcquireRequest(req SandboxLeaseAcquireRequest) error {
	if strings.TrimSpace(req.ID) == "" {
		return fmt.Errorf("lease id is required")
	}
	if err := validateStorePathID(req.ID, "lease id"); err != nil {
		return err
	}
	if strings.TrimSpace(req.ResourceKey) == "" {
		return fmt.Errorf("lease resource key is required")
	}
	if strings.TrimSpace(req.Holder) == "" {
		return fmt.Errorf("lease holder is required")
	}
	if strings.TrimSpace(req.Purpose) == "" {
		return fmt.Errorf("lease purpose is required")
	}
	if err := validateLeaseResourceKey(req.ResourceKey, req.SandboxName); err != nil {
		return err
	}
	if !validLeasePurpose(req.Purpose) {
		return fmt.Errorf("lease purpose %q is not supported", req.Purpose)
	}
	return nil
}

func validateLeaseResourceKey(resourceKey, sandboxName string) error {
	prefix, suffix, ok := strings.Cut(resourceKey, ":")
	if !ok {
		return fmt.Errorf("lease resource key %q must include a supported prefix", resourceKey)
	}
	if suffix == "" {
		return fmt.Errorf("lease resource key %q must include a non-empty suffix", resourceKey)
	}

	switch prefix {
	case "sandbox":
		if strings.TrimSpace(sandboxName) == "" {
			return fmt.Errorf("sandbox name is required for sandbox resource leases")
		}
	case "workspace", "host", "runtime":
		return nil
	default:
		return fmt.Errorf("lease resource key prefix %q is not supported", prefix)
	}
	return nil
}

func validLeasePurpose(purpose string) bool {
	switch purpose {
	case SandboxLeasePurposeRun, SandboxLeasePurposeAuto, SandboxLeasePurposeFactory:
		return true
	default:
		return false
	}
}

func validLeaseStatus(status string) bool {
	switch status {
	case SandboxLeaseStatusActive, SandboxLeaseStatusReleased, SandboxLeaseStatusExpired:
		return true
	default:
		return false
	}
}

func leasePath(id string) (string, error) {
	if err := validateStorePathID(id, "lease id"); err != nil {
		return "", err
	}
	dir, err := sandboxLeasesDirPath()
	if err != nil {
		return "", fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	return filepath.Join(dir, id+sandboxStateFileExt), nil
}

func writeLeaseFile(path string, lease *SandboxLease, overwrite bool) error {
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lease %q: %w", lease.ID, err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write lease %q: %w", lease.ID, err)
	}
	if !overwrite {
		if exists, err := registryFileExists(path); err != nil {
			_ = removeRegistryFile(tmpPath)
			return fmt.Errorf("check lease %q: %w", lease.ID, err)
		} else if exists {
			_ = removeRegistryFile(tmpPath)
			return fmt.Errorf("lease %q already exists", lease.ID)
		}
	}
	if err := saveRegistryFile(tmpPath, path, overwrite); err != nil {
		_ = removeRegistryFile(tmpPath)
		return fmt.Errorf("save lease %q: %w", lease.ID, err)
	}
	return nil
}

// Load loads a lease by ID.
func (s *SandboxLeaseStore) Load(id string) (*SandboxLease, error) {
	path, err := leasePath(id)
	if err != nil {
		return nil, err
	}

	lease, err := loadLeaseFile(path, id)
	if err == nil {
		return lease, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("lease %q does not exist: %w", id, err)
	}
	return nil, fmt.Errorf("read lease %q: %w", id, err)
}

func loadLeaseFile(path, id string) (*SandboxLease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lease SandboxLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return nil, fmt.Errorf("parse lease %q: %w", id, err)
	}
	return &lease, nil
}

// List returns all durable leases sorted by resource key, then ID.
func (s *SandboxLeaseStore) List() ([]*SandboxLease, error) {
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	entries, err := os.ReadDir(leaseDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandbox leases dir: %w", err)
	}

	leases := make([]*SandboxLease, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		path := filepath.Join(leaseDir, entry.Name())
		lease, err := loadLeaseFile(path, id)
		if err != nil {
			if strings.HasPrefix(err.Error(), "parse lease ") {
				return nil, fmt.Errorf("parse lease file %q: %w", entry.Name(), err)
			}
			return nil, fmt.Errorf("read lease file %q: %w", entry.Name(), err)
		}
		leases = append(leases, lease)
	}

	sort.Slice(leases, func(i, j int) bool {
		if leases[i].ResourceKey == leases[j].ResourceKey {
			return leases[i].ID < leases[j].ID
		}
		return leases[i].ResourceKey < leases[j].ResourceKey
	})

	return leases, nil
}

// Remove deletes a durable lease record.
func (s *SandboxLeaseStore) Remove(id string) error {
	path, err := leasePath(id)
	if err != nil {
		return err
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("lease %q does not exist: %w", id, err)
		}
		return fmt.Errorf("remove lease %q: %w", id, err)
	}
	return nil
}

// Heartbeat extends an active lease's freshness timestamps.
func (s *SandboxLeaseStore) Heartbeat(id string, ttl time.Duration) (*SandboxLease, error) {
	path, err := leasePath(id)
	if err != nil {
		return nil, err
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	lease, err := loadLeaseFile(path, id)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("lease %q does not exist: %w", id, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read lease %q: %w", id, err)
	}
	if lease.Status != SandboxLeaseStatusActive {
		return nil, fmt.Errorf("lease %q is %s, want %s", id, lease.Status, SandboxLeaseStatusActive)
	}

	now := s.now()
	lease.HeartbeatAt = now
	lease.ExpiresAt = now.Add(ttl)
	if err := writeLeaseFile(path, lease, true); err != nil {
		return nil, err
	}
	return lease, nil
}

// Release marks an active lease released while preserving the durable record.
func (s *SandboxLeaseStore) Release(id string) (*SandboxLease, error) {
	path, err := leasePath(id)
	if err != nil {
		return nil, err
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	lease, err := s.Load(id)
	if err != nil {
		return nil, err
	}

	switch lease.Status {
	case SandboxLeaseStatusActive:
		lease.Status = SandboxLeaseStatusReleased
		if err := writeLeaseFile(path, lease, true); err != nil {
			return nil, err
		}
		return lease, nil
	case SandboxLeaseStatusReleased:
		return lease, nil
	case SandboxLeaseStatusExpired:
		return nil, fmt.Errorf("lease %q is %s and cannot be released", id, SandboxLeaseStatusExpired)
	default:
		return nil, fmt.Errorf("lease %q has unsupported status %q", id, lease.Status)
	}
}

// ReleaseExact atomically validates stable lease identity and marks that exact
// lease released while holding the store lock. Releasing an already released
// exact match is idempotent.
func (s *SandboxLeaseStore) ReleaseExact(req SandboxLeaseExactReleaseRequest) (*SandboxLease, error) {
	if err := validateSandboxLeaseExactReleaseRequest(req); err != nil {
		return nil, err
	}
	path, err := leasePath(req.ID)
	if err != nil {
		return nil, err
	}
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	lease, err := loadLeaseFile(path, req.ID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("lease does not exist: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("read exact lease: %w", err)
	}
	if !sandboxLeaseMatchesExactReleaseRequest(lease, req) {
		return nil, fmt.Errorf("lease identity did not match exact release request")
	}
	switch lease.Status {
	case SandboxLeaseStatusActive:
		lease.Status = SandboxLeaseStatusReleased
		if err := writeLeaseFile(path, lease, true); err != nil {
			return nil, err
		}
		return lease, nil
	case SandboxLeaseStatusReleased:
		return lease, nil
	case SandboxLeaseStatusExpired:
		return nil, fmt.Errorf("exact lease is expired and cannot be released")
	default:
		return nil, fmt.Errorf("exact lease has unsupported status")
	}
}

func validateSandboxLeaseExactReleaseRequest(req SandboxLeaseExactReleaseRequest) error {
	if err := validateStorePathID(strings.TrimSpace(req.ID), "lease id"); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "sandbox id", value: req.SandboxID},
		{name: "sandbox name", value: req.SandboxName},
		{name: "resource key", value: req.ResourceKey},
		{name: "purpose", value: req.Purpose},
		{name: "run id", value: req.RunID},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("lease %s is required", field.name)
		}
	}
	if req.AcquiredAt.IsZero() {
		return fmt.Errorf("lease acquired time is required")
	}
	return nil
}

func sandboxLeaseMatchesExactReleaseRequest(lease *SandboxLease, req SandboxLeaseExactReleaseRequest) bool {
	if lease == nil {
		return false
	}
	return strings.TrimSpace(lease.ID) == strings.TrimSpace(req.ID) &&
		strings.TrimSpace(lease.SandboxID) == strings.TrimSpace(req.SandboxID) &&
		strings.TrimSpace(lease.SandboxName) == strings.TrimSpace(req.SandboxName) &&
		strings.TrimSpace(lease.ResourceKey) == strings.TrimSpace(req.ResourceKey) &&
		strings.TrimSpace(lease.Purpose) == strings.TrimSpace(req.Purpose) &&
		strings.TrimSpace(lease.RunID) == strings.TrimSpace(req.RunID) &&
		lease.AcquiredAt.Equal(req.AcquiredAt)
}

// ExpireLeases marks stale active leases expired and returns the leases it
// changed.
func (s *SandboxLeaseStore) ExpireLeases() ([]*SandboxLease, error) {
	leaseDir, err := sandboxLeasesDirPath()
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox leases dir: %w", err)
	}
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox leases dir: %w", err)
	}
	lock, err := acquireSandboxLeaseStoreLock(filepath.Join(leaseDir, sandboxLeaseLockFileName))
	if err != nil {
		return nil, fmt.Errorf("acquire sandbox lease store lock: %w", err)
	}
	defer lock.Close()

	entries, err := os.ReadDir(leaseDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandbox leases dir: %w", err)
	}

	type staleLease struct {
		path  string
		lease *SandboxLease
	}
	now := s.now()
	stale := make([]staleLease, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		path := filepath.Join(leaseDir, entry.Name())
		lease, err := loadLeaseFile(path, id)
		if err != nil {
			if strings.HasPrefix(err.Error(), "parse lease ") {
				return nil, fmt.Errorf("parse lease file %q: %w", entry.Name(), err)
			}
			return nil, fmt.Errorf("read lease file %q: %w", entry.Name(), err)
		}
		if lease.Status == SandboxLeaseStatusActive && !lease.ExpiresAt.After(now) {
			lease.Status = SandboxLeaseStatusExpired
			stale = append(stale, staleLease{path: path, lease: lease})
		}
	}

	expired := make([]*SandboxLease, 0, len(stale))
	for _, item := range stale {
		if err := writeLeaseFile(item.path, item.lease, true); err != nil {
			return nil, err
		}
		expired = append(expired, item.lease)
	}
	return expired, nil
}
