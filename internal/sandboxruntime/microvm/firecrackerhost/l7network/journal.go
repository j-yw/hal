package l7network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	journalVersion = 1
	journalLimit   = 64 << 10
)

type fileJournalStore struct{ root string }

type fileJournalLease struct {
	identity Identity
	dir      string
	path     string
	lock     *os.File
	released bool
	last     journalStage
}

type diskJournal struct {
	Version        int          `json:"version"`
	Identity       Identity     `json:"identity"`
	Stage          journalStage `json:"stage"`
	TAPName        string       `json:"tapName,omitempty"`
	TAPFingerprint string       `json:"tapFingerprint,omitempty"`
	RuleDigest     string       `json:"ruleDigest,omitempty"`
	ProxyAddress   string       `json:"proxyAddress,omitempty"`
	ProxyPort      uint16       `json:"proxyPort,omitempty"`
}

func newFileJournalStore(root string) (*fileJournalStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\x00\r\n") {
		return nil, ErrInvalidConfiguration
	}
	return &fileJournalStore{root: root}, nil
}

func (s *fileJournalStore) Acquire(ctx context.Context, identity Identity) (JournalLease, error) {
	if s == nil || !validIdentity(identity) {
		return nil, ErrInvalidIdentity
	}
	if err := ensurePrivateDir(s.root); err != nil {
		return nil, ErrCleanupIncomplete
	}
	dir := filepath.Join(s.root, identity.SandboxID)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, ErrCleanupIncomplete
	}
	lockPath := filepath.Join(dir, "host-topology.lock")
	lock, err := openPrivateFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, ErrCleanupIncomplete
	}
	if err := lockFile(lock); err != nil {
		_ = lock.Close()
		if errors.Is(err, errLockContended) {
			return nil, ErrTopologyCollision
		}
		if errors.Is(err, ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, ErrCleanupIncomplete
	}
	lease := &fileJournalLease{identity: identity, dir: dir, path: filepath.Join(dir, "host-topology.json"), lock: lock}
	retired := filepath.Join(dir, "retired-"+identity.TopologyGenerationID)
	if marker, err := openPrivateFile(retired, os.O_RDONLY, 0o600); err == nil {
		_ = marker.Close()
		_ = lease.Release()
		return nil, ErrStaleTopologyUnverified
	} else if !errors.Is(err, fs.ErrNotExist) {
		_ = lease.Release()
		return nil, ErrCleanupIncomplete
	}
	if ctx.Err() != nil {
		_ = lease.Release()
		return nil, ErrCleanupIncomplete
	}
	return lease, nil
}

func (l *fileJournalLease) Load() (journalRecord, error) {
	if l == nil || l.lock == nil || l.released {
		return journalRecord{}, ErrStaleTopologyUnverified
	}
	payload, err := readPrivateFile(l.path, journalLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return journalRecord{}, ErrJournalNotFound
	}
	if err != nil {
		return journalRecord{}, ErrStaleTopologyUnverified
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var disk diskJournal
	if decoder.Decode(&disk) != nil || decoder.Decode(&struct{}{}) != io.EOF || disk.Version != journalVersion ||
		disk.Identity != l.identity || !validJournalDisk(disk) {
		return journalRecord{}, ErrStaleTopologyUnverified
	}
	l.last = disk.Stage
	return journalRecord{identity: disk.Identity, stage: disk.Stage, tapName: disk.TAPName,
		tapFingerprint: disk.TAPFingerprint, ruleDigest: disk.RuleDigest,
		proxyAddress: disk.ProxyAddress, proxyPort: disk.ProxyPort}, nil
}

func (l *fileJournalLease) Save(ctx context.Context, record journalRecord) error {
	if l == nil || l.lock == nil || l.released || ctx.Err() != nil || record.identity != l.identity {
		return ErrCleanupIncomplete
	}
	disk := diskJournal{Version: journalVersion, Identity: record.identity, Stage: record.stage,
		TAPName: record.tapName, TAPFingerprint: record.tapFingerprint, RuleDigest: record.ruleDigest,
		ProxyAddress: record.proxyAddress, ProxyPort: record.proxyPort}
	if !validJournalDisk(disk) || stageOrder(record.stage) < stageOrder(l.last) {
		return ErrCleanupIncomplete
	}
	payload, err := json.Marshal(disk)
	if err != nil || len(payload) > journalLimit {
		return ErrCleanupIncomplete
	}
	if err := writePrivateAtomic(l.path, payload); err != nil {
		return ErrCleanupIncomplete
	}
	l.last = record.stage
	return nil
}

func (l *fileJournalLease) Remove() error {
	if l == nil || l.lock == nil || l.released {
		return ErrCleanupIncomplete
	}
	retired := filepath.Join(l.dir, "retired-"+l.identity.TopologyGenerationID)
	if err := writePrivateAtomic(retired, []byte("retired\n")); err != nil {
		return ErrCleanupIncomplete
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrCleanupIncomplete
	}
	if err := syncDir(l.dir); err != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func (l *fileJournalLease) Release() error {
	if l == nil || l.lock == nil || l.released {
		return nil
	}
	l.released = true
	return errors.Join(unlockFile(l.lock), l.lock.Close())
}

func validJournalDisk(disk diskJournal) bool {
	if !validIdentity(disk.Identity) || stageOrder(disk.Stage) == 0 {
		return false
	}
	if disk.TAPName != "" && !validInterfaceName(disk.TAPName) {
		return false
	}
	for _, value := range []string{disk.TAPFingerprint, disk.RuleDigest} {
		if value != "" && !safeIDPattern.MatchString(value) {
			return false
		}
	}
	if stageOrder(disk.Stage) >= stageOrder(journalStageTAPCreated) && disk.Stage != journalStageTopologyRemoved &&
		(disk.TAPName == "" || disk.TAPFingerprint == "" || disk.ProxyAddress == "" || disk.ProxyPort == 0) {
		return false
	}
	if disk.ProxyAddress != "" {
		address, err := netip.ParseAddr(disk.ProxyAddress)
		if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || disk.ProxyPort == 0 {
			return false
		}
	}
	return true
}

func stageOrder(stage journalStage) int {
	switch stage {
	case journalStageProxyStarting:
		return 1
	case journalStageTopologyStarting:
		return 2
	case journalStageTopologyPrepared:
		return 3
	case journalStageTAPCreated:
		return 4
	case journalStageRulesInspected:
		return 5
	case journalStageInspected:
		return 6
	case journalStageQuarantined:
		return 7
	case journalStageRulesRemoved:
		return 8
	case journalStageTAPRemoved:
		return 9
	case journalStageTopologyRemoved:
		return 10
	default:
		return 0
	}
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateFileOwned(info) {
		return ErrCleanupIncomplete
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func openPrivateFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, ErrCleanupIncomplete
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || !privateFileOwned(info) {
		_ = file.Close()
		return nil, ErrCleanupIncomplete
	}
	return file, nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := openPrivateFile(path, os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return nil, ErrStaleTopologyUnverified
	}
	return payload, nil
}

func writePrivateAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".host-topology-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
