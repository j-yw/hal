//go:build linux

package linuxtopology

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	privateJournalVersion = 1
	sysPIDFDOpen          = 434
	sysPIDFDSendSignal    = 424
)

type fileOwnershipStore struct {
	root string
}

type fileOwnershipLease struct {
	store       *fileOwnershipStore
	identity    Identity
	dir         string
	journalPath string
	lock        *os.File
	released    bool
}

type privateProcessRecord struct {
	PID       int    `json:"pid"`
	StartTime string `json:"startTime"`
}

type privateNamespaceRecord struct {
	UserDevice uint64 `json:"userDevice"`
	UserInode  uint64 `json:"userInode"`
	NetDevice  uint64 `json:"netDevice"`
	NetInode   uint64 `json:"netInode"`
}

type privateOwnershipJournal struct {
	Version        int                     `json:"version"`
	Identity       Identity                `json:"identity"`
	Keeper         *privateProcessRecord   `json:"keeper,omitempty"`
	Mapper         *privateProcessRecord   `json:"mapper,omitempty"`
	Namespace      *privateNamespaceRecord `json:"namespace,omitempty"`
	MappingArmed   bool                    `json:"mappingArmed,omitempty"`
	MappingCreator *privateProcessRecord   `json:"mappingCreator,omitempty"`
}

func newFileOwnershipStore(root string) (*fileOwnershipStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\x00\r\n") {
		return nil, ErrInvalidTools
	}
	return &fileOwnershipStore{root: root}, nil
}

func (s *fileOwnershipStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	return s.acquire(ctx, identity)
}

func (s *fileOwnershipStore) acquire(ctx context.Context, identity Identity) (*fileOwnershipLease, error) {
	if s == nil || !validIdentity(identity) {
		return nil, ErrInvalidIdentity
	}
	if err := ensurePrivateDirectory(s.root); err != nil {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("state_root_invalid"))
	}
	dir := filepath.Join(s.root, identity.SandboxID)
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("sandbox_state_invalid"))
	}
	lock, err := openPrivateRegular(filepath.Join(dir, "ownership.lock"), syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("ownership_lock_invalid"))
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrTopologyCollision
		}
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("ownership_lock_failed"))
	}
	lease := &fileOwnershipLease{
		store: s, identity: identity, dir: dir,
		journalPath: filepath.Join(dir, "ownership.json"), lock: lock,
	}
	retired := filepath.Join(dir, "retired-"+identity.TopologyGenerationID)
	if marker, err := openPrivateRegular(retired, syscall.O_RDONLY, 0o600); err == nil {
		if closeErr := marker.Close(); closeErr != nil {
			_ = lease.Release()
			return nil, ErrCleanupIncomplete
		}
		_ = lease.Release()
		return nil, ErrStaleGeneration
	} else if !errors.Is(err, fs.ErrNotExist) {
		_ = lease.Release()
		return nil, ErrCleanupIncomplete
	}
	if err := ctx.Err(); err != nil {
		_ = lease.Release()
		return nil, ErrStartFailed
	}
	return lease, nil
}

func (l *fileOwnershipLease) Reconcile(ctx context.Context) error {
	if l == nil || l.lock == nil || l.released {
		return ErrStaleTopologyUnverified
	}
	payload, err := readPrivateBounded(l.journalPath, maxOutputLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || len(payload) == 0 || int64(len(payload)) > maxOutputLimit {
		return ErrStaleTopologyUnverified
	}
	var journal privateOwnershipJournal
	if json.Unmarshal(payload, &journal) != nil || journal.Version != privateJournalVersion || !validIdentity(journal.Identity) {
		return ErrStaleTopologyUnverified
	}
	if journal.Identity.SandboxID != l.identity.SandboxID {
		return ErrIdentityMismatch
	}
	if journal.MappingArmed {
		if journal.Mapper != nil || journal.MappingCreator == nil || journal.Keeper == nil || journal.Namespace == nil {
			return ErrStaleTopologyUnverified
		}
		alive, err := recordedProcessCurrent(*journal.MappingCreator)
		if err != nil || alive {
			return ErrStaleTopologyUnverified
		}
	} else if journal.MappingCreator != nil {
		return ErrStaleTopologyUnverified
	}
	if journal.Mapper != nil {
		if err := terminateRecordedProcess(ctx, *journal.Mapper, nil); err != nil {
			return ErrStaleTopologyUnverified
		}
	}
	if journal.Keeper != nil {
		if err := terminateRecordedProcess(ctx, *journal.Keeper, journal.Namespace); err != nil {
			return ErrStaleTopologyUnverified
		}
	}
	retired := filepath.Join(l.dir, "retired-"+journal.Identity.TopologyGenerationID)
	if err := writePrivateAtomic(retired, []byte("retired\n")); err != nil {
		return ErrStaleTopologyUnverified
	}
	if err := os.Remove(l.journalPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrStaleTopologyUnverified
	}
	if err := syncDirectory(l.dir); err != nil {
		return ErrStaleTopologyUnverified
	}
	if journal.Identity.TopologyGenerationID == l.identity.TopologyGenerationID {
		return ErrStaleGeneration
	}
	return nil
}

func (l *fileOwnershipLease) Record(_ context.Context, keeper, mapper ProcessHandle, namespace *NamespaceHandle) error {
	if l == nil || l.lock == nil || l.released {
		return ErrCleanupIncomplete
	}
	journal := privateOwnershipJournal{Version: privateJournalVersion, Identity: l.identity}
	var err error
	if keeper != nil {
		journal.Keeper, err = recordProcess(keeper)
		if err != nil {
			return ErrCleanupIncomplete
		}
	}
	if mapper != nil {
		journal.Mapper, err = recordProcess(mapper)
		if err != nil {
			return ErrCleanupIncomplete
		}
	}
	if namespace != nil {
		journal.Namespace, err = recordNamespace(namespace)
		if err != nil {
			return ErrCleanupIncomplete
		}
	}
	payload, err := json.Marshal(journal)
	if err != nil {
		return ErrCleanupIncomplete
	}
	if err := writePrivateAtomic(l.journalPath, payload); err != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func (l *fileOwnershipLease) ArmMapping(_ context.Context, keeper ProcessHandle, namespace *NamespaceHandle) error {
	if l == nil || l.lock == nil || l.released || keeper == nil || namespace == nil {
		return ErrCleanupIncomplete
	}
	keeperRecord, err := recordProcess(keeper)
	if err != nil {
		return ErrCleanupIncomplete
	}
	namespaceRecord, err := recordNamespace(namespace)
	if err != nil {
		return ErrCleanupIncomplete
	}
	creatorRecord, err := currentProcessRecord()
	if err != nil {
		return ErrCleanupIncomplete
	}
	journal := privateOwnershipJournal{
		Version: privateJournalVersion, Identity: l.identity,
		Keeper: keeperRecord, Namespace: namespaceRecord,
		MappingArmed: true, MappingCreator: creatorRecord,
	}
	payload, err := json.Marshal(journal)
	if err != nil || writePrivateAtomic(l.journalPath, payload) != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func (l *fileOwnershipLease) Retire(identity Identity) error { return l.retire(identity) }

func (l *fileOwnershipLease) retire(identity Identity) error {
	if l == nil || l.lock == nil || l.released || identity != l.identity {
		return ErrIdentityMismatch
	}
	retired := filepath.Join(l.dir, "retired-"+identity.TopologyGenerationID)
	if err := writePrivateAtomic(retired, []byte("retired\n")); err != nil {
		return ErrCleanupIncomplete
	}
	if err := os.Remove(l.journalPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrCleanupIncomplete
	}
	return syncDirectory(l.dir)
}

func (l *fileOwnershipLease) Release() error { return l.release() }

func (l *fileOwnershipLease) release() error {
	if l == nil || l.lock == nil || l.released {
		return nil
	}
	l.released = true
	err := syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN)
	return errors.Join(err, l.lock.Close())
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return ErrCleanupIncomplete
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrCleanupIncomplete
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return ErrCleanupIncomplete
		}
	}
	return nil
}

func openPrivateRegular(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(mode) {
		_ = file.Close()
		return nil, ErrCleanupIncomplete
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = file.Close()
		return nil, ErrCleanupIncomplete
	}
	return file, nil
}

func writePrivateAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".ownership-*")
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
	return syncDirectory(dir)
}

func readPrivateBounded(path string, limit int64) ([]byte, error) {
	file, err := openPrivateRegular(path, syscall.O_RDONLY, 0o600)
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

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func recordProcess(process ProcessHandle) (*privateProcessRecord, error) {
	owned, ok := process.(interface {
		ownershipRecord() (privateProcessRecord, bool)
	})
	if !ok {
		return nil, ErrCleanupIncomplete
	}
	record, valid := owned.ownershipRecord()
	if !valid || record.PID <= 0 || record.StartTime == "" {
		return nil, ErrCleanupIncomplete
	}
	return &record, nil
}

func recordNamespace(namespace *NamespaceHandle) (*privateNamespaceRecord, error) {
	if namespace == nil {
		return nil, ErrCleanupIncomplete
	}
	namespace.mu.Lock()
	defer namespace.mu.Unlock()
	if namespace.closed {
		return nil, ErrCleanupIncomplete
	}
	user, userOK := namespace.userInfo.Sys().(*syscall.Stat_t)
	network, networkOK := namespace.netInfo.Sys().(*syscall.Stat_t)
	if !userOK || !networkOK {
		return nil, ErrCleanupIncomplete
	}
	return &privateNamespaceRecord{
		UserDevice: uint64(user.Dev), UserInode: user.Ino,
		NetDevice: uint64(network.Dev), NetInode: network.Ino,
	}, nil
}

func readProcessStartTime(pid int) (string, error) {
	payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closing := strings.LastIndexByte(string(payload), ')')
	if closing < 0 {
		return "", ErrStaleTopologyUnverified
	}
	fields := strings.Fields(string(payload[closing+1:]))
	if len(fields) <= 19 {
		return "", ErrStaleTopologyUnverified
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", ErrStaleTopologyUnverified
	}
	return fields[19], nil
}

func currentProcessRecord() (*privateProcessRecord, error) {
	pid := os.Getpid()
	startTime, err := readProcessStartTime(pid)
	if err != nil {
		return nil, err
	}
	return &privateProcessRecord{PID: pid, StartTime: startTime}, nil
}

func recordedProcessCurrent(record privateProcessRecord) (bool, error) {
	if record.PID <= 0 || record.StartTime == "" {
		return false, ErrStaleTopologyUnverified
	}
	startTime, err := readProcessStartTime(record.PID)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return startTime == record.StartTime, nil
}

func terminateRecordedProcess(ctx context.Context, record privateProcessRecord, namespace *privateNamespaceRecord) error {
	pidfd, _, errno := syscall.Syscall(uintptr(sysPIDFDOpen), uintptr(record.PID), 0, 0)
	if errno == syscall.ESRCH {
		return nil
	}
	if errno != 0 {
		return errno
	}
	defer syscall.Close(int(pidfd))
	start, err := readProcessStartTime(record.PID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || start != record.StartTime {
		return ErrIdentityMismatch
	}
	if namespace != nil {
		if !recordedNamespaceMatches(record.PID, *namespace) {
			return ErrIdentityMismatch
		}
	}
	if errno := pidfdSignal(int(pidfd), syscall.SIGTERM); errno != 0 && errno != syscall.ESRCH {
		return errno
	}
	deadline := time.Now().Add(defaultCleanupTimeout)
	for time.Now().Before(deadline) {
		if errno := pidfdSignal(int(pidfd), 0); errno == syscall.ESRCH {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if errno := pidfdSignal(int(pidfd), syscall.SIGKILL); errno != 0 && errno != syscall.ESRCH {
		return errno
	}
	return waitForPIDFDExit(ctx, int(pidfd), defaultCleanupTimeout)
}

func waitForPIDFDExit(ctx context.Context, pidfd int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if errno := pidfdSignal(pidfd, 0); errno == syscall.ESRCH {
			return nil
		} else if errno != 0 {
			return errno
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ErrStaleTopologyUnverified
}

func pidfdSignal(pidfd int, signal syscall.Signal) syscall.Errno {
	_, _, errno := syscall.Syscall6(uintptr(sysPIDFDSendSignal), uintptr(pidfd), uintptr(signal), 0, 0, 0, 0)
	return errno
}

func recordedNamespaceMatches(pid int, record privateNamespaceRecord) bool {
	user, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns", "user"))
	if err != nil {
		return false
	}
	network, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns", "net"))
	if err != nil {
		return false
	}
	userStat, userOK := user.Sys().(*syscall.Stat_t)
	netStat, netOK := network.Sys().(*syscall.Stat_t)
	return userOK && netOK && uint64(userStat.Dev) == record.UserDevice && userStat.Ino == record.UserInode &&
		uint64(netStat.Dev) == record.NetDevice && netStat.Ino == record.NetInode
}
