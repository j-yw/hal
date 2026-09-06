package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
)

var errJailerIdentity = errors.New("strict Jailer reserved identity unavailable")

const jailerIdentityJournalLimit = 1024

// This slot is trusted host configuration, never a job-supplied identity claim.
// All Hal processes must use the same prepared directory and reserved pair.
type strictJailerIdentitySlot struct {
	directory string
	uid, gid  uint32
}

type strictJailerIdentityFilesystem interface {
	lock() error
	verify() error
	read() ([]byte, error)
	write([]byte) error
	sync() error
	close() error
}

type strictJailerIdentityAuthority struct {
	slot strictJailerIdentitySlot
	open func(string) (strictJailerIdentityFilesystem, error)
}

func newStrictJailerIdentityAuthority(slot strictJailerIdentitySlot) *strictJailerIdentityAuthority {
	return &strictJailerIdentityAuthority{slot: slot, open: openLinuxJailerIdentityFilesystem}
}

// The journal is a private allocation record, not runtime absence evidence.
// Canonical encoding is required so aliases, duplicate fields and torn writes
// cannot acquire the meaning of an idle record.
type jailerIdentityRecord struct {
	Version   uint32 `json:"version"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	State     string `json:"state"`
	RuntimeID string `json:"runtimeId"`
	Config    string `json:"configSha256"`
	Nonce     string `json:"nonce"`
}

func (r jailerIdentityRecord) payload() []byte {
	data, _ := json.Marshal(r)
	return append(data, '\n')
}

func idleJailerIdentityRecord(slot strictJailerIdentitySlot) jailerIdentityRecord {
	return jailerIdentityRecord{Version: 1, UID: slot.uid, GID: slot.gid, State: "idle"}
}

func readJailerIdentityRecord(data []byte, slot strictJailerIdentitySlot) (jailerIdentityRecord, error) {
	var record jailerIdentityRecord
	if len(data) == 0 || len(data) > jailerIdentityJournalLimit || json.Unmarshal(data, &record) != nil ||
		!bytes.Equal(record.payload(), data) || record.Version != 1 || record.UID != slot.uid || record.GID != slot.gid {
		return record, errJailerIdentity
	}
	switch record.State {
	case "idle":
		if record != idleJailerIdentityRecord(slot) {
			return record, errJailerIdentity
		}
	case "busy":
		nonce, err := hex.DecodeString(record.Nonce)
		if !validStrictJailerRuntimeID(record.RuntimeID) || !validJailerStagingDigest(record.Config) ||
			err != nil || len(nonce) != 32 || record.Nonce != hex.EncodeToString(nonce) || bytes.Equal(nonce, make([]byte, 32)) {
			return record, errJailerIdentity
		}
	default:
		return record, errJailerIdentity
	}
	return record, nil
}

type strictJailerIdentityLease struct {
	mu                              sync.Mutex
	fs                              strictJailerIdentityFilesystem
	slot                            strictJailerIdentitySlot
	busy                            jailerIdentityRecord
	prepared, poisoned, launched    bool
	idleCommitted, closed, released bool
	closeErr                        error
}

func (authority *strictJailerIdentityAuthority) reserve(ctx context.Context, runtimeID, digest string, uid, gid uint32) (*strictJailerIdentityLease, error) {
	ctx = nonNilContext(ctx)
	if authority == nil || authority.open == nil || ctx.Err() != nil {
		return nil, errJailerIdentity
	}
	slot := authority.slot
	if slot.uid == 0 || slot.gid == 0 || slot.uid != uid || slot.gid != gid || !filepath.IsAbs(slot.directory) ||
		filepath.Clean(slot.directory) != slot.directory || slot.directory == "/" || strings.ContainsAny(slot.directory, "\x00\r\n") ||
		strings.TrimSpace(slot.directory) != slot.directory || !validStrictJailerRuntimeID(runtimeID) || !validJailerStagingDigest(digest) {
		return nil, errJailerIdentity
	}
	fs, err := authority.open(slot.directory)
	if interfaceValueIsNil(fs) {
		return nil, errJailerIdentity
	}
	owned := false
	defer func() {
		if !owned {
			_ = fs.close()
		}
	}()
	if err != nil || ctx.Err() != nil || fs.lock() != nil || fs.verify() != nil {
		return nil, errJailerIdentity
	}
	data, err := fs.read()
	record, parseErr := readJailerIdentityRecord(data, slot)
	if err != nil || parseErr != nil || record.State != "idle" || ctx.Err() != nil {
		return nil, errJailerIdentity
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil || nonce == ([32]byte{}) {
		return nil, errJailerIdentity
	}
	busy := jailerIdentityRecord{Version: 1, UID: uid, GID: gid, State: "busy", RuntimeID: runtimeID, Config: digest, Nonce: hex.EncodeToString(nonce[:])}
	lease := &strictJailerIdentityLease{fs: fs, slot: slot, busy: busy}
	owned = true
	if ctx.Err() != nil {
		_ = lease.close()
		return nil, errJailerIdentity
	}
	if lease.commitLocked(ctx, busy) != nil {
		if !lease.poisoned {
			// Canceled after the last read-only check, before any journal write.
			_ = lease.close()
			return nil, errJailerIdentity
		}
		return lease, errJailerIdentity
	}
	lease.prepared = true
	if ctx.Err() != nil {
		return lease, errJailerIdentity
	}
	return lease, nil
}

// Once an update is uncertain, this live lease cannot infer idle or repair a
// record opportunistically. Close leaves durable state for quarantine.
func (lease *strictJailerIdentityLease) commitLocked(ctx context.Context, record jailerIdentityRecord) error {
	payload := record.payload()
	if lease.fs.verify() != nil {
		lease.poisoned = true
		return errJailerIdentity
	}
	if nonNilContext(ctx).Err() != nil {
		return errJailerIdentity
	}
	// Once a write starts, complete synchronization/readback even if canceled;
	// it is not safe to abandon or roll back an uncertain durable transition.
	if lease.fs.write(payload) != nil || lease.fs.sync() != nil || lease.fs.verify() != nil {
		lease.poisoned = true
		return errJailerIdentity
	}
	got, err := lease.fs.read()
	if err != nil || !bytes.Equal(got, payload) || lease.fs.verify() != nil {
		lease.poisoned = true
		return errJailerIdentity
	}
	return nil
}

func (lease *strictJailerIdentityLease) verifyLocked(ctx context.Context) error {
	if nonNilContext(ctx).Err() != nil || !lease.prepared || lease.poisoned || lease.closed || lease.idleCommitted {
		return errJailerIdentity
	}
	if lease.fs.verify() != nil {
		lease.poisoned = true
		return errJailerIdentity
	}
	got, err := lease.fs.read()
	if err != nil || !bytes.Equal(got, lease.busy.payload()) || lease.fs.verify() != nil {
		lease.poisoned = true
		return errJailerIdentity
	}
	if nonNilContext(ctx).Err() != nil {
		return errJailerIdentity
	}
	return nil
}

func (lease *strictJailerIdentityLease) verify(ctx context.Context) error {
	if lease == nil {
		return errJailerIdentity
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.verifyLocked(ctx)
}

func (lease *strictJailerIdentityLease) verifyCleanup(ctx context.Context) error {
	if lease == nil {
		return errJailerIdentity
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	// Only a failed close remains after a successful idle commit. All resource
	// cleanup was already terminal; a retry must touch old handles only.
	if lease.idleCommitted && !lease.poisoned && nonNilContext(ctx).Err() == nil {
		return nil
	}
	return lease.verifyLocked(ctx)
}

// Close waits for this one-shot launch callback. The commit point is the
// existing lifecycle start: cancellation is checked immediately beforehand;
// once entered, its returned process/cleanup ownership must be preserved.
func (lease *strictJailerIdentityLease) withLaunch(ctx context.Context, use func() error) error {
	if lease == nil || use == nil {
		return errJailerIdentity
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.launched || lease.verifyLocked(ctx) != nil || nonNilContext(ctx).Err() != nil {
		return errJailerIdentity
	}
	lease.launched = true
	return use()
}

// Only the owning coordinator calls release, after its exact terminal cleanup
// sequence. No durable record, PID, timeout or caller boolean is a substitute.
func (lease *strictJailerIdentityLease) release(ctx context.Context) error {
	if lease == nil {
		return errJailerIdentity
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil
	}
	if !lease.idleCommitted {
		if lease.verifyLocked(ctx) != nil || nonNilContext(ctx).Err() != nil || lease.commitLocked(ctx, idleJailerIdentityRecord(lease.slot)) != nil {
			return errJailerIdentity
		}
		lease.idleCommitted = true
	}
	// A close retry touches only old retained handles, never a later journal.
	if err := lease.fs.close(); err != nil {
		if lease.closeErr == nil {
			lease.closeErr = err
		}
		return errJailerIdentity
	}
	lease.closed, lease.released = true, true
	return nil
}

func (lease *strictJailerIdentityLease) close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	if err := lease.fs.close(); err != nil {
		if lease.closeErr == nil {
			lease.closeErr = err
		}
		return errJailerIdentity
	}
	return nil
}
