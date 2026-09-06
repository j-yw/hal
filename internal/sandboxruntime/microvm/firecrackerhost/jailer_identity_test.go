package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

type fakeJailerIdentityStore struct {
	mu      sync.Mutex
	payload []byte
	owner   *fakeJailerIdentityFilesystem
	valid   bool
	fail    string
	hook    func(string)
}

type fakeJailerIdentityFilesystem struct {
	store  *fakeJailerIdentityStore
	closed bool
}

func newFakeJailerIdentityAuthority() (*strictJailerIdentityAuthority, *fakeJailerIdentityStore) {
	slot := strictJailerIdentitySlot{directory: "/prepared/identity", uid: 1001, gid: 1002}
	store := &fakeJailerIdentityStore{payload: idleJailerIdentityRecord(slot).payload(), valid: true}
	return &strictJailerIdentityAuthority{slot: slot, open: func(string) (strictJailerIdentityFilesystem, error) {
		return &fakeJailerIdentityFilesystem{store: store}, nil
	}}, store
}

func (fs *fakeJailerIdentityFilesystem) step(op string, fn func() error) error {
	fs.store.mu.Lock()
	var err error
	if fs.closed || !fs.store.valid || fs.store.fail == op {
		err = errJailerIdentity
	} else {
		err = fn()
	}
	hook := fs.store.hook
	fs.store.mu.Unlock()
	if hook != nil {
		hook(op)
	}
	return err
}

func (fs *fakeJailerIdentityFilesystem) lock() error {
	return fs.step("lock", func() error {
		if fs.store.owner != nil {
			return errJailerIdentity
		}
		fs.store.owner = fs
		return nil
	})
}
func (fs *fakeJailerIdentityFilesystem) verify() error {
	return fs.step("verify", func() error { return nil })
}
func (fs *fakeJailerIdentityFilesystem) read() (data []byte, err error) {
	err = fs.step("read", func() error {
		if fs.store.owner != fs {
			return errJailerIdentity
		}
		data = bytes.Clone(fs.store.payload)
		return nil
	})
	return
}
func (fs *fakeJailerIdentityFilesystem) write(data []byte) error {
	return fs.step("write", func() error {
		if fs.store.owner != fs {
			return errJailerIdentity
		}
		fs.store.payload = bytes.Clone(data)
		return nil
	})
}
func (fs *fakeJailerIdentityFilesystem) sync() error {
	return fs.step("sync", func() error { return nil })
}
func (fs *fakeJailerIdentityFilesystem) close() error {
	fs.store.mu.Lock()
	defer fs.store.mu.Unlock()
	if fs.closed {
		return nil
	}
	fs.closed = true
	if fs.store.owner == fs {
		fs.store.owner = nil
	}
	if fs.store.fail == "close" {
		return errJailerIdentity
	}
	return nil
}
func (store *fakeJailerIdentityStore) snapshot() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	return bytes.Clone(store.payload)
}
func reserveTestJailerIdentity(t *testing.T, authority *strictJailerIdentityAuthority) *strictJailerIdentityLease {
	t.Helper()
	lease, err := authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.close() })
	return lease
}

func TestJailerIdentityRequiresCanonicalPreparedIdleRecord(t *testing.T) {
	for _, name := range []string{"missing", "torn", "oversize", "version", "duplicate", "unknown", "uid", "gid", "case alias", "idle with owner", "busy stale", "pid expiry assertion", "unknown state", "extra newline"} {
		t.Run(name, func(t *testing.T) {
			authority, store := newFakeJailerIdentityAuthority()
			r := idleJailerIdentityRecord(authority.slot)
			switch name {
			case "missing":
				store.payload = nil
			case "torn":
				store.payload = r.payload()[:20]
			case "oversize":
				store.payload = bytes.Repeat([]byte(" "), jailerIdentityJournalLimit+1)
			case "version":
				r.Version++
				store.payload = r.payload()
			case "duplicate":
				store.payload = bytes.Replace(r.payload(), []byte(`"state":"idle"`), []byte(`"state":"busy","state":"idle"`), 1)
			case "unknown":
				store.payload = bytes.Replace(r.payload(), []byte(`"state":"idle"`), []byte(`"state":"idle","other":true`), 1)
			case "pid expiry assertion":
				store.payload = bytes.Replace(r.payload(), []byte(`"state":"idle"`), []byte(`"state":"idle","pid":1,"expired":true`), 1)
			case "uid":
				r.UID++
				store.payload = r.payload()
			case "gid":
				r.GID++
				store.payload = r.payload()
			case "case alias":
				store.payload = bytes.Replace(r.payload(), []byte(`"state"`), []byte(`"State"`), 1)
			case "idle with owner":
				r.RuntimeID = "old-run"
				store.payload = r.payload()
			case "busy stale":
				r.State, r.RuntimeID, r.Config, r.Nonce = "busy", "old-run", strings.Repeat("b", 64), strings.Repeat("c", 64)
				store.payload = r.payload()
			case "unknown state":
				r.State = "expired"
				store.payload = r.payload()
			case "extra newline":
				store.payload = append(r.payload(), '\n')
			}
			before := store.snapshot()
			lease, err := authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002)
			if err == nil || lease != nil || !bytes.Equal(before, store.snapshot()) || store.owner != nil {
				t.Fatal("untrusted journal was changed or admitted")
			}
		})
	}
}

func TestJailerIdentityRejectsUnconfiguredOrMismatchedSlot(t *testing.T) {
	for _, name := range []string{"nil", "zero uid", "zero gid", "wrong uid", "wrong gid", "empty directory", "root", "relative", "unclean", "bad runtime", "bad digest"} {
		t.Run(name, func(t *testing.T) {
			authority, _ := newFakeJailerIdentityAuthority()
			runtime, digest := "run-1", strings.Repeat("a", 64)
			switch name {
			case "nil":
				authority = nil
			case "zero uid":
				authority.slot.uid = 0
			case "zero gid":
				authority.slot.gid = 0
			case "wrong uid":
				authority.slot.uid++
			case "wrong gid":
				authority.slot.gid++
			case "empty directory":
				authority.slot.directory = ""
			case "root":
				authority.slot.directory = "/"
			case "relative":
				authority.slot.directory = "relative"
			case "unclean":
				authority.slot.directory += "/../identity"
			case "bad runtime":
				runtime = "../other"
			case "bad digest":
				digest = "bad"
			}
			if authority != nil {
				authority.open = func(string) (strictJailerIdentityFilesystem, error) {
					t.Fatal("invalid input opened authority")
					return nil, nil
				}
			}
			if lease, err := authority.reserve(context.Background(), runtime, digest, 1001, 1002); err == nil || lease != nil {
				t.Fatal("invalid slot accepted")
			}
		})
	}
}

func TestJailerIdentityExclusiveLeaseCloseAndStaleAliases(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	lease := reserveTestJailerIdentity(t, authority)
	alias := lease
	if next, err := authority.reserve(context.Background(), "run-2", strings.Repeat("b", 64), 1001, 1002); err == nil || next != nil {
		t.Fatal("busy slot reused")
	}
	if got, _ := json.Marshal(lease); string(got) != "{}" {
		t.Fatal("live identity became serializable")
	}
	if err := lease.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := reserveTestJailerIdentity(t, authority)
	before := store.snapshot()
	if alias.close() != nil || alias.release(context.Background()) != nil || alias.verify(context.Background()) == nil {
		t.Fatal("terminal alias behavior changed")
	}
	if next.verify(context.Background()) != nil || !bytes.Equal(before, store.snapshot()) {
		t.Fatal("stale alias touched new owner")
	}
	if next.close() != nil {
		t.Fatal("close failed")
	}
	if after, err := authority.reserve(context.Background(), "run-3", strings.Repeat("c", 64), 1001, 1002); err == nil || after != nil {
		t.Fatal("free lock reclaimed busy crash record")
	}
	if next.release(context.Background()) == nil {
		t.Fatal("closed lease released crash record")
	}
}

func TestJailerIdentityWriteSyncAndReadbackFailuresQuarantine(t *testing.T) {
	for _, phase := range []string{"busy", "idle"} {
		for _, failure := range []string{"write", "sync", "readback", "replacement"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				authority, store := newFakeJailerIdentityAuthority()
				var lease *strictJailerIdentityLease
				if phase == "idle" {
					lease = reserveTestJailerIdentity(t, authority)
				}
				store.hook = func(op string) {
					if op != "write" {
						return
					}
					store.mu.Lock()
					defer store.mu.Unlock()
					if failure == "readback" {
						store.payload = []byte("torn")
					}
					if failure == "replacement" {
						store.valid = false
					}
				}
				if failure == "write" || failure == "sync" {
					store.fail = failure
				}
				var err error
				if phase == "busy" {
					lease, err = authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002)
				} else {
					err = lease.release(context.Background())
				}
				if err == nil || lease == nil || !lease.poisoned || lease.verify(context.Background()) == nil {
					t.Fatal("failed commit authorized identity")
				}
				before := store.snapshot()
				store.fail, store.valid, store.hook = "", true, nil
				if lease.release(context.Background()) == nil || !bytes.Equal(before, store.snapshot()) {
					t.Fatal("uncertain update inferred idle or repaired record")
				}
				_ = lease.close()
			})
		}
	}
}

func TestJailerIdentityCancellationAndLaunchCloseRace(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lease, err := authority.reserve(ctx, "run-1", strings.Repeat("a", 64), 1001, 1002); err == nil || lease != nil || store.owner != nil {
		t.Fatal("canceled acquire reached lock")
	}
	lease := reserveTestJailerIdentity(t, authority)
	if lease.withLaunch(ctx, func() error { t.Fatal("canceled launch called"); return nil }) == nil {
		t.Fatal("canceled launch accepted")
	}
	entered, proceed, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	launch := make(chan error, 1)
	go func() {
		launch <- lease.withLaunch(context.Background(), func() error { close(entered); <-proceed; return nil })
	}()
	<-entered
	go func() { _ = lease.close(); close(closed) }()
	// The launch callback owns the mutex; Close cannot finish before it leaves.
	if lease.mu.TryLock() {
		lease.mu.Unlock()
		t.Fatal("launch did not retain lease lock")
	}
	select {
	case <-closed:
		t.Fatal("close revoked active callback")
	default:
	}
	close(proceed)
	if err := <-launch; err != nil {
		t.Fatal(err)
	}
	<-closed
	if lease.withLaunch(context.Background(), func() error { t.Fatal("closed launch called"); return nil }) == nil {
		t.Fatal("closed launch accepted")
	}
	if record, err := readJailerIdentityRecord(store.snapshot(), authority.slot); err != nil || record.State != "busy" {
		t.Fatal("close marked idle")
	}
}

type partialWriteJailerIdentityFilesystem struct{ strictJailerIdentityFilesystem }

func (fs partialWriteJailerIdentityFilesystem) write(payload []byte) error {
	if err := fs.strictJailerIdentityFilesystem.write(payload[:len(payload)/2]); err != nil {
		return err
	}
	return errJailerIdentity
}

func TestJailerIdentityPartialWriteRetainsUnusableLease(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	open := authority.open
	authority.open = func(path string) (strictJailerIdentityFilesystem, error) {
		fs, err := open(path)
		return partialWriteJailerIdentityFilesystem{fs}, err
	}
	lease, err := authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002)
	if err == nil || lease == nil || !lease.poisoned {
		t.Fatal("partial write admitted")
	}
	defer lease.close()
	before := store.snapshot()
	if lease.release(context.Background()) == nil || !bytes.Equal(before, store.snapshot()) {
		t.Fatal("partial record was repaired or inferred idle")
	}
	if lease.withLaunch(context.Background(), func() error { t.Fatal("partial commit launched"); return nil }) == nil {
		t.Fatal("partial commit usable")
	}
}

func TestJailerIdentityPreWriteFailuresCloseOnlyOwnHandles(t *testing.T) {
	for _, failure := range []string{"open", "lock", "verify", "read"} {
		t.Run(failure, func(t *testing.T) {
			authority, store := newFakeJailerIdentityAuthority()
			var opened *fakeJailerIdentityFilesystem
			authority.open = func(string) (strictJailerIdentityFilesystem, error) {
				opened = &fakeJailerIdentityFilesystem{store: store}
				if failure == "open" {
					return opened, errJailerIdentity
				}
				return opened, nil
			}
			store.fail = failure
			before := store.snapshot()
			if lease, err := authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002); err == nil || lease != nil {
				t.Fatal("failed admission succeeded")
			}
			if opened == nil || !opened.closed || store.owner != nil || !bytes.Equal(before, store.snapshot()) {
				t.Fatal("early failure leaked handle or changed journal")
			}
		})
	}
}

func TestJailerIdentityCloseFailureCannotTouchLaterLease(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	lease := reserveTestJailerIdentity(t, authority)
	store.fail = "close"
	if lease.release(context.Background()) == nil || !lease.idleCommitted || lease.released {
		t.Fatal("close failure not reported")
	}
	store.fail = ""
	next := reserveTestJailerIdentity(t, authority)
	before := store.snapshot()
	if lease.release(context.Background()) != nil || lease.close() != nil || next.verify(context.Background()) != nil || !bytes.Equal(before, store.snapshot()) {
		t.Fatal("close retry touched later ownership")
	}
	if lease.closeErr == nil {
		t.Fatal("retry erased the original close failure")
	}
}

func TestJailerIdentityCancellationAtLastCheckDoesNotWriteOrLaunch(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifies, writes := 0, 0
	store.hook = func(op string) {
		if op == "verify" {
			verifies++
			if verifies == 2 {
				cancel()
			}
		}
		if op == "write" {
			writes++
		}
	}
	before := store.snapshot()
	if lease, err := authority.reserve(ctx, "run-1", strings.Repeat("a", 64), 1001, 1002); err == nil || lease != nil {
		t.Fatal("last-check cancellation admitted")
	}
	if writes != 0 || store.owner != nil || !bytes.Equal(before, store.snapshot()) {
		t.Fatal("pre-write cancellation changed authority or retained lock")
	}
	store.hook = nil
	lease := reserveTestJailerIdentity(t, authority)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	store.hook = func(op string) {
		if op == "read" {
			cancel()
		}
	}
	if lease.withLaunch(ctx, func() error { t.Fatal("late cancellation launched"); return nil }) == nil {
		t.Fatal("late canceled verification succeeded")
	}
}

func TestJailerIdentityLaunchIsOneShotAndPreservesFailureOwnership(t *testing.T) {
	authority, store := newFakeJailerIdentityAuthority()
	lease := reserveTestJailerIdentity(t, authority)
	failure := errors.New("fixture launch failure")
	if err := lease.withLaunch(context.Background(), func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal("launch failure was lost")
	}
	if lease.withLaunch(context.Background(), func() error { t.Fatal("lease launched twice"); return nil }) == nil {
		t.Fatal("launch lease reused")
	}
	if record, err := readJailerIdentityRecord(store.snapshot(), authority.slot); err != nil || record.State != "busy" || store.owner == nil {
		t.Fatal("failed launch implicitly released identity")
	}
}
