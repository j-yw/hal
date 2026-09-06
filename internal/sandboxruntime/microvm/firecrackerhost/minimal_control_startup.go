//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"golang.org/x/sys/unix"
)

const (
	minimalControlStartupTimeout  = 15 * time.Second
	minimalControlStartupDelay    = 100 * time.Millisecond
	minimalControlStartupAttempts = 150
)

var errMinimalControlPortPending = errors.New("minimal control port is pending")

// OpenWhenAvailable admits one raw stream, not authenticated readiness. The
// later controller must use the returned stream's effective admissionDeadline.
func (c *minimalControlTransport) OpenWhenAvailable(ctx context.Context, admissionDeadline time.Time) (*minimalControlStream, error) {
	if c == nil || !c.claimed.CompareAndSwap(false, true) || c.manager == nil || ctx == nil ||
		c.runtimeID != strings.TrimSpace(c.runtimeID) || admissionDeadline.IsZero() {
		return nil, errMinimalControlTransport
	}
	started := time.Now()
	hard := started.Add(minimalControlBound(c.lifetime, session.MaxGuestCredentialSessionLifetime))
	if deadline, ok := ctx.Deadline(); ok {
		hard = earlierMinimalControlTime(hard, deadline)
	}
	admissionDeadline = earlierMinimalControlTime(admissionDeadline, earlierMinimalControlTime(started.Add(minimalControlStartupTimeout), hard))
	if err := minimalControlStartupContextError(ctx, admissionDeadline); err != nil {
		return nil, err
	}
	process, err := c.resolveProcess()
	if err != nil {
		return nil, err
	}
	var pinned *vsockSocketIdentity
	for attempts := 0; ; {
		if err := c.startupCurrent(ctx, process, pinned, admissionDeadline); err != nil {
			return nil, err
		}
		observed, err := statVsockSocketForOwner(process.paths.VsockSocketPath, process.owner, c.checks)
		if err != nil {
			if pinned != nil || !os.IsNotExist(err) {
				return nil, errMinimalControlTransport
			}
		} else {
			if pinned == nil {
				pinned = &observed
			} else if observed != *pinned {
				return nil, errMinimalControlTransport
			}
			if err := c.startupCurrent(ctx, process, pinned, admissionDeadline); err != nil {
				return nil, err
			}
			attempts++
			deadline := earlierMinimalControlTime(admissionDeadline, time.Now().Add(minimalControlBound(c.handshakeTimeout, session.HandshakeDeadline)))
			stream, err := c.openAttempt(ctx, process, *pinned, hard, deadline, admissionDeadline)
			if err == nil || !errors.Is(err, errMinimalControlPortPending) {
				return stream, err
			}
			if attempts >= minimalControlStartupAttempts {
				return nil, errMinimalControlTransport
			}
		}
		// ENOENT itself has not proved the parent, and a closed attempt is no
		// longer watching the owner. Recheck before waiting and before retrying.
		if err := c.startupCurrent(ctx, process, pinned, admissionDeadline); err != nil {
			return nil, err
		}
		timer := time.NewTimer(min(minimalControlBound(c.startupPollInterval, minimalControlStartupDelay), time.Until(admissionDeadline)))
		select {
		case <-ctx.Done():
		case <-process.done:
		case <-process.owner.done:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func earlierMinimalControlTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func minimalControlStartupContextError(ctx context.Context, deadline time.Time) error {
	if ctx.Err() != nil {
		return minimalControlContextError(ctx)
	}
	if !time.Now().Before(deadline) {
		return errors.Join(errMinimalControlTransport, context.DeadlineExceeded)
	}
	return nil
}

func (c *minimalControlTransport) startupCurrent(ctx context.Context, expected liveProcessIdentity, socket *vsockSocketIdentity, deadline time.Time) error {
	if err := minimalControlStartupContextError(ctx, deadline); err != nil {
		return err
	}
	current, err := c.manager.resolveLiveProcessIdentity(expected.handle)
	if err != nil || current.handle != expected.handle || current.pid != expected.pid || current.done != expected.done ||
		current.paths != expected.paths || !sameVsockProcessOwner(current.owner, expected.owner) || !minimalControlStartupParentCurrent(expected) {
		return errMinimalControlTransport
	}
	if socket != nil {
		observed, err := statVsockSocketForOwner(expected.paths.VsockSocketPath, expected.owner, c.checks)
		if err != nil || observed != *socket {
			return errMinimalControlTransport
		}
	}
	return minimalControlStartupContextError(ctx, deadline)
}

// Independently establish the original parent even when the socket is absent.
// Do not repair ownership/modes or use the caller UID as the expected owner.
func minimalControlStartupParentCurrent(process liveProcessIdentity) bool {
	if process.owner == nil || !process.owner.active() {
		return false
	}
	fd, err := unix.Open(process.paths.StateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var retained, current unix.Stat_t
	if unix.Fstat(fd, &retained) != nil || unix.Fstatat(unix.AT_FDCWD, process.paths.StateDir, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return retained.Mode&unix.S_IFMT == unix.S_IFDIR && retained.Mode&0o7777 == 0o700 &&
		process.owner.parent.device == uint64(retained.Dev) && process.owner.parent.inode == retained.Ino && process.owner.uid == retained.Uid &&
		retained.Dev == current.Dev && retained.Ino == current.Ino && retained.Uid == current.Uid && retained.Mode == current.Mode && process.owner.active()
}
