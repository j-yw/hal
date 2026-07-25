//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

func (backend *linuxBackend) CopyIn(ctx context.Context, plan CopyInPlan) (CopyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CopyResult{}, linuxContextError(guestagent.OperationCopyIn, err)
	}
	limit := effectiveLinuxLimit(plan.MaxBytes, DefaultCopyBytes)
	if int64(len(plan.Data)) > limit {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyIn, "payload", "copy payload exceeds the server limit", nil)
	}
	if !validLinuxSHA256(plan.Digest) {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeInvalidMetadata, guestagent.OperationCopyIn, "payload.digest", "copy payload digest is invalid", nil)
	}
	digest := linuxSHA256(plan.Data)
	if plan.Digest != digest {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeDigestMismatch, guestagent.OperationCopyIn, "payload.digest", "copy payload digest does not match", nil)
	}

	relative, err := backend.guestRelative(guestagent.OperationCopyIn, "destinationPath", plan.DestinationPath, false)
	if err != nil {
		return CopyResult{}, err
	}
	parentRelative, destinationName := path.Split(relative)
	parentRelative = strings.TrimSuffix(parentRelative, "/")
	if parentRelative == "" {
		parentRelative = "."
	}
	if destinationName == "" || destinationName == "." || destinationName == ".." {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeMalformedPath, guestagent.OperationCopyIn, "destinationPath", "copy destination is invalid", nil)
	}
	parentFD, err := backend.openWorkspace(parentRelative, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy destination is unavailable", err)
	}
	defer unix.Close(parentFD)

	tempName, tempFD, err := createLinuxCopyTemp(parentFD)
	if err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy temporary file could not be created", err)
	}
	published := false
	tempOpen := true
	defer func() {
		if tempOpen {
			_ = unix.Close(tempFD)
		}
		if !published {
			_ = unix.Unlinkat(parentFD, tempName, 0)
		}
	}()

	backend.runAfterCopyTempOpenTestHook()
	if err := writeLinuxCopyData(ctx, tempFD, plan.Data); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return CopyResult{}, linuxContextError(guestagent.OperationCopyIn, err)
		}
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "payload", "copy payload could not be written", err)
	}
	if err := unix.Fchmod(tempFD, 0o600); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy mode could not be applied", err)
	}
	if err := unix.Fsync(tempFD); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy payload could not be synchronized", err)
	}
	if err := unix.Close(tempFD); err != nil {
		tempOpen = false
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy payload could not be closed", err)
	}
	tempOpen = false
	if err := ctx.Err(); err != nil {
		return CopyResult{}, linuxContextError(guestagent.OperationCopyIn, err)
	}

	if err := unix.Renameat(parentFD, tempName, parentFD, destinationName); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyIn, "destinationPath", "copy payload could not be published", err)
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeDurabilityUncertain, guestagent.OperationCopyIn, "destinationPath", "copy publication durability is uncertain", err)
	}
	return CopyResult{SizeBytes: int64(len(plan.Data)), Digest: digest}, nil
}

func (backend *linuxBackend) CopyOut(ctx context.Context, plan CopyOutPlan) (CopyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CopyResult{}, linuxContextError(guestagent.OperationCopyOut, err)
	}
	relative, err := backend.guestRelative(guestagent.OperationCopyOut, "sourcePath", plan.SourcePath, false)
	if err != nil {
		return CopyResult{}, err
	}
	sourceFD, err := backend.openWorkspace(relative, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source is unavailable", err)
	}
	defer unix.Close(sourceFD)

	var before unix.Stat_t
	if err := unix.Fstat(sourceFD, &before); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source is unavailable", err)
	}
	if !safeLinuxCopySource(before) {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source is not a safe regular file", nil)
	}

	readFD, err := unix.Openat(backend.procSelfFD, strconv.Itoa(sourceFD), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source is unreadable", err)
	}
	defer unix.Close(readFD)
	var reopened unix.Stat_t
	if err := unix.Fstat(readFD, &reopened); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source is unreadable", err)
	}
	if !sameLinuxFile(before, reopened) || !safeLinuxCopySource(reopened) {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeResourceChanged, guestagent.OperationCopyOut, "sourcePath", "copy source changed during open", nil)
	}

	limit := effectiveLinuxLimit(plan.MaxBytes, DefaultCopyBytes)
	if before.Size > limit {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyOut, "payload", "copy payload exceeds the server limit", nil)
	}
	data, oversized, err := readLinuxCopyData(ctx, readFD, limit)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return CopyResult{}, linuxContextError(guestagent.OperationCopyOut, err)
		}
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source could not be read", err)
	}
	if oversized {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeOversizedPayloadMetadata, guestagent.OperationCopyOut, "payload", "copy payload exceeds the server limit", nil)
	}
	var after unix.Stat_t
	if err := unix.Fstat(readFD, &after); err != nil {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeCopyFailed, guestagent.OperationCopyOut, "sourcePath", "copy source could not be verified", err)
	}
	if !unchangedLinuxCopySource(before, after) {
		return CopyResult{}, linuxBackendError(guestagent.ErrorCodeResourceChanged, guestagent.OperationCopyOut, "sourcePath", "copy source changed while reading", nil)
	}
	return CopyResult{
		Data:      data,
		SizeBytes: int64(len(data)),
		Digest:    linuxSHA256(data),
	}, nil
}

func createLinuxCopyTemp(parentFD int) (string, int, error) {
	var random [16]byte
	for attempt := 0; attempt < 32; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, err
		}
		name := ".hal-copy-" + hex.EncodeToString(random[:]) + ".tmp"
		fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, errors.New("temporary name attempts exhausted")
}

func writeLinuxCopyData(ctx context.Context, fd int, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readLinuxCopyData(ctx context.Context, fd int, limit int64) ([]byte, bool, error) {
	data := make([]byte, 0, minLinuxCapacity(limit))
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		count, err := unix.Read(fd, buffer)
		if count > 0 {
			remaining := limit + 1 - int64(len(data))
			retain := int64(count)
			if retain > remaining {
				retain = remaining
			}
			if retain > 0 {
				data = append(data, buffer[:int(retain)]...)
			}
			if int64(len(data)) > limit {
				return nil, true, nil
			}
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		if count == 0 {
			return data, false, nil
		}
	}
}

func minLinuxCapacity(limit int64) int {
	const initial = 32 * 1024
	if limit < initial {
		return int(limit)
	}
	return initial
}

func safeLinuxCopySource(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
}

func sameLinuxFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev &&
		left.Ino == right.Ino &&
		left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func unchangedLinuxCopySource(before, after unix.Stat_t) bool {
	return sameLinuxFile(before, after) &&
		safeLinuxCopySource(after) &&
		before.Size == after.Size &&
		before.Mtim.Sec == after.Mtim.Sec &&
		before.Mtim.Nsec == after.Mtim.Nsec &&
		before.Ctim.Sec == after.Ctim.Sec &&
		before.Ctim.Nsec == after.Ctim.Nsec
}

func validLinuxSHA256(digest string) bool {
	if len(digest) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, char := range strings.TrimPrefix(digest, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func linuxSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}
