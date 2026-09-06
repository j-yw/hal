package firecrackerhost

import (
	"crypto/sha256"
	"errors"
	"os"
	"sync"
)

var errStrictJailerExecutablesInvalid = errors.New("strict Jailer executable ownership is invalid")

// This is an executable acquisition bound, not a guest/runtime resource limit.
const maxStrictJailerExecutableBytes = 128 << 20

// The pair is an in-memory ownership object, never launch or security proof.
// Each snapshot is independently measured and sealed before publication.
// Closing the pair prevents new launches; an in-flight launch owns its own
// close-on-exec duplicates until its private mount namespace holds the files.
type strictJailerExecutablePair struct {
	mu      sync.Mutex
	entries [2]strictJailerExecutable
	closed  bool
}

type strictJailerExecutable struct {
	path   string
	file   *os.File
	digest [sha256.Size]byte
}

type strictJailerExecutableLease struct {
	entries [2]strictJailerExecutable
}

func (pair *strictJailerExecutablePair) close() error {
	if pair == nil {
		return nil
	}
	pair.mu.Lock()
	defer pair.mu.Unlock()
	if pair.closed {
		return nil
	}
	pair.closed = true
	return (&strictJailerExecutableLease{entries: pair.entries}).close()
}

func (lease *strictJailerExecutableLease) close() error {
	if lease == nil {
		return nil
	}
	var failed bool
	for index := range lease.entries {
		entry := &lease.entries[index]
		if entry.file != nil {
			if err := entry.file.Close(); err != nil {
				failed = true
			}
			entry.file = nil
		}
	}
	if failed {
		return errStrictJailerExecutablesInvalid
	}
	return nil
}

// Keep the old read-only inspector useful without granting its metadata any
// launch authority. Only this explicit private composition snapshots the pair.
func inspectAndPinStrictJailerHost(request strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
	inspection, err := inspectStrictJailerHost(request)
	if err != nil {
		return strictJailerHostInspectionResult{}, err
	}
	pair, err := pinStrictJailerExecutables(inspection)
	if err != nil {
		return strictJailerHostInspectionResult{}, errStrictJailerExecutablesInvalid
	}
	inspection.executables = pair
	return inspection, nil
}
