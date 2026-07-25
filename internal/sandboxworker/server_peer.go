package sandboxworker

import "errors"

func validateWorkerPeerUID(peerUID, currentUID uint32) error {
	if peerUID != currentUID {
		return errors.New("worker peer identity is not authorized")
	}
	return nil
}

func validateWorkerPeerFilesystemFallback(bool) error {
	return errors.New("worker peer identity is unavailable")
}
