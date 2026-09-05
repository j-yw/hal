package sandboxworker

import "errors"

type workerPeerIdentity struct {
	uid uint32
	gid uint32
}

func validateWorkerPeerUID(peerUID, currentUID uint32) error {
	if peerUID != currentUID {
		return errors.New("worker peer identity is not authorized")
	}
	return nil
}

func validateWorkerPeerIdentity(peer workerPeerIdentity, currentUID, currentGID uint32) error {
	if validateWorkerPeerUID(peer.uid, currentUID) != nil || peer.gid != currentGID {
		return errors.New("worker peer identity is not authorized")
	}
	return nil
}

func validateWorkerPeerFilesystemFallback(bool) error {
	return errors.New("worker peer identity is unavailable")
}
