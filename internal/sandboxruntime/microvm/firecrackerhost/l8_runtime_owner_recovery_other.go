//go:build !linux

package firecrackerhost

import "github.com/jywlabs/hal/internal/sandboxruntime"

func l8RuntimeOwnerPlatformSupported() bool { return false }

func readL8RuntimeOwnerHostBootID() (string, error) {
	return "", errL8RuntimeOwnerUnsupported
}

func inspectL8RuntimeOwnerProcess(uint32) (l8RuntimeOwnerProcessObservation, error) {
	return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerUnsupported
}

func writeL8RuntimeOwnerRecord(string, firecrackerRuntimeOwnerRecordV1, sandboxruntime.JobCredentialIdentitySeed, string) error {
	return errL8RuntimeOwnerUnsupported
}

func readL8RuntimeOwnerRecord(string, sandboxruntime.JobCredentialIdentitySeed, string) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerUnsupported
}

func closeL8RuntimeOwnerProcessFD(int) error { return nil }
