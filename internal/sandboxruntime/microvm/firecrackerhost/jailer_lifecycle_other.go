//go:build !linux

package firecrackerhost

import "errors"

func statStrictJailerPrivateStateDir(string, uint32) (privateStateDirIdentity, error) {
	return privateStateDirIdentity{}, errors.New("strict Jailer state validation is unavailable")
}

func validateStrictJailerSocketOwnership(string, uint32) error {
	return errors.New("strict Jailer socket validation is unavailable")
}

func removeStrictJailerPinnedStateEntry(string, string, privateStateDirIdentity, uint32) error {
	return errors.New("strict Jailer state cleanup is unavailable")
}
