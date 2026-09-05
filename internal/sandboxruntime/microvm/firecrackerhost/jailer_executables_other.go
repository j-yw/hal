//go:build !linux

package firecrackerhost

func pinStrictJailerExecutables(strictJailerHostInspectionResult) (*strictJailerExecutablePair, error) {
	return nil, errStrictJailerExecutablesInvalid
}

func (*strictJailerExecutablePair) duplicateForLaunch(strictJailerCommand) (*strictJailerExecutableLease, error) {
	return nil, errStrictJailerExecutablesInvalid
}
