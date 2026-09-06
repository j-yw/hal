package firecrackerhost

func dispatchJailerRecoveryGate(ops l8RuntimeOwnerExecutableOps) int {
	if ops.OpenFD == nil || ops.CloseFD == nil || ops.RunJailerGate == nil {
		return 127
	}
	fds := [2]int{-1, -1}
	for index, role := range []string{"control-socket", "jailer-gate-config"} {
		fd, err := ops.OpenFD(uintptr(index+3), role)
		if err != nil || fd < 0 {
			for prior := index - 1; prior >= 0; prior-- {
				_ = ops.CloseFD(fds[prior])
			}
			return 127
		}
		fds[index] = fd
	}
	err := ops.RunJailerGate(fds)
	for index := len(fds) - 1; index >= 0; index-- {
		if closeErr := ops.CloseFD(fds[index]); closeErr != nil {
			err = closeErr
		}
	}
	if err != nil {
		return 127
	}
	return 0
}
