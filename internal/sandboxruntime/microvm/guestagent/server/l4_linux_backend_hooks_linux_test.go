//go:build linux && l4_guest_agent_server_integration

package server

func (backend *linuxBackend) setBeforeExecStartTestHook(hook func()) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.beforeExecStartTestHook = hook
}

func (backend *linuxBackend) setAfterCopyTempOpenTestHook(hook func()) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.afterCopyTempOpenTestHook = hook
}
