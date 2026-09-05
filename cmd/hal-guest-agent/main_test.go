package main

import "testing"

func TestLinuxBackendOptionsLockWorkspaceGuestRoot(t *testing.T) {
	options := linuxBackendOptions()
	if options.WorkspaceRoot != "/workspace" {
		t.Fatalf("WorkspaceRoot = %q, want /workspace", options.WorkspaceRoot)
	}
	if options.GuestRoot != "/workspace" {
		t.Fatalf("GuestRoot = %q, want /workspace", options.GuestRoot)
	}
}
