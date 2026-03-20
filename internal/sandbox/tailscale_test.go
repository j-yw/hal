package sandbox

import (
	"context"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestFetchTailscaleIP_UsesSudoForNonRootUser(t *testing.T) {
	t.Helper()

	var gotName string
	var gotArgs []string
	runSSH := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "bash", "-lc", "echo 100.64.0.1")
	}

	ip, err := fetchTailscaleIP(context.Background(), "ubuntu", "203.0.113.10", runSSH, nil, 1, time.Millisecond)
	if err != nil {
		t.Fatalf("fetchTailscaleIP() error = %v", err)
	}
	if ip != "100.64.0.1" {
		t.Fatalf("fetchTailscaleIP() ip = %q, want 100.64.0.1", ip)
	}

	want := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"ubuntu@203.0.113.10",
		"sudo", "cat", "/root/.tailscale-ip",
	}
	if gotName != "ssh" {
		t.Fatalf("runSSH command = %q, want ssh", gotName)
	}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("runSSH args = %#v, want %#v", gotArgs, want)
	}
}

func TestFetchTailscaleIP_RootUserReadsWithoutSudo(t *testing.T) {
	t.Helper()

	var gotArgs []string
	runSSH := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "bash", "-lc", "echo 100.64.0.2")
	}

	ip, err := fetchTailscaleIP(context.Background(), "root", "198.51.100.20", runSSH, nil, 1, time.Millisecond)
	if err != nil {
		t.Fatalf("fetchTailscaleIP() error = %v", err)
	}
	if ip != "100.64.0.2" {
		t.Fatalf("fetchTailscaleIP() ip = %q, want 100.64.0.2", ip)
	}

	want := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"root@198.51.100.20",
		"cat", "/root/.tailscale-ip",
	}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("runSSH args = %#v, want %#v", gotArgs, want)
	}
}
