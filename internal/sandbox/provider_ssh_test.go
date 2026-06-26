package sandbox

import "testing"

func TestNonInteractiveSSHOptionsDisablePrompts(t *testing.T) {
	got := nonInteractiveSSHOptionsWithConnectTimeout("10")
	want := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectTimeout=10",
	}
	if len(got) != len(want) {
		t.Fatalf("nonInteractiveSSHOptionsWithConnectTimeout() = %v, want %v", got, want)
	}
	for i, wantArg := range want {
		if got[i] != wantArg {
			t.Fatalf("nonInteractiveSSHOptionsWithConnectTimeout()[%d] = %q, want %q", i, got[i], wantArg)
		}
	}
}

func TestSSHRemoteCommandQuotesShellArgs(t *testing.T) {
	got := sshRemoteCommand([]string{"sh", "-lc", "cd '/workspace/hal' && exec 'git' 'checkout' '-B' 'develop' 'origin/develop'"})
	want := `'sh' '-lc' 'cd '"'"'/workspace/hal'"'"' && exec '"'"'git'"'"' '"'"'checkout'"'"' '"'"'-B'"'"' '"'"'develop'"'"' '"'"'origin/develop'"'"''`
	if got != want {
		t.Fatalf("sshRemoteCommand() = %q, want %q", got, want)
	}
}

func TestAppendSSHRemoteCommandSkipsEmptyArgs(t *testing.T) {
	base := []string{"-o", "LogLevel=ERROR", "root@10.0.0.42"}

	got := appendSSHRemoteCommand(append([]string(nil), base...), nil)
	if len(got) != len(base) {
		t.Fatalf("appendSSHRemoteCommand() appended empty command: got %v, want %v", got, base)
	}
	for i := range base {
		if got[i] != base[i] {
			t.Fatalf("appendSSHRemoteCommand()[%d] = %q, want %q", i, got[i], base[i])
		}
	}

	got = appendSSHRemoteCommand(append([]string(nil), base...), []string{"ls"})
	want := append(base, "'ls'")
	if len(got) != len(want) {
		t.Fatalf("appendSSHRemoteCommand() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("appendSSHRemoteCommand()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
