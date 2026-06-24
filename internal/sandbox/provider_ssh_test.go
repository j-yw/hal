package sandbox

import "testing"

func TestSSHRemoteCommandQuotesShellArgs(t *testing.T) {
	got := sshRemoteCommand([]string{"sh", "-lc", "cd '/workspace/hal' && exec 'git' 'checkout' '-B' 'develop' 'origin/develop'"})
	want := `'sh' '-lc' 'cd '"'"'/workspace/hal'"'"' && exec '"'"'git'"'"' '"'"'checkout'"'"' '"'"'-B'"'"' '"'"'develop'"'"' '"'"'origin/develop'"'"''`
	if got != want {
		t.Fatalf("sshRemoteCommand() = %q, want %q", got, want)
	}
}
