package cmd

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
)

func TestFactoryFinalizationLegacyHalCommandsRemainUnchanged(t *testing.T) {
	record := factory.RunRecord{RepoPath: "/workspace/repo", BaseBranch: "main", BranchName: "hal/output"}
	verifyArgs, err := factorySandboxRemoteVerifyArgs(record)
	if err != nil {
		t.Fatal(err)
	}
	publishArgs, err := factorySandboxRemotePublishArgs(record, factoryRunRequest{BaseBranch: "main"}, factory.PublishPolicyPush, record.BranchName)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{verifyArgs, publishArgs} {
		if len(args) != 3 || args[0] != "sh" || args[1] != "-lc" || !strings.Contains(args[2], `exec "$HOME/.local/bin/hal"`) || strings.Contains(args[2], "exec hal ") {
			t.Fatal("legacy SSH finalization command changed")
		}
	}
}

func TestFactoryFinalizationRequiresWorkspace(t *testing.T) {
	for _, imageHal := range []bool{false, true} {
		if _, err := factorySandboxVerifyArgsForImage(factory.RunRecord{}, imageHal); err != errFactorySandboxWorkspaceRequired {
			t.Fatalf("verify missing workspace error=%v", err)
		}
		if _, err := factorySandboxPublishArgsForImage(factory.RunRecord{}, factoryRunRequest{}, "none", "hal/output", imageHal); err != errFactorySandboxWorkspaceRequired {
			t.Fatalf("publish missing workspace error=%v", err)
		}
	}
}
