package factory

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestBootstrapFailureCategoryConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "repo", got: BootstrapFailureCategoryRepo, want: "repo"},
		{name: "auth", got: BootstrapFailureCategoryAuth, want: "auth"},
		{name: "dependency", got: BootstrapFailureCategoryDependency, want: "dependency"},
		{name: "engine_setup", got: BootstrapFailureCategoryEngineSetup, want: "engine_setup"},
		{name: "unknown", got: BootstrapFailureCategoryUnknown, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("category = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestClassifyBootstrapFailure(t *testing.T) {
	tests := []struct {
		name           string
		step           string
		command        string
		output         string
		err            error
		wantCategory   string
		wantMessage    string
		forbiddenParts []string
	}{
		{
			name:         "git clone repo failure",
			step:         "clone",
			command:      "git clone git@github.com:jywlabs/hal.git /workspace/hal",
			output:       "fatal: remote error: repository unavailable",
			err:          errors.New("exit status 128"),
			wantCategory: BootstrapFailureCategoryRepo,
			wantMessage:  "repository bootstrap failed while running git clone",
		},
		{
			name:         "git fetch repo failure",
			step:         "fetch",
			command:      "git fetch origin main",
			output:       "fatal: couldn't find remote ref main",
			err:          errors.New("exit status 128"),
			wantCategory: BootstrapFailureCategoryRepo,
			wantMessage:  "repository bootstrap failed while running git fetch",
		},
		{
			name:         "authentication failure",
			step:         "clone",
			command:      "git clone https://ghp_super_secret@github.com/jywlabs/hal.git /workspace/hal",
			output:       "remote: invalid username or password\nfatal: Authentication failed for 'https://ghp_super_secret@github.com/jywlabs/hal.git/'",
			err:          errors.New("exit status 128"),
			wantCategory: BootstrapFailureCategoryAuth,
			wantMessage:  "authentication failed while running git clone",
			forbiddenParts: []string{
				"ghp_super_secret",
				"invalid username or password",
			},
		},
		{
			name:         "missing cli dependency",
			step:         "verify_engine",
			command:      "codex --version",
			err:          &exec.Error{Name: "codex", Err: exec.ErrNotFound},
			wantCategory: BootstrapFailureCategoryDependency,
			wantMessage:  "required bootstrap command not found: codex",
		},
		{
			name:         "hal setup failure",
			step:         "hal_setup",
			command:      "hal init",
			output:       "failed to refresh templates",
			err:          errors.New("exit status 1"),
			wantCategory: BootstrapFailureCategoryEngineSetup,
			wantMessage:  "Hal or engine setup failed while running hal init",
		},
		{
			name:         "unknown command failure",
			step:         "custom",
			command:      "make bootstrap",
			output:       "unexpected process failure",
			err:          errors.New("exit status 2"),
			wantCategory: BootstrapFailureCategoryUnknown,
			wantMessage:  "bootstrap command failed while running make",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := ClassifyBootstrapFailure(tt.step, tt.command, tt.output, tt.err)
			if failure.Step != tt.step {
				t.Fatalf("failure step = %q, want %q", failure.Step, tt.step)
			}
			if failure.Category != tt.wantCategory {
				t.Fatalf("failure category = %q, want %q", failure.Category, tt.wantCategory)
			}
			if failure.Message != tt.wantMessage {
				t.Fatalf("failure message = %q, want %q", failure.Message, tt.wantMessage)
			}
			if strings.TrimSpace(failure.Message) == "" {
				t.Fatal("failure message should not be empty")
			}
			for _, part := range tt.forbiddenParts {
				if strings.Contains(failure.Message, part) {
					t.Fatalf("failure message %q should not contain %q", failure.Message, part)
				}
			}
		})
	}
}
