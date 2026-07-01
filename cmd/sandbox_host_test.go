package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestSandboxHostCommandScaffoldRegistered(t *testing.T) {
	host, err := commandAtPath(Root(), "sandbox", "host")
	if err != nil {
		t.Fatalf("sandbox host command missing: %v", err)
	}
	if missing := missingCommandMetadataFields(host); len(missing) > 0 {
		t.Fatalf("sandbox host missing metadata fields: %v", missing)
	}

	for _, path := range [][]string{
		{"sandbox", "host", "register"},
		{"sandbox", "host", "register", "worker"},
		{"sandbox", "host", "list"},
		{"sandbox", "host", "status"},
		{"sandbox", "host", "delete"},
	} {
		cmd, err := commandAtPath(Root(), path...)
		if err != nil {
			t.Fatalf("command path %q missing: %v", strings.Join(path, " "), err)
		}
		if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
			t.Fatalf("command %q missing metadata fields: %v", strings.Join(path, " "), missing)
		}
	}

	if _, err := commandAtPath(Root(), "sandboxd"); err != nil {
		t.Fatalf("sandboxd command missing or moved: %v", err)
	}
	if sandbox, err := commandAtPath(Root(), "sandbox"); err != nil {
		t.Fatalf("sandbox command missing: %v", err)
	} else if child := findDirectSubcommandByName(sandbox, "sandboxd"); child != nil {
		t.Fatal("sandboxd should remain a top-level command, not a hal sandbox subcommand")
	}

	for _, subcommand := range []string{"setup", "auth", "create", "start", "stop", "status", "delete", "ssh", "host"} {
		if _, err := commandAtPath(Root(), "sandbox", subcommand); err != nil {
			t.Fatalf("sandbox subcommand %q disrupted: %v", subcommand, err)
		}
	}
}

func TestSandboxHostHelpListsScaffoldSubcommands(t *testing.T) {
	cmd := newSandboxHostCommand(sandboxHostDeps{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandbox host --help error: %v", err)
	}

	help := stdout.String()
	for _, want := range []string{"register", "list", "status", "delete"} {
		if !strings.Contains(help, want) {
			t.Fatalf("sandbox host help = %q, want subcommand %q", help, want)
		}
	}
}
