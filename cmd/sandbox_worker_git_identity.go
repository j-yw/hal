package cmd

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const sandboxWorkerGitIdentityMaxBytes = 1024

// prepareSandboxWorkerGitIdentity is called only for an explicitly selected
// worker-rootless final command. Git's author/committer variables are scoped to
// that execution, including descendants and retries, without changing a reused
// container's Git config. These public commit identities are not credentials.
func prepareSandboxWorkerGitIdentity(projectDir string, target sandboxruntime.Target, command *sandboxexec.CommandRequest) error {
	if strings.TrimSpace(target.Runtime.Driver) != sandboxruntime.DriverRootlessPodman {
		return nil
	}
	config, err := compound.LoadSandboxConfig(projectDir)
	if err != nil {
		return sandboxWorkerGitIdentityConfigError{cause: err}
	}
	env, err := sandboxWorkerGitIdentityEnv(config.Env, command.Env)
	if err != nil {
		return err
	}
	command.Env = env
	return nil
}

// The project config loader does not expand host environment variables. Only
// these two explicit keys may contribute identity; other sandbox.env values
// continue to use their existing delivery contracts, if any.
func sandboxWorkerGitIdentityEnv(config, existing map[string]string) (map[string]string, error) {
	name, hasName := config["GIT_USER_NAME"]
	email, hasEmail := config["GIT_USER_EMAIL"]
	if !hasName && !hasEmail {
		return existing, nil
	}
	if !hasName || !hasEmail || !validSandboxWorkerGitIdentityValue(name, false) || !validSandboxWorkerGitIdentityValue(email, true) {
		return nil, errors.New("sandbox Git identity requires valid GIT_USER_NAME and GIT_USER_EMAIL in sandbox.env")
	}
	identity := map[string]string{
		"GIT_AUTHOR_NAME": name, "GIT_COMMITTER_NAME": name,
		"GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_EMAIL": email,
	}
	for key, value := range identity {
		if current, ok := existing[key]; ok && current != value {
			return nil, errors.New("sandbox Git identity conflicts with an explicit command environment value")
		}
	}
	merged := make(map[string]string, len(existing)+len(identity))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range identity {
		merged[key] = value
	}
	return merged, nil
}

func validSandboxWorkerGitIdentityValue(value string, email bool) bool {
	if len(value) > sandboxWorkerGitIdentityMaxBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) == "" || strings.ContainsAny(value, "<>") {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) || (email && unicode.IsSpace(char)) {
			return false
		}
	}
	return true
}

// Config parse/read errors can contain raw values or host paths. Retain the
// cause for errors.Is/As without adding it to user-visible or durable context.
type sandboxWorkerGitIdentityConfigError struct{ cause error }

func (sandboxWorkerGitIdentityConfigError) Error() string {
	return "sandbox Git identity configuration is unavailable"
}

func (err sandboxWorkerGitIdentityConfigError) Unwrap() error { return err.cause }
