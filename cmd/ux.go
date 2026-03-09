package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	deprecationIntroducedVersion = "v0.2.0"
	deprecationRemovalVersion    = "v1.0.0"
)

func noArgsValidation() cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("accepts 0 arg(s), received %d", len(args)))
	}
}

func maxArgsValidation(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) <= n {
			return nil
		}
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("accepts at most %d arg(s), received %d", n, len(args)))
	}
}

func exactArgsValidation(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == n {
			return nil
		}
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("accepts %d arg(s), received %d", n, len(args)))
	}
}

func minArgsValidation(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) >= n {
			return nil
		}
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("requires at least %d arg(s), only received %d", n, len(args)))
	}
}

func runParentCommand(cmd *cobra.Command, args []string, runDefault func() error) error {
	if len(args) == 0 {
		return runDefault()
	}
	if cmd == nil {
		return fmt.Errorf("unknown command %q", args[0])
	}

	if args[0] == "help" {
		if len(args) == 1 {
			return cmd.Help()
		}

		target, _, err := cmd.Find(args[1:])
		if err != nil || target == nil || target == cmd {
			return unknownSubcommandError(cmd, args[1])
		}
		return target.Help()
	}

	return unknownSubcommandError(cmd, args[0])
}

func unknownSubcommandError(cmd *cobra.Command, subcommand string) error {
	return fmt.Errorf("unknown command %q for %q", subcommand, cmd.CommandPath())
}

func resolveEngine(cmd *cobra.Command, flagName, fallbackFlagValue, dir string) (string, error) {
	normalize := func(v string) string {
		return strings.ToLower(strings.TrimSpace(v))
	}

	loadDefault := func() (string, error) {
		engineName, err := compound.LoadDefaultEngine(dir)
		if err != nil {
			return "", fmt.Errorf("failed to load default engine: %w", err)
		}
		engineName = normalize(engineName)
		if engineName == "" {
			return "codex", nil
		}
		return engineName, nil
	}

	if cmd == nil {
		engineName := normalize(fallbackFlagValue)
		if engineName != "" {
			return engineName, nil
		}
		return loadDefault()
	}

	flags := cmd.Flags()
	if flags == nil || flags.Lookup(flagName) == nil {
		engineName := normalize(fallbackFlagValue)
		if engineName != "" {
			return engineName, nil
		}
		return loadDefault()
	}

	value, err := flags.GetString(flagName)
	if err != nil {
		return "", err
	}

	if flags.Changed(flagName) {
		engineName := normalize(value)
		if engineName == "" {
			return "", fmt.Errorf("--%s must not be empty", flagName)
		}
		return engineName, nil
	}

	return loadDefault()
}

func parseIterations(positional []string, flagValue int, flagChanged bool, defaultValue int) (int, error) {
	if len(positional) > 1 {
		return 0, fmt.Errorf("expected at most one iterations argument")
	}
	if len(positional) > 0 && flagChanged {
		return 0, fmt.Errorf("iterations provided both positionally and via --iterations")
	}

	iterations := defaultValue
	if len(positional) > 0 {
		parsed, err := strconv.Atoi(positional[0])
		if err != nil {
			return 0, fmt.Errorf("invalid iterations: %q (must be a number)", positional[0])
		}
		iterations = parsed
	} else if flagChanged {
		iterations = flagValue
	}

	if iterations <= 0 {
		return 0, fmt.Errorf("iterations must be a positive integer")
	}

	return iterations, nil
}

func validateFormat(value string, allowed ...string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		return "", fmt.Errorf("format must not be empty")
	}

	for _, candidate := range allowed {
		if format == strings.ToLower(strings.TrimSpace(candidate)) {
			return format, nil
		}
	}

	return "", fmt.Errorf("invalid format %q (allowed: %s)", format, strings.Join(allowed, ", "))
}

func isTTY(r io.Reader) bool {
	file, ok := r.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func isNonInteractive(r io.Reader) bool {
	return !isTTY(r)
}

func warnDeprecated(w io.Writer, msg string) {
	if w == nil {
		return
	}
	message := strings.TrimSpace(msg)
	if message == "" {
		return
	}
	fmt.Fprintf(w, "warning: %s (deprecated in %s; will be removed in %s)\n", message, deprecationIntroducedVersion, deprecationRemovalVersion)
}

func exitWithCode(cmd *cobra.Command, code int, err error) error {
	if cmd != nil {
		if root := cmd.Root(); root != nil {
			root.SilenceUsage = true
			root.SilenceErrors = true
		} else {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
		}
	}

	return &ExitCodeError{Code: code, Err: err}
}
