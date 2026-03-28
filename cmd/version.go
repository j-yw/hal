package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

// Version information - set via ldflags at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var versionJSONFlag bool

// VersionInfo is the machine-readable version output.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	Go        string `json:"go"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Show version info",
	Args:    noArgsValidation(),
	Long:    `Show Hal version, commit hash, and build information.`,
	Example: `  hal version
  hal version --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := io.Writer(os.Stdout)
		if cmd != nil {
			out = cmd.OutOrStdout()
		}

		if versionJSONFlag {
			info := VersionInfo{
				Version:   Version,
				Commit:    Commit,
				BuildDate: BuildDate,
				Go:        runtime.Version(),
				OS:        runtime.GOOS,
				Arch:      runtime.GOARCH,
			}
			data, err := json.MarshalIndent(info, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal version: %w", err)
			}
			fmt.Fprintln(out, string(data))
			return nil
		}

		fmt.Fprintf(out, "%s %s\n", display.StyleTitle.Render("hal"), display.StyleBold.Render(Version))
		fmt.Fprintf(out, "  commit:  %s\n", display.StyleMuted.Render(Commit))
		fmt.Fprintf(out, "  built:   %s\n", display.StyleMuted.Render(BuildDate))
		fmt.Fprintf(out, "  go:      %s\n", display.StyleMuted.Render(runtime.Version()))
		fmt.Fprintf(out, "  os/arch: %s\n", display.StyleMuted.Render(runtime.GOOS+"/"+runtime.GOARCH))
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  %s\n", display.StyleAccent.Render("\"I'm completely operational, and all my circuits are functioning perfectly.\""))
		return nil
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionJSONFlag, "json", false, "Output as JSON")
	rootCmd.AddCommand(versionCmd)
}
