package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information - set via ldflags at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version info",
	Long:  `Show Hal version, commit hash, and build information.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("hal %s\n", Version)
		fmt.Printf("  commit:  %s\n", Commit)
		fmt.Printf("  built:   %s\n", BuildDate)
		fmt.Printf("  go:      %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println()
		fmt.Println("  \"I'm completely operational, and all my circuits are functioning perfectly.\"")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
