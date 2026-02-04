# Tech Stack

## Language

- **Go 1.22+** — Primary language for CLI development
- Enables single binary distribution with no runtime dependencies

## CLI Framework

- **[Cobra](https://github.com/spf13/cobra)** — Industry-standard Go CLI framework
- Subcommands, flags, help generation, shell completion

## Configuration

- **[gopkg.in/yaml.v3](https://pkg.go.dev/gopkg.in/yaml.v3)** — YAML parsing for `.hal/config.yaml`
- Struct tags for clean serialization/deserialization

## Git Integration

- **[go-git](https://github.com/go-git/go-git)** — Pure Go git implementation
- Worktree management, branch operations, commit creation
- No dependency on system git binary

## GitHub API

- **[go-github](https://github.com/google/go-github)** — GitHub REST API client
- Issue fetching, PR creation, label filtering

## Terminal UI (Optional)

- **[Bubble Tea](https://github.com/charmbracelet/bubbletea)** — TUI framework for interactive components
- **[Lip Gloss](https://github.com/charmbracelet/lipgloss)** — Terminal styling
- **[Bubbles](https://github.com/charmbracelet/bubbles)** — Pre-built components (spinners, progress bars)

## HTTP Client

- **net/http** — Standard library HTTP client for webhook notifications
- No external dependencies needed

## Process Execution

- **os/exec** — Standard library for spawning engine CLI processes
- Cross-platform support (Windows cmd.exe handling)

## Build & Distribution

- **[GoReleaser](https://goreleaser.com/)** — Automated cross-platform builds
- Targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64

## Testing

- **testing** — Standard library test framework
- **[testify](https://github.com/stretchr/testify)** — Assertions and mocking (optional)

## Development

- **[golangci-lint](https://golangci-lint.run/)** — Linter aggregator
- **[gofumpt](https://github.com/mvdan/gofumpt)** — Stricter gofmt
