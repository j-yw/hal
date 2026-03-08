package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	halcmd "github.com/jywlabs/hal/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const (
	defaultOutDir  = "./docs/cli"
	formatMarkdown = "markdown"
	formatMan      = "man"
	formatReST     = "rest"
)

type options struct {
	outDir      string
	format      string
	frontmatter bool
}

func main() {
	if err := run(os.Args[1:], halcmd.Root()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, root *cobra.Command) error {
	if root == nil {
		return fmt.Errorf("root command must not be nil")
	}

	opts, err := parseFlags(args, io.Discard)
	if err != nil {
		return err
	}

	if opts.frontmatter && opts.format != formatMarkdown {
		return fmt.Errorf("-frontmatter is only supported with -format=%s", formatMarkdown)
	}

	if err := os.MkdirAll(opts.outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %q: %w", opts.outDir, err)
	}

	root.DisableAutoGenTag = true

	switch opts.format {
	case formatMarkdown:
		return generateMarkdown(root, opts.outDir, opts.frontmatter)
	case formatMan:
		return generateMan(root, opts.outDir)
	case formatReST:
		return generateReST(root, opts.outDir)
	default:
		return fmt.Errorf("invalid -format %q (expected markdown|man|rest)", opts.format)
	}
}

func parseFlags(args []string, output io.Writer) (options, error) {
	opts := options{
		outDir: defaultOutDir,
		format: formatMarkdown,
	}

	fs := flag.NewFlagSet("docgen", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&opts.outDir, "out", opts.outDir, "output directory for generated docs")
	fs.StringVar(&opts.format, "format", opts.format, "output format: markdown|man|rest")
	fs.BoolVar(&opts.frontmatter, "frontmatter", false, "prepend frontmatter to markdown output")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	switch opts.format {
	case formatMarkdown, formatMan, formatReST:
		return opts, nil
	default:
		return options{}, fmt.Errorf("invalid -format %q (expected markdown|man|rest)", opts.format)
	}
}

func generateMarkdown(root *cobra.Command, outDir string, includeFrontmatter bool) error {
	if includeFrontmatter {
		filePrepender := func(filename string) string {
			slug := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
			title := strings.ReplaceAll(slug, "_", " ")
			return fmt.Sprintf("---\ntitle: %q\nslug: %q\n---\n\n", title, slug)
		}
		linkHandler := func(link string) string {
			return link
		}
		if err := doc.GenMarkdownTreeCustom(root, outDir, filePrepender, linkHandler); err != nil {
			return fmt.Errorf("failed to generate markdown docs: %w", err)
		}
		return nil
	}

	if err := doc.GenMarkdownTree(root, outDir); err != nil {
		return fmt.Errorf("failed to generate markdown docs: %w", err)
	}

	return nil
}

func generateMan(root *cobra.Command, outDir string) error {
	header := &doc.GenManHeader{
		Title:   "HAL",
		Section: "1",
	}
	if err := doc.GenManTree(root, header, outDir); err != nil {
		return fmt.Errorf("failed to generate man docs: %w", err)
	}
	return nil
}

func generateReST(root *cobra.Command, outDir string) error {
	if err := doc.GenReSTTree(root, outDir); err != nil {
		return fmt.Errorf("failed to generate ReST docs: %w", err)
	}
	return nil
}
