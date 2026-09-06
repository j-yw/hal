//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type selectedSource struct {
	revision, tree string
	epoch          int64
	root           *directory
	metadata       map[string][]byte
}

func gitCommand(ctx context.Context, repo string, args ...string) *exec.Cmd {
	flags := []string{"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null", "-C", repo}
	cmd := exec.CommandContext(ctx, "git", append(flags, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"}
	cmd.WaitDelay = 2 * time.Second
	return cmd
}
func checkCheckout(ctx context.Context, repo, revision string) error {
	for _, query := range [][]string{{"rev-parse", "HEAD"}, {"status", "--porcelain", "--untracked-files=all"}} {
		cmd := gitCommand(ctx, repo, query...)
		var out boundedBuffer
		out.limit = 4 << 20
		cmd.Stdout = &out
		cmd.Stderr = io.Discard
		if cmd.Run() != nil {
			return errInput
		}
		if query[0] == "rev-parse" {
			if strings.TrimSpace(out.String()) != revision {
				return errInput
			}
		} else if out.Len() != 0 {
			return errInput
		}
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errInput
	}
	return b.Buffer.Write(p)
}

// Read raw Git objects and verify their object IDs. git archive is deliberately
// not used: export-ignore/export-subst attributes can alter the selected tree.
func snapshotSource(ctx context.Context, repo, revision string, stage *directory) (result selectedSource, retErr error) {
	if !gitPattern.MatchString(revision) || revision == strings.Repeat("0", 40) {
		return result, errInput
	}
	repoFD, err := openDirectory(repo, false)
	if err != nil {
		return result, err
	}
	defer repoFD.close()
	destination := stage.name
	root, err := os.OpenRoot(destination)
	if err != nil {
		return result, errInput
	}
	defer root.Close()
	rootFile, err := root.Open(".")
	if err != nil {
		return result, errInput
	}
	rootInfo, err := rootFile.Stat()
	_ = rootFile.Close()
	stageInfo, stageErr := stage.file.Stat()
	if err != nil || stageErr != nil || !os.SameFile(rootInfo, stageInfo) || stage.current() != nil {
		return result, errInput
	}
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if checkCheckout(bounded, repo, revision) != nil {
		return result, errInput
	}
	cmd := gitCommand(bounded, repo, "cat-file", "--batch")
	input, err := cmd.StdinPipe()
	if err != nil {
		return result, errInput
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return result, errInput
	}
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		return result, errInput
	}
	defer func() { _ = input.Close(); cancel(); _ = cmd.Wait() }()
	reader := bufio.NewReaderSize(output, 4096)
	object := func(id, kind string, max int64) ([]byte, error) {
		if !gitPattern.MatchString(id) {
			return nil, errInput
		}
		if _, err := fmt.Fprintln(input, id); err != nil {
			return nil, errInput
		}
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > 256 {
			return nil, errInput
		}
		fields := strings.Fields(string(line))
		if len(fields) != 3 || fields[0] != id || fields[1] != kind {
			return nil, errInput
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > max {
			return nil, errInput
		}
		body := make([]byte, int(size))
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, errInput
		}
		end, err := reader.ReadByte()
		if err != nil || end != '\n' {
			return nil, errInput
		}
		hash := sha1.New()
		fmt.Fprintf(hash, "%s %d\x00", kind, size)
		_, _ = hash.Write(body)
		if hex.EncodeToString(hash.Sum(nil)) != id {
			return nil, errInput
		}
		return body, nil
	}
	commit, err := object(revision, "commit", 4<<20)
	if err != nil {
		return result, err
	}
	header := strings.SplitN(string(commit), "\n\n", 2)[0]
	tree := ""
	var epoch int64
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(line, "tree ") {
			if tree != "" {
				return result, errInput
			}
			tree = strings.TrimPrefix(line, "tree ")
		}
		if strings.HasPrefix(line, "committer ") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				return result, errInput
			}
			epoch, err = strconv.ParseInt(fields[len(fields)-2], 10, 64)
			if err != nil {
				return result, errInput
			}
		}
	}
	if !gitPattern.MatchString(tree) || epoch <= 0 || epoch > 2147483647 {
		return result, errInput
	}
	var total int64
	count := 0
	metadata := map[string][]byte{}
	var copyTree func(string, string, int) error
	copyTree = func(id, prefix string, depth int) error {
		if depth > 64 {
			return errInput
		}
		body, err := object(id, "tree", 4<<20)
		if err != nil {
			return err
		}
		for len(body) > 0 {
			split := bytes.IndexByte(body, 0)
			if split < 0 || len(body) < split+21 {
				return errInput
			}
			fields := strings.SplitN(string(body[:split]), " ", 2)
			if len(fields) != 2 {
				return errInput
			}
			mode, name := fields[0], fields[1]
			if name == "" || name == "." || name == ".." || name == ".git" || strings.ContainsAny(name, "/\\\x00\r\n") {
				return errInput
			}
			child := hex.EncodeToString(body[split+1 : split+21])
			body = body[split+21:]
			relative := filepath.Join(prefix, name)
			count++
			if count > 20000 {
				return errInput
			}
			switch mode {
			case "40000":
				if root.Mkdir(relative, 0755) != nil {
					return errInput
				}
				if copyTree(child, relative, depth+1) != nil {
					return errInput
				}
			case "100644", "100755":
				data, err := object(child, "blob", 32<<20)
				if err != nil {
					return err
				}
				switch filepath.ToSlash(relative) {
				case "tools/microvm/l5/cache.manifest", "tools/microvm/l8/cache.manifest", "tools/microvm/l8-minimal/native-sources.lock.json":
					if len(data) > 4<<20 {
						return errInput
					}
					metadata[filepath.ToSlash(relative)] = data
				}
				total += int64(len(data))
				if total > 128<<20 {
					return errInput
				}
				permissions := os.FileMode(0644)
				if mode == "100755" {
					permissions = 0755
				}
				file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permissions)
				if err != nil {
					return errInput
				}
				_, writeErr := file.Write(data)
				syncErr := file.Sync()
				closeErr := file.Close()
				if writeErr != nil || syncErr != nil || closeErr != nil {
					return errInput
				}
			case "120000":
				data, err := object(child, "blob", 4096)
				if err != nil {
					return errInput
				}
				link := string(data)
				resolved := filepath.Clean(filepath.Join(filepath.Dir(relative), link))
				if link == "" || filepath.IsAbs(link) || strings.ContainsAny(link, "\\\x00\r\n") || resolved == ".." || strings.HasPrefix(resolved, "../") {
					return errInput
				}
				if root.Symlink(link, relative) != nil {
					return errInput
				}
			default:
				return errInput // No submodules or special files.
			}
		}
		return nil
	}
	if copyTree(tree, "", 0) != nil || repoFD.current() != nil || stage.current() != nil || checkCheckout(bounded, repo, revision) != nil {
		return result, errInput
	}
	return selectedSource{revision: revision, tree: "tree-" + tree, epoch: epoch, root: stage, metadata: metadata}, nil
}
