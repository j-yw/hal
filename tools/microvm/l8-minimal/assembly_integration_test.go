//go:build linux && microvm_assets_integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Real local Git selects each fixture's immutable source tree. Podman is a
// deliberate fake that never executes a recipe or emits measured build proof.
func TestMinimalNativeAssemblerRequiresCommittedOfflineInputs(t *testing.T) {
	entry, err := filepath.Abs("assemble.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("actual native assembler entrypoint is absent: %v", err)
	}
	for _, scenario := range []string{"valid_runner_failure", "missing_native", "altered_native", "extra_native", "native_symlink", "missing_lock", "duplicate_native_record", "unknown_native_field", "native_traversal", "modified_lock", "replaced_tree", "wrong_revision", "caller_tree", "caller_receipt", "fake_success_no_output"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			repo, cache, native, bin := filepath.Join(root, "repo"), filepath.Join(root, "cache"), filepath.Join(root, "native"), filepath.Join(root, "bin")
			for _, dir := range []string{repo, cache, native, bin} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name string, data []byte, mode fs.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			// Copy tracked source plus the evolving owned assembler files. Commit
			// this test fixture explicitly; it is not an upstream source receipt.
			sourceRoot, err := filepath.Abs("../../..")
			if err != nil {
				t.Fatal(err)
			}
			git := func(args ...string) string {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, "git", args...)
				command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_PARAMETERS='commit.gpgsign=false'", "GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid"}
				data, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("local Git %v failed: %v %s", args, err, data)
				}
				return strings.TrimSpace(string(data))
			}
			tracked := git("-C", sourceRoot, "ls-files", "-z")
			for _, name := range strings.Split(tracked, "\x00") {
				if name == "" {
					continue
				}
				data, err := os.ReadFile(filepath.Join(sourceRoot, name))
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(filepath.Join(sourceRoot, name))
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(repo, name), data, info.Mode().Perm())
			}
			if err := filepath.WalkDir(".", func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.IsDir() {
					return nil
				}
				if strings.HasSuffix(path, "_test.go") {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				write(filepath.Join(repo, "tools/microvm/l8-minimal", path), data, info.Mode().Perm())
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, lane := range []string{"l5", "l8"} {
				manifest := filepath.Join(repo, "tools/microvm", lane, "cache.manifest")
				data, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				var records []string
				for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
					fields := strings.Fields(line)
					if len(fields) != 3 {
						t.Fatal("invalid fixture manifest")
					}
					body := []byte("synthetic offline source: " + fields[2] + "\n")
					sum := sha256.Sum256(body)
					write(filepath.Join(cache, fields[2]), body, 0600)
					records = append(records, fmt.Sprintf("%x\t%d\t%s", sum, len(body), fields[2]))
				}
				sort.Strings(records)
				write(manifest, []byte(strings.Join(records, "\n")+"\n"), 0600)
			}
			lockPath := filepath.Join(repo, "tools/microvm/l8-minimal/native-sources.lock.json")
			lockBytes, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			var lock map[string]any
			if err := json.Unmarshal(lockBytes, &lock); err != nil {
				t.Fatal(err)
			}
			buildroot := sha256.Sum256([]byte("synthetic offline source: buildroot-2026.05.1.tar.xz\n"))
			lock["buildroot"].(map[string]any)["archiveSHA256"] = hex.EncodeToString(buildroot[:])
			var first string
			for _, raw := range lock["records"].([]any) {
				record := raw.(map[string]any)
				name := record["name"].(string)
				if first == "" {
					first = name
				}
				body := []byte("synthetic native source: " + name + "\n")
				sum := sha256.Sum256(body)
				record["size"], record["sha256"] = len(body), hex.EncodeToString(sum[:])
				if record["upstreamAlgorithm"] == "sha512" {
					upstream := sha512.Sum512(body)
					record["upstreamDigest"] = hex.EncodeToString(upstream[:])
				} else {
					record["upstreamDigest"] = hex.EncodeToString(sum[:])
				}
				write(filepath.Join(native, name), body, 0600)
			}
			switch scenario {
			case "duplicate_native_record":
				records := lock["records"].([]any)
				lock["records"] = append(records, records[0])
			case "unknown_native_field":
				lock["callerVerified"] = true
			case "native_traversal":
				lock["records"].([]any)[0].(map[string]any)["name"] = "../foreign.tar.gz"
			}
			lockBytes, err = json.MarshalIndent(lock, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			write(lockPath, append(lockBytes, '\n'), 0600)
			if scenario == "missing_lock" {
				if err := os.Remove(lockPath); err != nil {
					t.Fatal(err)
				}
			}
			git("-C", repo, "init", "-q")
			git("-C", repo, "add", ".")
			git("-C", repo, "commit", "-qm", "fixture selected source")
			revision := git("-C", repo, "rev-parse", "HEAD")
			output, runLog := filepath.Join(root, "output"), filepath.Join(root, "runtime-run")
			args := []string{entry, "--source-repo", repo, "--source-revision", revision, "--cache", cache, "--native-cache", native, "--output", output, "--runtime", "podman"}
			switch scenario {
			case "missing_native":
				if err := os.Remove(filepath.Join(native, first)); err != nil {
					t.Fatal(err)
				}
			case "altered_native":
				write(filepath.Join(native, first), []byte("substituted bytes"), 0600)
			case "extra_native":
				write(filepath.Join(native, "extra.tar.gz"), []byte("extra"), 0600)
			case "native_symlink":
				if err := os.Rename(filepath.Join(native, first), filepath.Join(root, first)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, first), filepath.Join(native, first)); err != nil {
					t.Fatal(err)
				}
			case "modified_lock", "replaced_tree":
				write(lockPath, []byte("{}\n"), 0600)
				if scenario == "replaced_tree" {
					git("-C", repo, "add", ".")
					git("-C", repo, "commit", "-qm", "replacement tree")
				}
			case "wrong_revision":
				args[4] = strings.Repeat("0", 40)
			case "caller_tree":
				args = append(args, "--source-tree", "tree-"+strings.Repeat("a", 40))
			case "caller_receipt":
				forgery := filepath.Join(root, "receipt.json")
				write(forgery, []byte(`{"SourceRevision":"`+revision+`","SourceTree":"tree-`+strings.Repeat("a", 40)+`","NativeLockSHA256":"`+strings.Repeat("b", 64)+`"}`), 0600)
				args = append(args, "--receipt", forgery)
			}
			runExit := "74"
			if scenario == "fake_success_no_output" {
				runExit = "0"
			}
			write(filepath.Join(bin, "podman"), []byte(`#!/bin/sh
if [ "$1" = --remote=false ]; then shift; fi
case "$1" in
info) printf 'true\n' ;;
image) printf 'registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6\n' ;;
run)
 printf '%s\n' "$@" > '`+runLog+`'
 cidfile= label=
 for arg do
  case "$arg" in --cidfile=*) cidfile=${arg#--cidfile=} ;; --label=hal.microvm.build=*) label=${arg#--label=hal.microvm.build=} ;; esac
 done
 [ -n "$cidfile" ] && [ -n "$label" ] || exit 94
 cid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 printf '%s\n' "$cid" > "$cidfile"
 printf '%s %s\n' "$cid" "$label" > '`+filepath.Join(root, "runtime-state")+`'
 # No recipe is run. Even a zero exit below cannot mint assembly evidence.
 [ '`+runExit+`' != 0 ] || printf '{"SourceRevision":"`+revision+`","SourceTree":"tree-`+strings.Repeat("a", 40)+`","NativeLockSHA256":"`+strings.Repeat("b", 64)+`"}\n'
 exit `+runExit+` ;;
container)
 case "$2" in
 exists) test -f '`+filepath.Join(root, "runtime-state")+`' ;;
 inspect) cat '`+filepath.Join(root, "runtime-state")+`' ;;
 *) exit 93 ;;
 esac ;;
rm) rm -- '`+filepath.Join(root, "runtime-state")+`' ;;
*) exit 92 ;;
esac
`), 0700)
			for _, forbidden := range []string{"curl", "wget", "npm", "docker"} {
				write(filepath.Join(bin, forbidden), []byte("#!/bin/sh\nprintf forbidden > '"+filepath.Join(root, "forbidden")+"'\nexit 99\n"), 0700)
			}
			goPath, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/bash", args...)
			command.Env = []string{"PATH=" + bin + ":" + filepath.Dir(goPath) + ":/usr/bin:/bin", "HOME=" + root, "GOCACHE=" + filepath.Join(root, "gocache"), "GOMAXPROCS=3", "GOPROXY=off", "GOSUMDB=off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "UNRELATED_SECRET=fixture-must-not-reach-build"}
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err = command.Run()
			if err == nil || stdout.Len() != 0 {
				t.Fatalf("unmeasured invocation issued success/receipt: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("unmeasured output published: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "forbidden")); !os.IsNotExist(err) {
				t.Fatal("offline route invoked forbidden acquisition/runtime fallback")
			}
			called, readErr := os.ReadFile(runLog)
			if scenario == "valid_runner_failure" || scenario == "fake_success_no_output" {
				if readErr != nil {
					t.Fatalf("valid selected fixture never reached bounded offline runner: %v stderr=%s", readErr, stderr.String())
				}
				for _, want := range []string{"--network=none", "--pull=never", "--userns=keep-id", "BR2_PRIMARY_SITE=file:///nonexistent", "BR2_PRIMARY_SITE_ONLY=y"} {
					if !strings.Contains(string(called), want) {
						t.Fatalf("missing offline runner argument %s: %s", want, called)
					}
				}
				if strings.Contains(string(called), "fixture-must-not-reach-build") {
					t.Fatal("host environment leaked to build")
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("invalid source/cache/authority reached runner: %s (%v)", called, readErr)
			}
		})
	}
}
