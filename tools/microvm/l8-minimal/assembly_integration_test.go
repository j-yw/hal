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
	"syscall"
	"testing"
	"time"
)

// Real local Git selects each fixture's immutable source tree. Podman is a
// deliberate fake that never executes a recipe or emits measured build proof.
func TestMinimalNativeAssemblerRequiresCommittedOfflineInputs(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	cacheData, err := exec.Command(goPath, "env", "GOMODCACHE", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	compilerCaches := strings.Split(strings.TrimSpace(string(cacheData)), "\n")
	if len(compilerCaches) != 2 {
		t.Fatal("missing offline host compiler caches")
	}
	entry, err := filepath.Abs("assemble.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("actual native assembler entrypoint is absent: %v", err)
	}
	for _, scenario := range []string{"valid_runner_failure", "missing_native", "altered_native", "extra_native", "native_symlink", "missing_lock", "duplicate_native_record", "unknown_native_field", "native_traversal", "modified_lock", "replaced_tree", "wrong_revision", "caller_tree", "caller_receipt", "fake_success_no_output", "signal_entrypoint", "simulated_timeout"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
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
				info, err := os.Lstat(filepath.Join(sourceRoot, name))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					link, err := os.Readlink(filepath.Join(sourceRoot, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(link, filepath.Join(repo, name)); err != nil {
						t.Fatal(err)
					}
					continue
				}
				data, err := os.ReadFile(filepath.Join(sourceRoot, name))
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
			if scenario == "fake_success_no_output" || scenario == "simulated_timeout" {
				runExit = "0"
			}
			// Capture the actual runner's outer budget. Only the timeout case
			// substitutes status 124, after the fake runtime has created its
			// exact owned CID. No wall-clock multi-hour wait is performed.
			write(filepath.Join(bin, "timeout"), []byte(`#!/bin/sh
if [ "${6-}" = run ]; then
 printf '%s\n' "$1" "$2" "$3" > '`+filepath.Join(root, "outer-budget")+`'
 if [ '`+scenario+`' = simulated_timeout ]; then
  /usr/bin/timeout "$@" || exit 98
  printf '124\n' > '`+filepath.Join(root, "timeout-status")+`'
  exit 124
 fi
fi
exec /usr/bin/timeout "$@"
`), 0700)
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
 if [ '`+scenario+`' = signal_entrypoint ]; then
  trap 'exit 143' TERM INT
  while :; do sleep 0.1; done
 fi
 # No recipe is run. Even a zero exit below cannot mint assembly evidence.
 [ '`+runExit+`' != 0 ] || printf '{"SourceRevision":"`+revision+`","SourceTree":"tree-`+strings.Repeat("a", 40)+`","NativeLockSHA256":"`+strings.Repeat("b", 64)+`"}\n'
 exit `+runExit+` ;;
container)
 case "$2" in
 exists) test -f '`+filepath.Join(root, "runtime-state")+`' ;;
 inspect) cat '`+filepath.Join(root, "runtime-state")+`' ;;
 *) exit 93 ;;
 esac ;;
rm)
 printf '%s\n' "$@" > '`+filepath.Join(root, "cleanup-args")+`'
 rm -- '`+filepath.Join(root, "runtime-state")+`' ;;
*) exit 92 ;;
esac
`), 0700)
			for _, forbidden := range []string{"curl", "wget", "npm", "docker"} {
				write(filepath.Join(bin, forbidden), []byte("#!/bin/sh\nprintf forbidden > '"+filepath.Join(root, "forbidden")+"'\nexit 99\n"), 0700)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/bash", args...)
			command.Env = []string{"PATH=" + bin + ":" + filepath.Dir(goPath) + ":/usr/bin:/bin", "HOME=" + root, "GOCACHE=" + compilerCaches[1], "GOMODCACHE=" + compilerCaches[0], "GOMAXPROCS=3", "GOPROXY=off", "GOSUMDB=off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "UNRELATED_SECRET=fixture-must-not-reach-build"}
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if scenario == "signal_entrypoint" {
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- command.Wait() }()
				deadline := time.NewTimer(20 * time.Second)
				ticker := time.NewTicker(20 * time.Millisecond)
				defer deadline.Stop()
				defer ticker.Stop()
			waiting:
				for {
					select {
					case err := <-done:
						t.Fatalf("assembler exited before admitted launch: %v %s", err, stderr.String())
					case <-deadline.C:
						cancel()
						<-done
						t.Fatal("runtime launch timed out")
					case <-ticker.C:
						if data, err := os.ReadFile(filepath.Join(root, "runtime-state")); err == nil && len(data) > 65 {
							break waiting
						}
					}
				}
				// Signal only the public entrypoint PID, not its process group.
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
				case <-time.After(15 * time.Second):
					cancel()
					<-done
					t.Fatal("entrypoint signal failed bounded owned cleanup")
				}
				if _, err := os.Stat(filepath.Join(root, "runtime-state")); !os.IsNotExist(err) {
					t.Fatalf("owned runtime remains: %v", err)
				}
			} else {
				err = command.Run()
			}
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
			if scenario == "valid_runner_failure" || scenario == "fake_success_no_output" || scenario == "signal_entrypoint" || scenario == "simulated_timeout" {
				if readErr != nil {
					t.Fatalf("valid selected fixture never reached bounded offline runner: %v stderr=%s", readErr, stderr.String())
				}
				for _, want := range []string{"--network=none", "--pull=never", "--userns=keep-id", "BR2_PRIMARY_SITE=file:///nonexistent", "BR2_PRIMARY_SITE_ONLY=y", "--label=hal.microvm.build=.hal-l8-minimal-runtime."} {
					if !strings.Contains(string(called), want) {
						t.Fatalf("missing offline runner argument %s: %s", want, called)
					}
				}
				for _, want := range []string{"--timeout=28800\n", "--cpus=3\n", "--memory=12g\n", "--pids-limit=512\n", "--security-opt=no-new-privileges\n"} {
					if !strings.Contains(string(called), want) {
						t.Errorf("actual minimal runner missing %q", want)
					}
				}
				outer, err := os.ReadFile(filepath.Join(root, "outer-budget"))
				if err != nil || string(outer) != "--signal=TERM\n--kill-after=10s\n481m\n" {
					t.Errorf("actual outer budget = %q, err=%v; want 481m with unchanged TERM/10s grace", outer, err)
				}
				if strings.Contains(string(called), "fixture-must-not-reach-build") {
					t.Fatal("host environment leaked to build")
				}
				if scenario == "fake_success_no_output" && !strings.Contains(stderr.String(), "actual output measurement rejected") {
					t.Fatalf("fake success must reach output measurement, not fail earlier cleanup: %s", stderr.String())
				}
				if scenario == "simulated_timeout" {
					status, err := os.ReadFile(filepath.Join(root, "timeout-status"))
					if err != nil || string(status) != "124\n" || !strings.Contains(stderr.String(), "offline runtime rejected") {
						t.Fatalf("timeout fixture did not reach actual runtime rejection: status=%q err=%v stderr=%s", status, err, stderr.String())
					}
					cleanup, err := os.ReadFile(filepath.Join(root, "cleanup-args"))
					if err != nil || string(cleanup) != "rm\n--force\n--ignore\n"+strings.Repeat("a", 64)+"\n" {
						t.Fatalf("timeout lost exact owned cleanup: args=%q err=%v", cleanup, err)
					}
					if _, err := os.Stat(filepath.Join(root, "runtime-state")); !os.IsNotExist(err) {
						t.Fatalf("timeout left fake owned runtime: %v", err)
					}
					stages, err := filepath.Glob(filepath.Join(root, ".native-assembly-*"))
					if err != nil || len(stages) != 1 {
						t.Fatalf("timeout did not retain exactly one private stage: %v %v", stages, err)
					}
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("invalid source/cache/authority reached runner: %s (%v)", called, readErr)
			}
		})
	}
}
