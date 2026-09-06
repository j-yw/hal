//go:build linux

// The native assembler is an offline source producer, not a runtime or a B1
// publisher. Its successful stdout must be retained by the trusted supervisor.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/minimalprofile"
	"golang.org/x/sys/unix"
)

type assemblyReceipt struct {
	SchemaVersion                                string
	SourceRevision, SourceTree, NativeLockSHA256 string
	SourceDateEpoch                              int64
	ArchiveSHA256                                string
	Pins                                         minimalprofile.Pins
	Measurement                                  minimalprofile.Measurement
	PiSource                                     string
	HostQEMU                                     string
	PiLifecycleScriptsExecuted                   bool
	GuestCredentialControlVerified               bool
}

const (
	nativeAssemblyTimeout   = 490 * time.Minute
	nativeAssemblyWaitDelay = 90 * time.Second
	nativeAssemblyLogBytes  = 64 << 20
)

func main() {
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, nativeAssemblyTimeout)
	defer cancel()
	if err := assemble(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func assemble(ctx context.Context, args []string, out, logs io.Writer) (retErr error) {
	phase := "request"
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("native assembly: %s rejected; private staging, if created, retained", phase)
		}
	}()
	flags := flag.NewFlagSet("assemble", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repo := flags.String("source-repo", "", "")
	revision := flags.String("source-revision", "", "")
	cache := flags.String("cache", "", "")
	native := flags.String("native-cache", "", "")
	output := flags.String("output", "", "")
	runtime := flags.String("runtime", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *runtime != "podman" || !gitPattern.MatchString(*revision) {
		return errInput
	}
	for _, name := range []string{*repo, *cache, *native, *output} {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" || strings.ContainsAny(name, ",\x00\r\n") {
			return errInput
		}
	}
	if strings.HasPrefix(*output, *repo+"/") || strings.HasPrefix(*cache, *repo+"/") || strings.HasPrefix(*native, *repo+"/") || *cache == *native {
		return errInput
	}
	parent, err := openDirectory(filepath.Dir(*output), true)
	if err != nil {
		return err
	}
	defer parent.close()
	if !leafPattern.MatchString(filepath.Base(*output)) {
		return errInput
	}
	if _, err := os.Lstat(*output); !os.IsNotExist(err) {
		return errInput
	}
	workFD, err := ownedChild(parent, "")
	if err != nil {
		return err
	}
	defer workFD.close()
	work := workFD.name
	// Failures retain only this task-owned stage for diagnosis. In particular a
	// runtime cleanup uncertainty must not be erased by an outer Go defer.
	children := map[string]*directory{}
	for _, name := range []string{"source", "cache", "build", "export", "publish", "inspection"} {
		child, err := ownedChild(workFD, name)
		if err != nil {
			return err
		}
		children[name] = child
		defer child.close()
	}
	phase = "Git source snapshot"
	selected, err := snapshotSource(ctx, *repo, *revision, children["source"])
	if err != nil {
		return err
	}
	phase = "selected source locks"
	// Parse exactly the immutable blobs already verified against the Git tree,
	// not an independently reopened metadata pathname.
	l5bytes := selected.metadata["tools/microvm/l5/cache.manifest"]
	l5, err := parseManifest(l5bytes, 52)
	if err != nil {
		return err
	}
	l8bytes := selected.metadata["tools/microvm/l8/cache.manifest"]
	l8, err := parseManifest(l8bytes, 142)
	if err != nil {
		return err
	}
	combined := map[string]pin{}
	for _, set := range []map[string]pin{l5, l8} {
		for n, p := range set {
			if combined[n].Name != "" {
				return errInput
			}
			combined[n] = p
		}
	}
	lockBytes := selected.metadata["tools/microvm/l8-minimal/native-sources.lock.json"]
	lock, err := parseNative(lockBytes, l5["buildroot-2026.05.1.tar.xz"])
	if err != nil {
		return err
	}
	phase = "cache directory admission"
	original, err := openDirectory(*cache, true)
	if err != nil {
		return err
	}
	defer original.close()
	extra, err := openDirectory(*native, true)
	if err != nil {
		return err
	}
	defer extra.close()
	copied := children["cache"]
	phase = "exact cache entries"
	if original.exact(combined) != nil {
		return errInput
	}
	nativePins := map[string]pin{}
	for _, r := range lock.Records {
		if combined[r.Name].Name != "" {
			return errInput
		}
		nativePins[r.Name] = r.pin
	}
	if extra.exact(nativePins) != nil {
		return errInput
	}
	phase = "cache byte verification"
	for _, name := range keys(combined) {
		if copyVerified(ctx, original, copied, combined[name], nil) != nil {
			return errInput
		}
	}
	for _, r := range lock.Records {
		if copyVerified(ctx, extra, copied, r.pin, &r) != nil {
			return errInput
		}
		combined[r.Name] = r.pin
	}
	if copied.exact(combined) != nil || selected.root.current() != nil || workFD.current() != nil || parent.current() != nil {
		return errInput
	}
	// The immutable snapshot is the input for the long build. Subsequent changes
	// to the original integration checkout cannot alter it or its source identity.
	if checkCheckout(ctx, *repo, *revision) != nil {
		return errInput
	}
	phase = "offline runtime"
	podman, err := exec.LookPath("podman")
	if err != nil {
		return fmt.Errorf("native assembly: local rootless runtime unavailable")
	}
	command := exec.CommandContext(ctx, "/bin/bash", filepath.Join(selected.root.name, "tools/microvm/l8-minimal/run-native.sh"), selected.root.name, copied.name, filepath.Join(work, "build"), filepath.Join(work, "export"), fmt.Sprint(selected.epoch), selected.revision, selected.tree, parent.name)
	command.Env = []string{"PATH=" + filepath.Dir(podman) + ":/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	// Allow the existing owned runner's bounded TERM/kill and exact-CID probes
	// to finish before an unresponsive shell is forcibly stopped.
	command.WaitDelay = nativeAssemblyWaitDelay
	boundedLog := &logWriter{dest: logs, remaining: nativeAssemblyLogBytes}
	command.Stdout = boundedLog
	command.Stderr = boundedLog
	if command.Run() != nil {
		return fmt.Errorf("native assembly: offline build failed; private evidence retained")
	}
	if ctx.Err() != nil || copied.current() != nil || selected.root.current() != nil || workFD.current() != nil || parent.current() != nil {
		return errInput
	}
	phase = "actual output measurement"
	published := children["publish"]
	publication := published.name
	archiveSHA, pins, err := canonicalize(ctx, filepath.Join(work, "export/rootfs.tar"), filepath.Join(publication, "rootfs.tar"), selected.epoch)
	if err != nil {
		return fmt.Errorf("native assembly: measured output rejected")
	}
	// BuildImage's private extraction/image intermediates must remain on the
	// selected task filesystem, not the host's potentially tmpfs-backed /tmp.
	if children["inspection"].current() != nil || os.Setenv("TMPDIR", children["inspection"].name) != nil {
		return errInput
	}
	measurement, err := minimalprofile.BuildImage(ctx, minimalprofile.ImageRequest{Archive: filepath.Join(publication, "rootfs.tar"), ArchiveSHA256: archiveSHA, Output: filepath.Join(publication, "rootfs.ext4"), Epoch: selected.epoch, Pins: pins})
	if err != nil {
		return fmt.Errorf("native assembly: ext4 inspection rejected")
	}
	receipt := assemblyReceipt{SchemaVersion: "hal-l8-minimal-assembly-v1", SourceRevision: selected.revision, SourceTree: selected.tree, NativeLockSHA256: digest(lockBytes), SourceDateEpoch: selected.epoch, ArchiveSHA256: archiveSHA, Pins: pins, Measurement: measurement, PiSource: "pinned_published_javascript_not_typescript_rebuild", HostQEMU: "build_time_v8_snapshot_only"}
	data, err := json.Marshal(receipt)
	if err != nil {
		return errInput
	}
	data = append(data, '\n')
	fd, err := unix.Openat(int(published.file.Fd()), "assembly.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errInput
	}
	file := os.NewFile(uintptr(fd), "assembly.json")
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errInput
	}
	if ctx.Err() != nil || parent.current() != nil || workFD.current() != nil || published.current() != nil || published.file.Sync() != nil {
		return errInput
	}
	if unix.Renameat2(int(workFD.file.Fd()), "publish", int(parent.file.Fd()), filepath.Base(*output), unix.RENAME_NOREPLACE) != nil {
		return errInput
	}
	if parent.file.Sync() != nil {
		return fmt.Errorf("native assembly: committed output needs explicit verification")
	}
	// Only this host-generated, successfully measured record reaches stdout.
	// The caller must retain it independently; adjacent assembly.json is audit.
	_, err = out.Write(data)
	return err
}

type logWriter struct {
	dest      io.Writer
	remaining int64
}

func (w *logWriter) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > w.remaining {
		p = p[:w.remaining]
	}
	if len(p) > 0 {
		if _, err := w.dest.Write(p); err != nil {
			return 0, err
		}
		w.remaining -= int64(len(p))
	}
	return n, nil
}
