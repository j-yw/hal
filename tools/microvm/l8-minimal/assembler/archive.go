//go:build linux

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/minimalprofile"
	"golang.org/x/sys/unix"
)

var guestName = regexp.MustCompile(`^[A-Za-z0-9._@+/-]+$`)

type archiveEntry struct {
	header tar.Header
	offset int64
	hash   string
}

func archiveName(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimSuffix(name, "/")
	return name, name != "" && name != "." && guestName.MatchString(name) && path.Clean(name) == name && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../")
}

// Convert the trusted builder's actual tar into the minimal canonical format.
// Device records below /dev are omitted because boot mounts devtmpfs there;
// hard links become measured independent regular entries. No host chown occurs.
func canonicalize(ctx context.Context, input, output string, epoch int64) (string, minimalprofile.Pins, error) {
	var pins minimalprofile.Pins
	parent, err := openDirectory(filepath.Dir(input), true)
	if err != nil {
		return "", pins, err
	}
	defer parent.close()
	source, initial, err := parent.entry(filepath.Base(input))
	if err != nil {
		return "", pins, err
	}
	defer source.Close()
	if initial.Size <= 0 || initial.Size > 576<<20 {
		return "", pins, errInput
	}
	destination, err := openDirectory(filepath.Dir(output), true)
	if err != nil {
		return "", pins, err
	}
	defer destination.close()
	spoolFD, err := unix.Openat(int(destination.file.Fd()), ".contents", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", pins, err
	}
	spool := os.NewFile(uintptr(spoolFD), ".contents")
	defer spool.Close()
	defer func() {
		var retained, named unix.Stat_t
		if unix.Fstat(spoolFD, &retained) == nil && unix.Fstatat(int(destination.file.Fd()), ".contents", &named, unix.AT_SYMLINK_NOFOLLOW) == nil && retained.Dev == named.Dev && retained.Ino == named.Ino {
			_ = unix.Unlinkat(int(destination.file.Fd()), ".contents", 0)
		}
	}()
	reader := tar.NewReader(contextReader{ctx, io.LimitReader(source, initial.Size+1)})
	entries := map[string]archiveEntry{}
	seen := map[string]bool{}
	var content int64
	for count := 0; ; count++ {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 65534 || h.Size < 0 || h.Mode&^int64(07777) != 0 || h.Mode&06000 != 0 {
			return "", pins, errInput
		}
		if h.Name == "." || h.Name == "./" {
			if count != 0 || h.Typeflag != tar.TypeDir || h.Mode != 0755 || h.Uid != 0 || h.Gid != 0 {
				return "", pins, errInput
			}
			continue
		}
		name, ok := archiveName(h.Name)
		// Two pinned BusyBox applets need literal bracket names, not a wider
		// archive/link alphabet. Admit only their exact canonical symlink tuple.
		applet := name == "usr/bin/[" || name == "usr/bin/[["
		if (!ok && !applet) || seen[name] {
			return "", pins, errInput
		}
		if applet && ((h.Name != name && h.Name != "./"+name) || h.Typeflag != tar.TypeSymlink || h.Mode != 0777 || h.Uid != 0 || h.Gid != 0 || h.Size != 0 || h.Linkname != "../../bin/busybox") {
			return "", pins, errInput
		}
		seen[name] = true
		for key := range h.PAXRecords {
			if key != "path" && key != "linkpath" && key != "mtime" && key != "atime" && key != "ctime" {
				return "", pins, errInput
			}
		}
		if len(h.Xattrs) != 0 {
			return "", pins, errInput
		}
		if h.Typeflag == tar.TypeChar || h.Typeflag == tar.TypeBlock {
			if !strings.HasPrefix(name, "dev/") || h.Uid != 0 || h.Gid != 0 {
				return "", pins, errInput
			}
			continue
		}
		if h.Uid != 0 || h.Gid != 0 {
			if (name != "workspace" && name != "run/agent") || h.Uid != 1000 || h.Gid != 1000 || h.Typeflag != tar.TypeDir {
				return "", pins, errInput
			}
		}
		// GNU long-name records preserve the pinned Pi package's >100-byte
		// basenames without PAX metadata, truncation or changed installed bytes.
		canonical := tar.Header{Name: name, Mode: h.Mode, Uid: h.Uid, Gid: h.Gid, Typeflag: h.Typeflag, Size: h.Size, ModTime: time.Unix(epoch, 0).UTC(), Format: tar.FormatGNU}
		e := archiveEntry{header: canonical, offset: content}
		switch h.Typeflag {
		case tar.TypeReg:
			if h.Size > 512<<20-content {
				return "", pins, errInput
			}
			hash := sha256.New()
			n, err := io.Copy(io.MultiWriter(spool, hash), reader)
			if err != nil || n != h.Size {
				return "", pins, errInput
			}
			content += n
			e.hash = hex.EncodeToString(hash.Sum(nil))
		case tar.TypeDir:
			if h.Size != 0 {
				return "", pins, errInput
			}
		case tar.TypeLink:
			link, ok := archiveName(h.Linkname)
			if !ok || h.Size != 0 {
				return "", pins, errInput
			}
			e.header.Linkname = link
		case tar.TypeSymlink:
			if h.Size != 0 || h.Linkname == "" || !guestName.MatchString(h.Linkname) || len(h.Linkname) > 100 {
				return "", pins, errInput
			}
			if strings.HasPrefix(h.Linkname, "/") {
				if path.Clean(h.Linkname) != h.Linkname {
					return "", pins, errInput
				}
			} else {
				depth := strings.Count(path.Dir("/"+name), "/")
				for _, part := range strings.Split(h.Linkname, "/") {
					if part == ".." {
						depth--
					} else if part != "" && part != "." {
						depth++
					}
					if depth < 0 {
						return "", pins, errInput
					}
				}
			}
			e.header.Linkname = h.Linkname
			e.hash = digest([]byte(h.Linkname))
		default:
			return "", pins, errInput
		}
		entries[name] = e
	}
	position, err := source.Seek(0, io.SeekCurrent)
	if err != nil || position > initial.Size {
		return "", pins, errInput
	}
	tail := io.LimitReader(contextReader{ctx, source}, initial.Size-position+1)
	var padding [4096]byte
	for {
		n, err := tail.Read(padding[:])
		for _, b := range padding[:n] {
			if b != 0 {
				return "", pins, errInput
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", pins, errInput
		}
	}
	var final, named unix.Stat_t
	if unix.Fstat(int(source.Fd()), &final) != nil || unix.Fstatat(int(parent.file.Fd()), filepath.Base(input), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFile(initial, final) || !sameFile(initial, named) {
		return "", pins, errInput
	}
	if content == 0 || parent.current() != nil || destination.current() != nil || ctx.Err() != nil {
		return "", pins, errInput
	}
	// Buildroot clears /run after its ownership tables. Construct this one
	// declared empty recipe directory before measurement, never repair an
	// unsafe parent or overwrite malformed candidate metadata/contents.
	run := entries["run"].header
	if run.Typeflag != tar.TypeDir || run.Mode != 0755 || run.Uid != 0 || run.Gid != 0 {
		return "", pins, errInput
	}
	for name := range entries {
		if strings.HasPrefix(name, "run/agent/") {
			return "", pins, errInput
		}
	}
	if agent, exists := entries["run/agent"]; exists {
		h := agent.header
		if h.Typeflag != tar.TypeDir || h.Mode != 0700 || h.Uid != 1000 || h.Gid != 1000 {
			return "", pins, errInput
		}
	} else {
		if len(entries) >= 65534 {
			return "", pins, errInput
		}
		entries["run/agent"] = archiveEntry{header: tar.Header{Name: "run/agent", Typeflag: tar.TypeDir, Mode: 0700, Uid: 1000, Gid: 1000, ModTime: time.Unix(epoch, 0).UTC(), Format: tar.FormatGNU}}
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var tree strings.Builder
	var logical int64
	for _, name := range names {
		e := entries[name]
		if dir := path.Dir(name); dir != "." && entries[dir].header.Typeflag != tar.TypeDir {
			return "", pins, errInput
		}
		if e.header.Typeflag == tar.TypeLink {
			target, ok := entries[e.header.Linkname]
			if !ok || target.header.Typeflag != tar.TypeReg || target.header.Mode != e.header.Mode || target.header.Uid != e.header.Uid || target.header.Gid != e.header.Gid {
				return "", pins, errInput
			}
			e.header.Typeflag = tar.TypeReg
			e.header.Linkname = ""
			e.header.Size = target.header.Size
			e.offset = target.offset
			e.hash = target.hash
			entries[name] = e
		}
		logical += e.header.Size
		if logical > 512<<20 {
			return "", pins, errInput
		}
		if name == "usr/lib/pi" || strings.HasPrefix(name, "usr/lib/pi/") {
			kind := map[byte]string{tar.TypeReg: "regular", tar.TypeDir: "directory", tar.TypeSymlink: "symlink"}[e.header.Typeflag]
			fmt.Fprintf(&tree, "/%s\x00%s\x00%o\x00%d\x00%d\x00%s\n", name, kind, e.header.Mode, e.header.Uid, e.header.Gid, e.hash)
		}
	}
	pinFor := func(name string) string {
		e := entries[name]
		if e.header.Typeflag != tar.TypeReg || e.header.Size <= 0 || e.header.Mode != 0755 || e.header.Uid != 0 || e.header.Gid != 0 {
			return ""
		}
		return e.hash
	}
	pins = minimalprofile.Pins{GuestInitSHA256: pinFor("sbin/hal-init"), GuestAgentSHA256: pinFor("usr/bin/hal-guest-agent"), NodeSHA256: pinFor("usr/bin/node"), PiLauncherSHA256: pinFor("usr/bin/pi"), InitScriptSHA256: pinFor("sbin/init"), InstalledPiTreeSHA256: digest([]byte(tree.String()))}
	for _, p := range []string{pins.GuestInitSHA256, pins.GuestAgentSHA256, pins.NodeSHA256, pins.PiLauncherSHA256, pins.InitScriptSHA256} {
		if !shaPattern.MatchString(p) {
			return "", pins, errInput
		}
	}
	if tree.Len() == 0 {
		return "", pins, errInput
	}
	if !leafPattern.MatchString(filepath.Base(output)) {
		return "", pins, errInput
	}
	fd, err := unix.Openat(int(destination.file.Fd()), filepath.Base(output), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", pins, err
	}
	f := os.NewFile(uintptr(fd), filepath.Base(output))
	defer f.Close()
	hash := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(f, hash))
	for _, name := range names {
		e := entries[name]
		if writer.WriteHeader(&e.header) != nil {
			return "", pins, errInput
		}
		if e.header.Typeflag == tar.TypeReg {
			if _, err := io.Copy(writer, contextReader{ctx, io.NewSectionReader(spool, e.offset, e.header.Size)}); err != nil {
				return "", pins, errInput
			}
		}
	}
	if writer.Close() != nil || f.Sync() != nil || destination.current() != nil || ctx.Err() != nil {
		return "", pins, errInput
	}
	return hex.EncodeToString(hash.Sum(nil)), pins, nil
}
