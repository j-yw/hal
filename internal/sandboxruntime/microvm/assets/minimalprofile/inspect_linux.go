//go:build linux

package minimalprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

type imageEntry struct {
	inode              uint64
	mode, uid, gid     uint32
	size               int64
	kind, link, digest string
}
type imageQuery func(string) ([]byte, error)

func inspectImage(ctx context.Context, image string, pins Pins) (Measurement, error) {
	result, err := inspect(func(command string) ([]byte, error) { return debugTool(ctx, 1700000000, image, "-R", command) }, pins)
	if err != nil {
		return Measurement{}, err
	}
	f, err := os.Open(image)
	if err != nil {
		return Measurement{}, errImage
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (1<<30)+1))
	if err != nil || n > 1<<30 {
		return Measurement{}, errImage
	}
	result.RootfsSHA256 = hex.EncodeToString(h.Sum(nil))
	result.SizeBytes = n
	return result, nil
}

// inspect visits only reachable entries, but visits every such entry and every
// regular file's contents and attributes. Incomplete command output is fatal.
// All debugfs requests containing untrusted identities use numeric inodes.
func inspect(query imageQuery, pins Pins) (Measurement, error) {
	if !validPins(pins) {
		return Measurement{}, errImage
	}
	entries := map[string]imageEntry{}
	seen := map[uint64]imageEntry{}
	type directory struct {
		name          string
		inode, parent uint64
	}
	queue := []directory{{"/", 2, 2}}
	queued := map[uint64]bool{2: true}
	var records uint64
	var logical int64
	for index := 0; index < len(queue); index++ {
		dir := queue[index]
		out, err := query(fmt.Sprintf("ls -p -r <%d>", dir.inode))
		if err != nil || len(out) > 32<<20 {
			return Measurement{}, errImage
		}
		self, parent := 0, 0
		names := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			if line == "" {
				continue
			}
			records++
			if records > maxRecords {
				return Measurement{}, errImage
			}
			if line == "/0/000000/0/0//0/" {
				continue
			}
			name, e, err := parseDirectoryRecord(line)
			if err != nil {
				return Measurement{}, errImage
			}
			if names[name] {
				return Measurement{}, errImage
			}
			names[name] = true
			if name == "." {
				if e.inode != dir.inode || e.kind != "directory" {
					return Measurement{}, errImage
				}
				self++
				entries[dir.name] = e
				continue
			}
			if name == ".." {
				if e.inode != dir.parent || e.kind != "directory" {
					return Measurement{}, errImage
				}
				parent++
				continue
			}
			if forbiddenName(name) {
				return Measurement{}, errImage
			}
			full := path.Join(dir.name, name)
			if _, exists := entries[full]; exists {
				return Measurement{}, errImage
			}
			entries[full] = e
			if old, exists := seen[e.inode]; exists {
				if old != e || e.kind == "directory" {
					return Measurement{}, errImage
				}
			} else {
				seen[e.inode] = e
				if len(seen) > maxInodes {
					return Measurement{}, errImage
				}
				if e.kind == "regular" {
					if e.size > maxContent-logical {
						return Measurement{}, errImage
					}
					logical += e.size
				}
			}
			if e.mode&06000 != 0 {
				return Measurement{}, errImage
			}
			if e.kind == "directory" {
				if queued[e.inode] {
					return Measurement{}, errImage
				}
				queued[e.inode] = true
				queue = append(queue, directory{full, e.inode, dir.inode})
			}
		}
		if self != 1 || parent != 1 {
			return Measurement{}, errImage
		}
	}
	if logical == 0 {
		return Measurement{}, errImage
	}
	seen[2] = entries["/"]
	contents := map[uint64][]byte{}
	digests := map[uint64]string{}
	links := map[uint64]string{}
	for _, name := range sortedKeys(entries) {
		e := entries[name]
		if e.mode&06000 != 0 {
			return Measurement{}, errImage
		}
		if _, done := digests[e.inode]; done {
			continue
		}
		attributes, err := query(fmt.Sprintf("ea_list <%d>", e.inode))
		if err != nil || len(attributes) != 0 {
			return Measurement{}, errImage
		} // Minimal image admits no extended attributes.
		switch e.kind {
		case "regular":
			data, err := query(fmt.Sprintf("cat <%d>", e.inode))
			if err != nil || int64(len(data)) != e.size || secretContent.Match(data) {
				return Measurement{}, errImage
			}
			digests[e.inode] = digestBytes(data)
			// Only retain small configuration; each large file is released after
			// hashing/scanning, so aggregate image size is not aggregate memory.
			if name == "/etc/passwd" || name == "/etc/group" || name == "/etc/shadow" || name == "/usr/lib/pi/package.json" {
				if len(data) > 1<<20 {
					return Measurement{}, errImage
				}
				contents[e.inode] = data
			}
		case "symlink":
			out, err := query(fmt.Sprintf("stat <%d>", e.inode))
			if err != nil {
				return Measurement{}, errImage
			}
			matches := fastLink.FindAllSubmatch(out, -1)
			if len(matches) != 1 || strings.Count(string(out), "Fast link dest:") != 1 {
				return Measurement{}, errImage
			}
			target := string(matches[0][1])
			if int64(len(target)) != e.size || !safeLink(name, target) {
				return Measurement{}, errImage
			}
			links[e.inode] = target
			digests[e.inode] = digestBytes([]byte(target))
		case "directory":
			digests[e.inode] = ""
		default:
			return Measurement{}, errImage
		}
	}
	for name, e := range entries {
		e.digest = digests[e.inode]
		e.link = links[e.inode]
		entries[name] = e
	}
	traversable := func(name string) bool {
		for parent := path.Dir(name); ; parent = path.Dir(parent) {
			e, ok := entries[parent]
			if !ok || e.kind != "directory" || e.uid != 0 || e.gid != 0 || e.mode&0005 != 0005 || e.mode&0022 != 0 {
				return false
			}
			if parent == "/" {
				return true
			}
		}
	}
	check := func(name, kind string, mode, uid uint32) bool {
		e, ok := entries[name]
		return ok && e.kind == kind && e.mode == mode && e.uid == uid && e.gid == uid && traversable(name)
	}
	for _, name := range []string{"/sbin/init", "/sbin/hal-init", "/usr/bin/hal-guest-agent", "/usr/bin/node", "/usr/bin/pi", "/bin/busybox", "/usr/bin/setpriv"} {
		if !check(name, "regular", 0755, 0) {
			return Measurement{}, errImage
		}
	}
	if !check("/workspace", "directory", 0700, 1000) || !check("/run/agent", "directory", 0700, 1000) || !check("/etc/resolv.conf", "regular", 0644, 0) || entries["/etc/resolv.conf"].size != 0 || entries["/sbin/init"].digest != pins.InitScriptSHA256 {
		return Measurement{}, errImage
	}
	for _, name := range []string{"/bin/sh", "/usr/bin/env", "/sbin/ip", "/usr/bin/nc", "/bin/ping", "/bin/ping6", "/usr/bin/nslookup", "/usr/bin/wget"} {
		resolved, ok := resolveEntry(entries, name)
		if !ok || entries[resolved].inode != entries["/bin/busybox"].inode || !traversable(name) {
			return Measurement{}, errImage
		}
	}
	for _, name := range []string{"/etc/passwd", "/etc/group", "/etc/shadow"} {
		mode := uint32(0644)
		if name == "/etc/shadow" {
			mode = 0600
		}
		if !check(name, "regular", mode, 0) {
			return Measurement{}, errImage
		}
	}
	if !strings.Contains(string(contents[entries["/etc/passwd"].inode]), "workload:x:1000:1000:Workload:/workspace:/bin/sh\n") || !strings.Contains(string(contents[entries["/etc/group"].inode]), "workload:x:1000:\n") {
		return Measurement{}, errImage
	}
	for _, line := range strings.Split(strings.TrimSpace(string(contents[entries["/etc/shadow"].inode])), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 9 || (parts[1] != "!" && parts[1] != "*") {
			return Measurement{}, errImage
		}
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(contents[entries["/usr/lib/pi/package.json"].inode], &pkg) != nil || pkg.Name != "@earendil-works/pi-coding-agent" || pkg.Version != "0.82.1" {
		return Measurement{}, errImage
	}
	var tree strings.Builder
	dependencyFiles := 0
	for _, name := range sortedKeys(entries) {
		if name != "/usr/lib/pi" && !strings.HasPrefix(name, "/usr/lib/pi/") {
			continue
		}
		e := entries[name]
		if e.uid != 0 || e.gid != 0 || !traversable(name) || (e.kind != "symlink" && (e.mode&0022 != 0 || e.mode&0004 == 0)) {
			return Measurement{}, errImage
		}
		if e.kind == "symlink" {
			resolved, ok := resolveEntry(entries, name)
			if !ok || !strings.HasPrefix(resolved, "/usr/lib/pi/") {
				return Measurement{}, errImage
			}
		}
		if strings.HasPrefix(name, "/usr/lib/pi/node_modules/") && e.kind == "regular" {
			dependencyFiles++
		}
		fmt.Fprintf(&tree, "%s\x00%s\x00%o\x00%d\x00%d\x00%s\n", name, e.kind, e.mode, e.uid, e.gid, e.digest)
	}
	installed := digestBytes([]byte(tree.String()))
	if dependencyFiles == 0 || installed != pins.InstalledPiTreeSHA256 {
		return Measurement{}, errImage
	}
	result := Measurement{Inventory: assetbuild.L8MinimalInventory{Inodes: uint64(len(seen)), DirectoryRecords: records, LogicalBytes: uint64(logical), Findings: []string{}}, InstalledPiTreeSHA256: installed}
	for index, name := range []string{"/sbin/hal-init", "/usr/bin/hal-guest-agent", "/usr/bin/node", "/usr/bin/pi"} {
		e := entries[name]
		expected := []string{pins.GuestInitSHA256, pins.GuestAgentSHA256, pins.NodeSHA256, pins.PiLauncherSHA256}[index]
		if e.digest != expected || e.size <= 0 {
			return Measurement{}, errImage
		}
		uid, gid := e.uid, e.gid
		result.Executables = append(result.Executables, assetbuild.L8MinimalExecutable{Role: []string{"hal-init", "hal-guest-agent", "node", "pi-launcher"}[index], Type: e.kind, SHA256: e.digest, SizeBytes: e.size, UID: &uid, GID: &gid, Mode: e.mode})
	}
	return result, nil
}

var secretContent = regexp.MustCompile(`(?i)BEGIN ([A-Z0-9_-]+[ \t]+)*PRIVATE KEY|(?:_authToken|aws_secret_access_key)[ \t]*=|HAL_[A-Z0-9_]*CANARY`)
var fastLink = regexp.MustCompile(`(?m)^Fast link dest: "([A-Za-z0-9._@+/-]+)"$`)
var directoryRecord = regexp.MustCompile(`^/([1-9][0-9]*)/([0-7]{6})/([0-9]+)/([0-9]+)/([A-Za-z0-9._@+-]+)/([0-9]*)/$`)

func parseDirectoryRecord(line string) (string, imageEntry, error) {
	m := directoryRecord.FindStringSubmatch(line)
	if m == nil {
		return "", imageEntry{}, errImage
	}
	ino, e1 := strconv.ParseUint(m[1], 10, 64)
	mode, e2 := strconv.ParseUint(m[2], 8, 32)
	uid, e3 := strconv.ParseUint(m[3], 10, 32)
	gid, e4 := strconv.ParseUint(m[4], 10, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || ino > maxInodes {
		return "", imageEntry{}, errImage
	}
	kind := ""
	switch mode & 0170000 {
	case 0040000:
		kind = "directory"
	case 0100000:
		kind = "regular"
	case 0120000:
		kind = "symlink"
	default:
		return "", imageEntry{}, errImage
	}
	var size int64
	if m[6] != "" {
		var err error
		size, err = strconv.ParseInt(m[6], 10, 64)
		if err != nil || size < 0 {
			return "", imageEntry{}, errImage
		}
	} else if kind != "directory" {
		return "", imageEntry{}, errImage
	}
	return m[5], imageEntry{inode: ino, mode: uint32(mode & 07777), uid: uint32(uid), gid: uint32(gid), size: size, kind: kind}, nil
}

func resolveEntry(entries map[string]imageEntry, name string) (string, bool) {
	for depth := 0; depth < 40; depth++ {
		parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
		prefix := "/"
		changed := false
		for index, part := range parts {
			prefix = path.Join(prefix, part)
			e, ok := entries[prefix]
			if !ok {
				return "", false
			}
			if e.kind == "symlink" {
				target := e.link
				if !strings.HasPrefix(target, "/") {
					target = path.Join(path.Dir(prefix), target)
				}
				name = path.Join(append([]string{target}, parts[index+1:]...)...)
				changed = true
				break
			}
			if index < len(parts)-1 && e.kind != "directory" {
				return "", false
			}
		}
		if !changed {
			return name, true
		}
	}
	return "", false
}
