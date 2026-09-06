//go:build linux

// Package minimalprofile produces offline image artifacts. It has no VM,
// credential, strict-runtime, or boot authority.
package minimalprofile

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"golang.org/x/sys/unix"
)

const maxContent = int64(512 << 20)
const maxInodes = 65536
const maxRecords = 262144

var errImage = errors.New("minimal image: input, inspection, or publication rejected")
var safeName = regexp.MustCompile(`^[A-Za-z0-9._@+/-]+$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Pins must be supplied independently of the candidate archive/image. The Pi
// tree pin authenticates installed paths, types, modes, ownership and bytes;
// it is deliberately separate from B1's source-archive inventory digest.
type Pins struct {
	GuestInitSHA256, GuestAgentSHA256, NodeSHA256, PiLauncherSHA256 string
	InitScriptSHA256, InstalledPiTreeSHA256                         string
}

type ImageRequest struct {
	Archive, ArchiveSHA256, Output string
	Epoch                          int64
	Pins                           Pins
}

// Measurement is produced by a complete scan of the resulting ext4, not by
// converting caller-provided inspection JSON. It is not launch authorization.
type Measurement struct {
	RootfsSHA256          string
	SizeBytes             int64
	Executables           []assetbuild.L8MinimalExecutable
	Inventory             assetbuild.L8MinimalInventory
	InstalledPiTreeSHA256 string
}

type stageEntry struct {
	name     string
	mode     int64
	uid, gid int
	kind     byte
	link     string
	size     int64
}

// BuildImage consumes a digest-authenticated staged rootfs tar, constructs an
// actual ext4 without mounting it, and publishes only after complete bounded
// inspection. It does NOT compile Node/Pi or prove their offline source build.
// No existing destination is overwritten, including a concurrent publisher.
func BuildImage(ctx context.Context, req ImageRequest) (result Measurement, retErr error) {
	phase := "request"
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("minimal image: %s rejected", phase)
		}
	}()
	if req.Epoch <= 0 || req.Epoch > 2147483647 || !validPins(req.Pins) {
		return Measurement{}, errImage
	}
	phase = "image tool versions"
	if err := checkImageTools(ctx); err != nil {
		return Measurement{}, err
	}
	phase = "output directory"
	parent, err := openDirectory(filepath.Dir(req.Output), true)
	if err != nil {
		return Measurement{}, errImage
	}
	defer parent.Close()
	base := filepath.Base(req.Output)
	if !safeLeaf(base) {
		return Measurement{}, errImage
	}
	scratch, err := os.MkdirTemp("", "hal-minimal-image-")
	if err != nil {
		return Measurement{}, errImage
	}
	defer os.RemoveAll(scratch)
	archive := filepath.Join(scratch, "input.tar")
	phase = "archive snapshot"
	if _, err := copyPinned(req.Archive, archive, req.ArchiveSHA256, maxContent+(64<<20)); err != nil {
		return Measurement{}, errImage
	}
	root := filepath.Join(scratch, "root")
	if err := os.Mkdir(root, 0755); err != nil {
		return Measurement{}, errImage
	}
	phase = "archive extraction"
	entries, content, err := extractStage(archive, root, req.Epoch)
	if err != nil {
		return Measurement{}, err
	}
	phase = "ext4 generation"
	image := filepath.Join(scratch, "rootfs.ext4")
	// A fixed formula keeps small fixture images cheap and real payload images
	// adequately provisioned. Logical scan limits are checked independently.
	imageBytes := ((content*2 + (64 << 20) + (4 << 20) - 1) / (4 << 20)) * (4 << 20)
	if imageBytes > 1<<30 {
		return Measurement{}, errImage
	}
	file, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Measurement{}, errImage
	}
	err = file.Truncate(imageBytes)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return Measurement{}, errImage
	}
	_, err = runTool(ctx, req.Epoch, 4<<20, "mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-I", "256", "-N", "65536", "-m", "0", "-U", "8f3e62d8-7e65-4fc2-96d4-8f0d15f13058", "-L", "hal-l8-minimal", "-O", "extent,dir_index,filetype,has_journal,sparse_super,^metadata_csum_seed", "-E", "hash_seed=7c4d3b19-4aa5-4e78-9e1b-a561b5f94428,lazy_itable_init=0,lazy_journal_init=0", "-d", root, image)
	if err != nil {
		return Measurement{}, errImage
	}
	// mke2fs -d sees the invoking user's ownership; set the tar's verified
	// ownership in the filesystem itself, never chown the host or need root.
	phase = "ext4 ownership"
	var commands strings.Builder
	entries = append(entries, stageEntry{name: ".", mode: 0755, kind: tar.TypeDir})
	entries = append(entries, stageEntry{name: "lost+found", mode: 0700, kind: tar.TypeDir})
	for _, e := range entries {
		name := "/" + e.name
		if e.name == "." {
			name = "/"
		}
		typeMode := int64(unix.S_IFREG)
		if e.kind == tar.TypeDir {
			typeMode = unix.S_IFDIR
		}
		if e.kind == tar.TypeSymlink {
			typeMode = unix.S_IFLNK
		}
		for _, field := range []struct {
			name  string
			value int64
		}{{"mode", typeMode | e.mode}, {"uid", int64(e.uid)}, {"gid", int64(e.gid)}, {"atime", req.Epoch}, {"ctime", req.Epoch}, {"mtime", req.Epoch}, {"crtime", req.Epoch}} {
			fmt.Fprintf(&commands, "set_inode_field %s %s %d\n", name, field.name, field.value)
		}
	}
	commandFile := filepath.Join(scratch, "ownership.commands")
	if err := os.WriteFile(commandFile, []byte(commands.String()), 0600); err != nil {
		return Measurement{}, errImage
	}
	out, err := debugTool(ctx, req.Epoch, image, "-w", "-f", commandFile)
	if err != nil {
		return Measurement{}, errImage
	}
	want := "debugfs: " + strings.ReplaceAll(strings.TrimSuffix(commands.String(), "\n"), "\n", "\ndebugfs: ") + "\n"
	if string(out) != want {
		return Measurement{}, errImage
	}
	phase = "ext4 consistency"
	if _, err := runTool(ctx, req.Epoch, 4<<20, "e2fsck", "-f", "-n", image); err != nil {
		return Measurement{}, errImage
	}
	phase = "ext4 inspection"
	measurement, err := inspectImage(ctx, image, req.Pins)
	if err != nil {
		return Measurement{}, err
	}
	phase = "publication"
	if err := publishFile(ctx, parent, base, image, measurement.RootfsSHA256); err != nil {
		return Measurement{}, errImage
	}
	return measurement, nil
}

func validPins(p Pins) bool {
	for _, value := range []string{p.GuestInitSHA256, p.GuestAgentSHA256, p.NodeSHA256, p.PiLauncherSHA256, p.InitScriptSHA256, p.InstalledPiTreeSHA256} {
		if !validDigest(value) {
			return false
		}
	}
	return true
}
func validDigest(s string) bool { return digestPattern.MatchString(s) && s != strings.Repeat("0", 64) }
func safeLeaf(s string) bool {
	return s != "." && s != ".." && s != "" && safeName.MatchString(s) && !strings.Contains(s, "/")
}
func safeRelative(s string) bool {
	return s != "." && path.Clean(s) == s && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "../") && safeName.MatchString(s)
}

func extractStage(archive, root string, epoch int64) ([]stageEntry, int64, error) {
	file, err := os.Open(archive)
	if err != nil {
		return nil, 0, errImage
	}
	defer file.Close()
	r := tar.NewReader(file)
	entries := []stageEntry{}
	seen := map[string]byte{".": tar.TypeDir}
	var content int64
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, errImage
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !safeRelative(name) || seen[name] != 0 || len(entries) >= maxInodes-2 || h.Size < 0 || h.Size > maxContent-content || len(h.PAXRecords) > 0 || len(h.Xattrs) > 0 || h.Mode & ^int64(07777) != 0 || h.Mode&06000 != 0 {
			return nil, 0, errImage
		}
		if seen[path.Dir(name)] != tar.TypeDir || forbiddenName(path.Base(name)) {
			return nil, 0, errImage
		}
		if h.Uid != 0 || h.Gid != 0 {
			if (name != "workspace" && name != "run/agent") || h.Uid != 1000 || h.Gid != 1000 || h.Typeflag != tar.TypeDir {
				return nil, 0, errImage
			}
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if h.Size != 0 || os.Mkdir(dest, 0755) != nil {
				return nil, 0, errImage
			}
		case tar.TypeReg:
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return nil, 0, errImage
			}
			n, copyErr := io.CopyN(f, r, h.Size)
			closeErr := f.Close()
			if copyErr != nil || closeErr != nil || n != h.Size {
				return nil, 0, errImage
			}
			content += n
		case tar.TypeSymlink:
			if h.Size != 0 || !safeLink("/"+name, h.Linkname) || os.Symlink(h.Linkname, dest) != nil {
				return nil, 0, errImage
			}
		default:
			return nil, 0, errImage // No devices, hardlinks, sockets or sparse extensions.
		}
		seen[name] = h.Typeflag
		entries = append(entries, stageEntry{name, h.Mode, h.Uid, h.Gid, h.Typeflag, h.Linkname, h.Size})
	}
	if content == 0 {
		return nil, 0, errImage
	}
	return entries, content, nil
}

func safeLink(name, target string) bool {
	if target == "" || len(target) > 4096 || !safeName.MatchString(target) {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return path.Clean(target) == target
	}
	depth := strings.Count(path.Dir(name), "/")
	for _, part := range strings.Split(target, "/") {
		if part == ".." {
			depth--
			if depth < 0 {
				return false
			}
		} else if part != "." && part != "" {
			depth++
		}
	}
	return true
}

func forbiddenName(name string) bool {
	n := strings.ToLower(name)
	for _, exact := range []string{".npmrc", ".npm", ".ssh", ".aws", ".netrc", "credentials", "credentials.json", "auth.json", "id_rsa", "id_ed25519", "hal-guest-role-bootstrap", "hal-guest-credential-helper", "hal-guest-mount-monitor", "hal-guest-workload-shim"} {
		if n == exact {
			return true
		}
	}
	return strings.HasSuffix(n, ".pem") || strings.Contains(n, "npm-session")
}

// All components are opened nofollow. Writable shared directories are rejected
// except root-owned sticky ancestors such as /tmp. The final output directory
// must be private and owned by the invoking uid.
func openDirectory(name string, private bool) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errImage
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errImage
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, errImage
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Getuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			unix.Close(fd)
			return nil, errImage
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || (private && (st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0)) {
		unix.Close(fd)
		return nil, errImage
	}
	return os.NewFile(uintptr(fd), name), nil
}

func copyPinned(source, dest, digest string, limit int64) (int64, error) {
	if !validDigest(digest) {
		return 0, errImage
	}
	dir, err := openDirectory(filepath.Dir(source), false)
	if err != nil {
		return 0, errImage
	}
	defer dir.Close()
	base := filepath.Base(source)
	if !safeLeaf(base) {
		return 0, errImage
	}
	fd, err := unix.Openat(int(dir.Fd()), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, errImage
	}
	file := os.NewFile(uintptr(fd), base)
	defer file.Close()
	before, err := file.Stat()
	var initial unix.Stat_t
	if err != nil || unix.Fstat(fd, &initial) != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit || before.Mode().Perm()&0022 != 0 || (initial.Uid != 0 && initial.Uid != uint32(os.Getuid())) {
		return 0, errImage
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, errImage
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(file, limit+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	var st unix.Stat_t
	after, statErr := file.Stat()
	if copyErr != nil || syncErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != digest || unix.Fstatat(int(dir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Ino != initial.Ino || st.Dev != initial.Dev {
		return 0, errImage
	}
	return n, nil
}

func publishFile(ctx context.Context, parent *os.File, base, source, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return errImage
	}
	defer in.Close()
	return publishReader(ctx, parent, base, in, digest)
}

// publishReader is the private, CLI-free publication primitive. Cancellation
// must be observed before the final check adjacent to rename. Cancellation
// racing after that check may commit; a committed output is never deleted in
// response to late cancellation.
func publishReader(ctx context.Context, parent *os.File, base string, source io.Reader, digest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Temp names are created relative to the retained output directory. Use
	// /proc only for our own pinned directory, never for unverified input.
	root := fmt.Sprintf("/proc/self/fd/%d", parent.Fd())
	tmp, err := os.CreateTemp(root, ".minimal-")
	if err != nil {
		return errImage
	}
	tempBase := filepath.Base(tmp.Name())
	defer unix.Unlinkat(int(parent.Fd()), tempBase, 0)
	h := sha256.New()
	_, copyErr := copyContext(ctx, io.MultiWriter(tmp, h), source)
	var syncErr error
	if copyErr == nil && ctx.Err() == nil {
		syncErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if copyErr != nil || syncErr != nil || closeErr != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		return errImage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if unix.Renameat2(int(parent.Fd()), tempBase, int(parent.Fd()), base, unix.RENAME_NOREPLACE) != nil {
		return errImage
	}
	return parent.Sync()
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	n, err := io.Copy(destination, contextReader{ctx: ctx, source: source})
	if cancelErr := ctx.Err(); cancelErr != nil {
		return n, cancelErr
	}
	return n, err
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.source.Read(data)
	if cancelErr := r.ctx.Err(); cancelErr != nil {
		return n, cancelErr
	}
	return n, err
}

type boundedBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(len(p)) > b.limit-int64(b.Len()) {
		return 0, errImage
	}
	return b.Buffer.Write(p)
}

func runTool(ctx context.Context, epoch, limit int64, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "TZ=UTC", "MKE2FS_CONFIG=/dev/null", "SOURCE_DATE_EPOCH=" + strconv.FormatInt(epoch, 10), "E2FSPROGS_FAKE_TIME=" + strconv.FormatInt(epoch, 10)}
	out := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, errImage
	}
	return out.Bytes(), nil
}

func debugTool(ctx context.Context, epoch int64, image string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "debugfs", append(args, image)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "TZ=UTC", "E2FSPROGS_FAKE_TIME=" + strconv.FormatInt(epoch, 10)}
	out := &boundedBuffer{limit: maxContent}
	stderr := &boundedBuffer{limit: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, errImage
	}
	if !regexp.MustCompile(`^debugfs [0-9]+\.[0-9]+[^\n]*\n$`).Match(stderr.Bytes()) {
		return nil, errImage
	}
	return out.Bytes(), nil
}

func checkImageTools(ctx context.Context) error {
	for _, name := range []string{"mke2fs", "debugfs", "e2fsck"} {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(probeCtx, name, "-V")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
		out := &boundedBuffer{limit: 4096}
		cmd.Stdout = out
		cmd.Stderr = out
		err := cmd.Run()
		cancel()
		if err != nil || !strings.HasPrefix(out.String(), name+" 1.47.4 ") || !strings.Contains(out.String(), "Using EXT2FS Library version 1.47.4") {
			return errImage
		}
	}
	return nil
}

func digestBytes(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
