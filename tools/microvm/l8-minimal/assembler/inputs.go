//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var errInput = errors.New("native assembly: selected input rejected")
var leafPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var gitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

type pin struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type nativeRecord struct {
	pin
	HashFile  string `json:"hashFile"`
	Algorithm string `json:"upstreamAlgorithm"`
	Digest    string `json:"upstreamDigest"`
	URL       string `json:"url"`
	MaxBytes  int64  `json:"maxBytes"`
}
type nativeLock struct {
	SchemaVersion string `json:"schemaVersion"`
	Buildroot     struct {
		Version string `json:"version"`
		SHA256  string `json:"archiveSHA256"`
	} `json:"buildroot"`
	Records []nativeRecord `json:"records"`
}

func strictJSON(data []byte, result any) error {
	if len(data) == 0 || len(data) > 4<<20 {
		return errInput
	}
	// encoding/json's struct decoder does not reject duplicate object keys.
	d := json.NewDecoder(bytes.NewReader(data))
	allowed := map[string]bool{"schemaVersion": true, "buildroot": true, "version": true, "archiveSHA256": true, "records": true, "name": true, "size": true, "sha256": true, "hashFile": true, "upstreamAlgorithm": true, "upstreamDigest": true, "url": true, "maxBytes": true}
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errInput
		}
		token, err := d.Token()
		if err != nil {
			return errInput
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || !allowed[name] {
					return errInput
				}
				seen[name] = true
				if walk(depth+1) != nil {
					return errInput
				}
			}
		case '[':
			for d.More() {
				if walk(depth+1) != nil {
					return errInput
				}
			}
		default:
			return errInput
		}
		_, err = d.Token()
		return err
	}
	if walk(0) != nil {
		return errInput
	}
	if _, err := d.Token(); err != io.EOF {
		return errInput
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(result) != nil {
		return errInput
	}
	return nil
}

func parseNative(data []byte, buildroot pin) (nativeLock, error) {
	var lock nativeLock
	if strictJSON(data, &lock) != nil || lock.SchemaVersion != "hal-l8-minimal-native-lock-v1" || lock.Buildroot.Version != "2026.05.1" || lock.Buildroot.SHA256 != buildroot.SHA256 || len(lock.Records) != 11 {
		return lock, errInput
	}
	names := []string{"c-ares-1.34.6.tar.gz", "distlib-0.4.0.tar.gz", "glib-2.86.5.tar.xz", "icu4c-78.2-sources.tgz", "libslirp-v4.9.1.tar.bz2", "libuv-v1.52.1-dist.tar.gz", "nghttp2-1.68.1.tar.xz", "openssl-3.6.3.tar.gz", "pcre2-10.47.tar.bz2", "pixman-0.46.4.tar.xz", "qemu-10.2.0.tar.xz"}
	var max int64
	for i, r := range lock.Records {
		u, err := url.Parse(r.URL)
		if !validPin(r.pin) || r.Name != names[i] || r.Size > r.MaxBytes || r.MaxBytes > 256<<20 || err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || !strings.HasPrefix(r.HashFile, "package/") || filepath.Clean(r.HashFile) != r.HashFile || !strings.HasSuffix(r.HashFile, ".hash") {
			return lock, errInput
		}
		if r.Name == "pixman-0.46.4.tar.xz" {
			if r.Algorithm != "sha512" || len(r.Digest) != 128 {
				return lock, errInput
			}
			if _, err := hex.DecodeString(r.Digest); err != nil {
				return lock, errInput
			}
		} else if r.Algorithm != "sha256" || r.Digest != r.SHA256 {
			return lock, errInput
		}
		max += r.MaxBytes
	}
	if max != 448790528 {
		return lock, errInput
	}
	return lock, nil
}

func parseManifest(data []byte, count int) (map[string]pin, error) {
	if len(data) == 0 || len(data) > 4<<20 || data[len(data)-1] != '\n' {
		return nil, errInput
	}
	result := map[string]pin{}
	previous := ""
	var total int64
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || line <= previous {
			return nil, errInput
		}
		previous = line
		n, err := strconv.ParseInt(f[1], 10, 64)
		p := pin{f[2], n, f[0]}
		if err != nil || strconv.FormatInt(n, 10) != f[1] || !validPin(p) || result[p.Name].Name != "" {
			return nil, errInput
		}
		result[p.Name] = p
		total += n
	}
	if len(result) != count || total > 1<<30 {
		return nil, errInput
	}
	return result, nil
}
func validPin(p pin) bool {
	return leafPattern.MatchString(p.Name) && p.Size > 0 && p.Size <= 512<<20 && shaPattern.MatchString(p.SHA256) && p.SHA256 != strings.Repeat("0", 64)
}

// These handles retain the same no-follow directory/entry ownership semantics
// as the accepted L8 fetcher, without exposing a general lease framework.
type directory struct {
	name string
	file *os.File
	stat unix.Stat_t
}

func openDirectory(name string, private bool) (*directory, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errInput
	}
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil || resolved != name {
		return nil, errInput
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errInput
	}
	d := &directory{name: name, file: os.NewFile(uintptr(fd), name)}
	if unix.Fstat(fd, &d.stat) != nil || d.stat.Uid != uint32(os.Getuid()) || d.stat.Mode&0022 != 0 || (private && d.stat.Mode&0777 != 0700) {
		d.file.Close()
		return nil, errInput
	}
	return d, nil
}
func (d *directory) current() error {
	var st unix.Stat_t
	if unix.Lstat(d.name, &st) != nil || st.Dev != d.stat.Dev || st.Ino != d.stat.Ino || st.Mode != d.stat.Mode || st.Uid != d.stat.Uid {
		return errInput
	}
	return nil
}
func (d *directory) close() { _ = d.file.Close() }
func ownedChild(parent *directory, name string) (*directory, error) {
	if name == "" {
		var token [12]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, errInput
		}
		name = ".native-assembly-" + hex.EncodeToString(token[:])
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return nil, errInput
	}
	if unix.Mkdirat(int(parent.file.Fd()), name, 0700) != nil {
		return nil, errInput
	}
	fd, err := unix.Openat(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errInput
	}
	child := &directory{name: filepath.Join(parent.name, name), file: os.NewFile(uintptr(fd), name)}
	if unix.Fstat(fd, &child.stat) != nil || parent.current() != nil || child.current() != nil {
		child.close()
		return nil, errInput
	}
	return child, nil
}
func (d *directory) entry(name string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if !leafPattern.MatchString(name) {
		return nil, st, errInput
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, errInput
	}
	file := os.NewFile(uintptr(fd), name)
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 || st.Mode&0022 != 0 {
		file.Close()
		return nil, st, errInput
	}
	return file, st, nil
}
func (d *directory) exact(names map[string]pin) error {
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errInput
	}
	f := os.NewFile(uintptr(fd), "enumeration")
	defer f.Close()
	entries, err := f.Readdirnames(len(names) + 1)
	if err != nil && err != io.EOF {
		return errInput
	}
	if len(entries) != len(names) {
		return errInput
	}
	for _, name := range entries {
		if names[name].Name == "" {
			return errInput
		}
	}
	return d.current()
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return r.r.Read(p)
}
func copyVerified(ctx context.Context, source, dest *directory, p pin, upstream *nativeRecord) error {
	f, st, err := source.entry(p.Name)
	if err != nil {
		return err
	}
	defer f.Close()
	if st.Size != p.Size {
		return errInput
	}
	fd, err := unix.Openat(int(dest.file.Fd()), p.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errInput
	}
	target := os.NewFile(uintptr(fd), p.Name)
	defer target.Close()
	sum := sha256.New()
	wide := sha512.New()
	n, err := io.Copy(io.MultiWriter(target, sum, wide), io.LimitReader(contextReader{ctx, f}, p.Size+1))
	if err != nil || n != p.Size || hex.EncodeToString(sum.Sum(nil)) != p.SHA256 {
		return errInput
	}
	if upstream != nil && upstream.Algorithm == "sha512" && hex.EncodeToString(wide.Sum(nil)) != upstream.Digest {
		return errInput
	}
	var after, named unix.Stat_t
	if unix.Fstat(int(f.Fd()), &after) != nil || unix.Fstatat(int(source.file.Fd()), p.Name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFile(after, st) || !sameFile(named, st) || source.current() != nil || dest.current() != nil || ctx.Err() != nil {
		return errInput
	}
	return target.Sync()
}
func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func keys(m map[string]pin) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func digest(data []byte) string { s := sha256.Sum256(data); return fmt.Sprintf("%x", s) }
