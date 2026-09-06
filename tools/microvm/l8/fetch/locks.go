//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxManifestBytes = 4 << 20
	maxSourceBytes   = 512 << 20
	maxArchiveBytes  = 64 << 20
	maxSources       = 4096
	nodeFile         = "node-v22.22.0.tar.xz"
	piFile           = "pi-coding-agent-0.82.1.tgz"
	shrinkwrapFile   = "pi-shrinkwrap-0.82.1.json"
	nodeURL          = "https://nodejs.org/dist/v22.22.0/" + nodeFile
	piURL            = "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/" + piFile
)

var errCache = errors.New("L8 cache: locked input, transfer, or publication rejected")
var filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$`)
var npmNamePattern = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
var versionPattern = regexp.MustCompile(`^[0-9][A-Za-z0-9.+-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type lockedFile struct {
	Name   string
	Size   int64
	SHA256 string
}
type downloadSpec struct {
	File lockedFile
	URL  string
}

func validPin(f lockedFile) bool {
	return filenamePattern.MatchString(f.Name) && f.Size > 0 && f.Size <= maxSourceBytes && digestPattern.MatchString(f.SHA256) && f.SHA256 != strings.Repeat("0", 64)
}

func parseManifest(r io.Reader) (map[string]lockedFile, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxManifestBytes || data[len(data)-1] != '\n' {
		return nil, errCache
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > maxSources {
		return nil, errCache
	}
	result := make(map[string]lockedFile, len(lines))
	previous := ""
	var total int64
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || line <= previous {
			return nil, errCache
		}
		previous = line
		size, err := strconv.ParseInt(fields[1], 10, 64)
		f := lockedFile{Name: fields[2], Size: size, SHA256: fields[0]}
		if err != nil || strconv.FormatInt(size, 10) != fields[1] || !validPin(f) {
			return nil, errCache
		}
		if _, exists := result[f.Name]; exists {
			return nil, errCache
		}
		total += size
		if total > 1<<30 {
			return nil, errCache
		}
		result[f.Name] = f
	}
	return result, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func matchesPin(data []byte, f lockedFile) bool {
	sum := sha256.Sum256(data)
	return validPin(f) && int64(len(data)) == f.Size && hex.EncodeToString(sum[:]) == f.SHA256
}

// The caller authenticates the compressed archive before this bounded scan.
// No tar path is ever written to the host filesystem.
func extractShrinkwrap(ctx context.Context, source io.Reader, pin lockedFile) ([]byte, error) {
	if ctx.Err() != nil || !validPin(pin) || pin.Size > maxManifestBytes {
		return nil, errCache
	}
	gz, err := gzip.NewReader(contextReader{ctx, source})
	if err != nil {
		return nil, errCache
	}
	defer gz.Close()
	expanded := &io.LimitedReader{R: gz, N: maxArchiveBytes + 1}
	tr := tar.NewReader(expanded)
	seen := map[string]bool{}
	var found []byte
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 65536 || ctx.Err() != nil {
			return nil, errCache
		}
		name := strings.TrimSuffix(h.Name, "/")
		if len(name) > 4096 || !strings.HasPrefix(name, "package/") || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00\r\n") || seen[name] || len(h.PAXRecords) != 0 || h.Size < 0 || h.Size > maxArchiveBytes || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) {
			return nil, errCache
		}
		seen[name] = true
		if name == "package/npm-shrinkwrap.json" {
			if h.Typeflag != tar.TypeReg || h.Size != pin.Size {
				return nil, errCache
			}
			found, err = io.ReadAll(io.LimitReader(tr, pin.Size+1))
			if err != nil || !matchesPin(found, pin) {
				return nil, errCache
			}
		}
	}
	// Consume the bounded gzip tail so truncated streams and invalid checksums
	// cannot be hidden after tar end markers.
	var padding [4096]byte
	for {
		n, readErr := expanded.Read(padding[:])
		for _, value := range padding[:n] {
			if value != 0 {
				return nil, errCache
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil || expanded.N == 0 || ctx.Err() != nil {
			return nil, errCache
		}
	}
	if expanded.N == 0 || ctx.Err() != nil || found == nil {
		return nil, errCache
	}
	return found, nil
}

type npmPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

func planNPMDownloads(data []byte, locks map[string]lockedFile) ([]downloadSpec, error) {
	if len(data) == 0 || len(data) > maxManifestBytes || len(locks) > maxSources {
		return nil, errCache
	}
	var wrap struct {
		LockfileVersion int                   `json:"lockfileVersion"`
		Packages        map[string]npmPackage `json:"packages"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&wrap) != nil || decoder.Decode(new(any)) != io.EOF || wrap.LockfileVersion != 3 || len(wrap.Packages) < 2 || len(wrap.Packages) > maxSources {
		return nil, errCache
	}
	root, ok := wrap.Packages[""]
	if !ok || root.Name != "@earendil-works/pi-coding-agent" || root.Version != "0.82.1" {
		return nil, errCache
	}
	for _, required := range []string{nodeFile, piFile, shrinkwrapFile} {
		if f, ok := locks[required]; !ok || f.Name != required || !validPin(f) {
			return nil, errCache
		}
	}
	byName := map[string]downloadSpec{}
	for installed, pkg := range wrap.Packages {
		if installed == "" {
			continue
		}
		if path.Clean(installed) != installed || strings.ContainsAny(installed, "\\\x00\r\n") || !strings.HasPrefix(installed, "node_modules/") || pkg.Link || !versionPattern.MatchString(pkg.Version) {
			return nil, errCache
		}
		parts := strings.Split(installed, "node_modules/")
		name := parts[len(parts)-1]
		if !npmNamePattern.MatchString(name) || (pkg.Name != "" && pkg.Name != name) {
			return nil, errCache
		}
		for _, parent := range parts[1 : len(parts)-1] {
			if !npmNamePattern.MatchString(strings.TrimSuffix(parent, "/")) {
				return nil, errCache
			}
		}
		filename := strings.ReplaceAll(strings.TrimPrefix(name, "@"), "/", "-") + "-" + pkg.Version + ".tgz"
		canonical := "https://registry.npmjs.org/" + name + "/-/" + path.Base(name) + "-" + pkg.Version + ".tgz"
		if pkg.Resolved != "" && pkg.Resolved != canonical {
			return nil, errCache
		}
		pin, ok := locks[filename]
		if !ok || pin.Name != filename || !validPin(pin) {
			return nil, errCache
		}
		spec := downloadSpec{File: pin, URL: canonical}
		if prior, ok := byName[filename]; ok && prior != spec {
			return nil, errCache
		}
		byName[filename] = spec
	}
	if len(byName)+3 != len(locks) {
		return nil, errCache
	}
	result := make([]downloadSpec, 0, len(byName))
	for _, spec := range byName {
		result = append(result, spec)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].File.Name < result[j].File.Name })
	return result, nil
}
