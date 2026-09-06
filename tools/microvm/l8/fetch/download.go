//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

func allowedDownloadURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return false
	}
	if u.Host == "nodejs.org" {
		return u.String() == nodeURL
	}
	return u.Host == "registry.npmjs.org" && strings.HasSuffix(u.Path, ".tgz")
}

func newHTTPClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 20 * time.Second}).DialContext, TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxConnsPerHost: 1, DisableCompression: true}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 || len(via) > 5 || !allowedDownloadURL(req.URL) || req.URL.String() != via[0].URL.String() {
			return errCache
		}
		return nil
	}}
}

func downloadPinned(ctx context.Context, client *http.Client, dir string, spec downloadSpec) (retErr error) {
	root, err := openCacheDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = downloadPinnedAt(ctx, client, root, spec)
	return err
}

func downloadPinnedAt(ctx context.Context, client *http.Client, dir *os.File, spec downloadSpec) (owned ownedCacheEntry, retErr error) {
	if ctx.Err() != nil || client == nil || !validPin(spec.File) {
		return owned, errCache
	}
	u, err := url.Parse(spec.URL)
	if err != nil || !allowedDownloadURL(u) {
		return owned, errCache
	}
	// A stage is private to this invocation. O_EXCL refuses existing files and
	// symlinks; no failed download removes an entry owned by another invocation.
	file, owned, err := createCacheEntry(dir, spec.File)
	if err != nil {
		return owned, errCache
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if retErr != nil {
			owned.remove(dir)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return owned, errCache
	}
	response, err := client.Do(req)
	if err != nil {
		return owned, errCache
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > spec.File.Size {
		return owned, errCache
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(contextReader{ctx, response.Body}, spec.File.Size+1))
	if err != nil || n != spec.File.Size || hex.EncodeToString(hash.Sum(nil)) != spec.File.SHA256 || ctx.Err() != nil {
		return owned, errCache
	}
	if file.Sync() != nil || file.Close() != nil {
		return owned, errCache
	}
	file = nil
	if ctx.Err() != nil {
		return owned, errCache
	}
	return owned, nil
}
