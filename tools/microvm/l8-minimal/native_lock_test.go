//go:build linux

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// This pins the reviewed acquisition fixture, not an assembler implementation.
// Behavioral cache/source/receipt rejection is in the tagged CLI regression.
func TestMinimalNativeLockPinsReviewedClosure(t *testing.T) {
	data, err := os.ReadFile("native-sources.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		SchemaVersion string `json:"schemaVersion"`
		Buildroot     struct {
			Version string `json:"version"`
			SHA256  string `json:"archiveSHA256"`
		} `json:"buildroot"`
		Records []struct {
			Name      string `json:"name"`
			HashFile  string `json:"hashFile"`
			Algorithm string `json:"upstreamAlgorithm"`
			Digest    string `json:"upstreamDigest"`
			URL       string `json:"url"`
			MaxBytes  int64  `json:"maxBytes"`
			Size      int64  `json:"size"`
			SHA256    string `json:"sha256"`
		} `json:"records"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		t.Fatal(err)
	}
	if lock.SchemaVersion != "hal-l8-minimal-native-lock-v1" || lock.Buildroot.Version != "2026.05.1" || lock.Buildroot.SHA256 != "ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58" {
		t.Fatal("native closure must retain the trusted Buildroot archive identity")
	}
	names := []string{"c-ares-1.34.6.tar.gz", "distlib-0.4.0.tar.gz", "glib-2.86.5.tar.xz", "icu4c-78.2-sources.tgz", "libslirp-v4.9.1.tar.bz2", "libuv-v1.52.1-dist.tar.gz", "nghttp2-1.68.1.tar.xz", "openssl-3.6.3.tar.gz", "pcre2-10.47.tar.bz2", "pixman-0.46.4.tar.xz", "qemu-10.2.0.tar.xz"}
	if len(lock.Records) != len(names) {
		t.Fatal("native closure must contain exactly eleven evaluated archives")
	}
	var size, capacity int64
	for i, record := range lock.Records {
		if record.Name != names[i] || record.Size <= 0 || record.Size > record.MaxBytes || len(record.SHA256) != 64 || !strings.HasPrefix(record.URL, "https://") || !strings.HasPrefix(record.HashFile, "package/") {
			t.Fatalf("invalid native lock record %d", i)
		}
		if record.Name == "pixman-0.46.4.tar.xz" {
			if record.Algorithm != "sha512" || record.Digest != "83b133e7969ba34f883f4e08dcc5d388c4397f43ce836c191c05945fe77c16ff501d531600780c12678a0d08105828a6bdeff2156b63f9c1a84087bc7f40ae9f" || record.SHA256 != "a098c33924754ad43f981b740f6d576c70f9ed1006e12221b1845431ebce1239" || record.Size != 660536 {
				t.Fatal("pixman must retain upstream SHA512 and separately measured SHA256")
			}
		} else if record.Algorithm != "sha256" || record.Digest != record.SHA256 {
			t.Fatalf("record %d lost its upstream SHA256 authority", i)
		}
		size += record.Size
		capacity += record.MaxBytes
	}
	if size != 237662404 || capacity != 448790528 {
		t.Fatalf("changed measured or authorized byte totals: %d %d", size, capacity)
	}
}
