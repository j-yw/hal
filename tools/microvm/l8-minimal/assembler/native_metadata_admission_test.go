//go:build linux

package main

import (
	"archive/tar"
	"testing"
)

func TestCanonicalNativeAppletRawSpellings(t *testing.T) {
	for _, name := range []string{"usr/bin/[/", "usr/bin/[[/", "usr//bin/[", "./usr/bin/[", "usr/bin/../../usr/bin/["} {
		t.Run(name, func(t *testing.T) {
			nativeMetadataCanonical(t, false, func(headers map[string]tar.Header) {
				headers[name] = tar.Header{Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "../../bin/busybox"}
			})
		})
	}
	for _, name := range []string{"usr/bin/[", "usr/bin/[["} {
		if _, ok := archiveName(name); ok || guestName.MatchString(name) {
			t.Fatal("generic archive/link alphabet was expanded")
		}
	}
}
