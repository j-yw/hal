package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	l5BuildrootTagObject = "de1f9260590a53a7cd8a59addc47c96ecd09f983"
	l5BuildrootCommit    = "cb857ba4c87a93e5265a9e4a3f32071abf39e14a"
	l5BuildrootSigner    = "18C7DF2819C1733D822D599EA500D6EE9CB0E540"
	l5BuildImage         = "registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6"
)

type l5SourceLockFile struct {
	SchemaVersion string `json:"schemaVersion"`
	Architecture  string `json:"architecture"`
	BuildImage    struct {
		Reference string `json:"reference"`
		Platform  string `json:"platform"`
	} `json:"buildImage"`
	Buildroot struct {
		Tag               string `json:"tag"`
		TagObject         string `json:"tagObject"`
		Commit            string `json:"commit"`
		SignerFingerprint string `json:"signerFingerprint"`
		SigningKeyURL     string `json:"signingKeyUrl"`
		SignatureFilename string `json:"signatureFilename"`
		SignatureURL      string `json:"signatureUrl"`
	} `json:"buildroot"`
	Sources []l5SourceLock `json:"sources"`
}

type l5SourceLock struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Purpose   string `json:"purpose"`
	Filename  string `json:"filename"`
	URL       string `json:"url"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

func TestL5PinnedSourceLockMatchesAuthoritativeInputs(t *testing.T) {
	path := filepath.Join("..", "tools", "microvm", "l5", "sources.lock.json")
	data := l5ReadRequiredFile(t, path)
	var lock l5SourceLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("decode L5 source lock: %v", err)
	}

	if lock.SchemaVersion != "hal-microvm-source-lock-v1" {
		t.Fatalf("schemaVersion = %q", lock.SchemaVersion)
	}
	if lock.Architecture != "x86_64" {
		t.Fatalf("architecture = %q", lock.Architecture)
	}
	if lock.BuildImage.Reference != l5BuildImage || lock.BuildImage.Platform != "linux/amd64" {
		t.Fatalf("build image lock = %#v", lock.BuildImage)
	}
	if lock.Buildroot.Tag != "2026.05.1" ||
		lock.Buildroot.TagObject != l5BuildrootTagObject ||
		lock.Buildroot.Commit != l5BuildrootCommit ||
		lock.Buildroot.SignerFingerprint != l5BuildrootSigner ||
		lock.Buildroot.SignatureFilename != "buildroot-2026.05.1.tar.xz.sign" ||
		lock.Buildroot.SignatureURL != "https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz.sign" {
		t.Fatalf("Buildroot release identity = %#v", lock.Buildroot)
	}
	if lock.Buildroot.SigningKeyURL != "https://gitlab.com/-/snippets/4836881/raw/main/arnout@rnout.be.asc" {
		t.Fatalf("Buildroot signing key URL is not the release-message GitLab key origin")
	}

	expected := map[string]l5SourceLock{
		"buildroot": {
			Name:     "buildroot",
			Version:  "2026.05.1",
			Purpose:  "buildroot_release",
			Filename: "buildroot-2026.05.1.tar.xz",
			URL:      "https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz",
			SHA256:   "ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58",
		},
		"busybox": {
			Name:     "busybox",
			Version:  "1.38.0",
			Purpose:  "buildroot_download",
			Filename: "busybox-1.38.0.tar.bz2",
			URL:      "https://busybox.net/downloads/busybox-1.38.0.tar.bz2",
			SHA256:   "34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2",
		},
		"bzip2": {
			Name:     "bzip2",
			Version:  "1.0.8",
			Purpose:  "buildroot_download",
			Filename: "bzip2-1.0.8.tar.gz",
			URL:      "https://sources.buildroot.net/bzip2/bzip2-1.0.8.tar.gz",
			SHA256:   "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269",
		},
		"e2fsprogs": {
			Name:     "e2fsprogs",
			Version:  "1.47.4",
			Purpose:  "buildroot_download",
			Filename: "e2fsprogs-1.47.4.tar.xz",
			URL:      "https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.4/e2fsprogs-1.47.4.tar.xz",
			SHA256:   "fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b",
		},
		"elfutils": {
			Name:     "elfutils",
			Version:  "0.194",
			Purpose:  "buildroot_download",
			Filename: "elfutils-0.194.tar.bz2",
			URL:      "https://sources.buildroot.net/elfutils/elfutils-0.194.tar.bz2",
			SHA256:   "09e2ff033d39baa8b388a2d7fbc5390bfde99ae3b7c67c7daaf7433fbcf0f01e",
		},
		"firecracker": {
			Name:     "firecracker",
			Version:  "v1.15.1",
			Purpose:  "live_prerequisite",
			Filename: "firecracker-v1.15.1-x86_64.tgz",
			URL:      "https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz",
			SHA256:   "d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a",
		},
		"go": {
			Name:     "go",
			Version:  "1.25.7",
			Purpose:  "guest_toolchain",
			Filename: "go1.25.7.linux-amd64.tar.gz",
			URL:      "https://go.dev/dl/go1.25.7.linux-amd64.tar.gz",
			SHA256:   "12e6d6a191091ae27dc31f6efc630e3a3b8ba409baf3573d955b196fdf086005",
		},
		"linux": {
			Name:     "linux",
			Version:  "6.1.178",
			Purpose:  "buildroot_download",
			Filename: "linux-6.1.178.tar.xz",
			URL:      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.178.tar.xz",
			SHA256:   "7d83fa67ca75032b1ac6ef49973722073963c0cb9bc3aa7ef3efa749cf6c720f",
		},
		"xz": {
			Name:     "xz",
			Version:  "5.8.3",
			Purpose:  "buildroot_download",
			Filename: "xz-5.8.3.tar.bz2",
			URL:      "https://sources.buildroot.net/xz/xz-5.8.3.tar.bz2",
			SHA256:   "33bf69c0d6c698e83a68f77e6c1f465778e418ca0b3d59860d3ab446f4ac99a6",
		},
		"zstd": {
			Name:     "zstd",
			Version:  "1.5.7",
			Purpose:  "buildroot_download",
			Filename: "zstd-1.5.7.tar.gz",
			URL:      "https://sources.buildroot.net/zstd/zstd-1.5.7.tar.gz",
			SHA256:   "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3",
		},
	}
	if len(lock.Sources) <= len(expected) {
		t.Fatalf("source locks = %d, want authoritative inputs plus transitive Buildroot downloads", len(lock.Sources))
	}

	names := make([]string, 0, len(lock.Sources))
	nameSet := make(map[string]struct{}, len(lock.Sources))
	filenames := make(map[string]struct{}, len(lock.Sources))
	digests := make(map[string]struct{}, len(lock.Sources))
	for _, source := range lock.Sources {
		want, ok := expected[source.Name]
		if ok {
			if source.Version != want.Version ||
				source.Purpose != want.Purpose ||
				source.Filename != want.Filename ||
				source.URL != want.URL ||
				source.SHA256 != want.SHA256 {
				t.Fatalf("source lock %q = %#v, want %#v", source.Name, source, want)
			}
			delete(expected, source.Name)
		} else {
			if source.Purpose != "buildroot_download" {
				t.Fatalf("additional source lock %q purpose = %q, want buildroot_download", source.Name, source.Purpose)
			}
			if source.Version == "" || source.Filename == "" || source.URL == "" {
				t.Fatalf("transitive Buildroot source lock %q is incomplete", source.Name)
			}
		}
		if source.SizeBytes <= 0 {
			t.Fatalf("source lock %q has non-positive size", source.Name)
		}
		if len(source.SHA256) != 64 || strings.ToLower(source.SHA256) != source.SHA256 {
			t.Fatalf("source lock %q has malformed SHA-256", source.Name)
		}
		if !strings.HasPrefix(source.URL, "https://") {
			t.Fatalf("source lock %q URL is not HTTPS", source.Name)
		}
		if _, exists := nameSet[source.Name]; exists {
			t.Fatalf("duplicate source name %q", source.Name)
		}
		if _, exists := filenames[source.Filename]; exists {
			t.Fatalf("duplicate source filename %q", source.Filename)
		}
		if _, exists := digests[source.SHA256]; exists {
			t.Fatalf("duplicate source digest for %q", source.Name)
		}
		nameSet[source.Name] = struct{}{}
		filenames[source.Filename] = struct{}{}
		digests[source.SHA256] = struct{}{}
		names = append(names, source.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing authoritative source locks: %v", reflect.ValueOf(expected).MapKeys())
	}
	sortedNames := append([]string(nil), names...)
	sort.Strings(sortedNames)
	if !reflect.DeepEqual(names, sortedNames) {
		t.Fatalf("source locks are not sorted by name: %v", names)
	}

	goMod := string(l5ReadRequiredFile(t, filepath.Join("..", "go.mod")))
	if !strings.Contains(goMod, "\ngo 1.25.7\n") {
		t.Fatal("Go source lock does not match repository go directive")
	}
}

func TestL5E2fsprogsLockUsesBuildrootSelectedXZArtifact(t *testing.T) {
	path := filepath.Join("..", "tools", "microvm", "l5", "sources.lock.json")
	var lock l5SourceLockFile
	if err := json.Unmarshal(l5ReadRequiredFile(t, path), &lock); err != nil {
		t.Fatalf("decode L5 source lock: %v", err)
	}
	for _, source := range lock.Sources {
		if source.Name != "e2fsprogs" {
			continue
		}
		const (
			filename = "e2fsprogs-1.47.4.tar.xz"
			digest   = "fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b"
		)
		if source.Filename != filename ||
			!strings.HasSuffix(source.URL, "/"+filename) ||
			source.SHA256 != digest {
			t.Fatalf("e2fsprogs lock does not identify the Buildroot-selected xz artifact: %#v", source)
		}
		return
	}
	t.Fatal("e2fsprogs source lock is missing")
}

func TestL5LibcapNGOfflineCacheLockCoversBuildrootDependency(t *testing.T) {
	const (
		name     = "libcap-ng"
		version  = "0.9.3"
		filename = "libcap-ng-0.9.3.tar.gz"
		url      = "https://sources.buildroot.net/libcap-ng/libcap-ng-0.9.3.tar.gz"
		size     = int64(126257)
		digest   = "fe11ebbb55904763b3532f19069f13ec319042634620180a03bd4653d301563e"
	)

	var lock l5SourceLockFile
	if err := json.Unmarshal(l5ReadRequiredFile(t, filepath.Join("..", "tools", "microvm", "l5", "sources.lock.json")), &lock); err != nil {
		t.Fatalf("decode L5 source lock: %v", err)
	}
	for _, source := range lock.Sources {
		if source.Name != name {
			continue
		}
		if source.Version != version ||
			source.Purpose != "buildroot_download" ||
			source.Filename != filename ||
			source.URL != url ||
			source.SizeBytes != size ||
			source.SHA256 != digest {
			t.Fatalf("libcap-ng source lock = %#v, want pinned Buildroot dependency", source)
		}
		manifestLine := fmt.Sprintf("%s\t%d\t%s", digest, size, filename)
		manifest := string(l5ReadRequiredFile(t, filepath.Join("..", "tools", "microvm", "l5", "cache.manifest")))
		if !strings.Contains("\n"+manifest, "\n"+manifestLine+"\n") {
			t.Fatalf("L5 cache manifest is missing libcap-ng pinned dependency %q", filename)
		}
		return
	}
	t.Fatal("libcap-ng source lock is missing")
}

func TestL5CacheManifestVerifierRejectsContainmentAndSetViolations(t *testing.T) {
	script := filepath.Join("..", "tools", "microvm", "l5", "verify-cache.sh")
	if info, err := os.Stat(script); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("L5 cache verifier unavailable: %v", err)
	}

	type mutation func(t *testing.T, cache, manifest string)
	tests := []struct {
		name   string
		mutate mutation
		wantOK bool
	}{
		{name: "valid", wantOK: true},
		{name: "missing", mutate: func(t *testing.T, cache, _ string) {
			t.Helper()
			if err := os.Remove(filepath.Join(cache, "dep-b.tar")); err != nil {
				t.Fatalf("remove cache entry: %v", err)
			}
		}},
		{name: "extra", mutate: func(t *testing.T, cache, _ string) {
			t.Helper()
			l5WriteTestFile(t, filepath.Join(cache, "extra.tar"), []byte("extra"))
		}},
		{name: "hidden extra", mutate: func(t *testing.T, cache, _ string) {
			t.Helper()
			l5WriteTestFile(t, filepath.Join(cache, ".hidden"), []byte("extra"))
		}},
		{name: "symlink", mutate: func(t *testing.T, cache, _ string) {
			t.Helper()
			if err := os.Remove(filepath.Join(cache, "dep-b.tar")); err != nil {
				t.Fatalf("remove cache entry: %v", err)
			}
			if err := os.Symlink("dep-a.tar", filepath.Join(cache, "dep-b.tar")); err != nil {
				t.Fatalf("create cache symlink: %v", err)
			}
		}},
		{name: "nonregular", mutate: func(t *testing.T, cache, _ string) {
			t.Helper()
			if err := os.Remove(filepath.Join(cache, "dep-b.tar")); err != nil {
				t.Fatalf("remove cache entry: %v", err)
			}
			if err := os.Mkdir(filepath.Join(cache, "dep-b.tar"), 0o700); err != nil {
				t.Fatalf("create cache directory: %v", err)
			}
		}},
		{name: "size mismatch", mutate: func(t *testing.T, _, manifest string) {
			t.Helper()
			data := l5ReadRequiredFile(t, manifest)
			fields := strings.Split(string(data), "\t")
			size, err := strconv.Atoi(fields[1])
			if err != nil {
				t.Fatalf("parse cache size: %v", err)
			}
			fields[1] = strconv.Itoa(size + 1)
			l5WriteTestFile(t, manifest, []byte(strings.Join(fields, "\t")))
		}},
		{name: "digest mismatch", mutate: func(t *testing.T, _, manifest string) {
			t.Helper()
			data := l5ReadRequiredFile(t, manifest)
			l5WriteTestFile(t, manifest, []byte(strings.Repeat("f", 64)+string(data[64:])))
		}},
		{name: "traversal", mutate: func(t *testing.T, _, manifest string) {
			t.Helper()
			data := l5ReadRequiredFile(t, manifest)
			l5WriteTestFile(t, manifest, append(data, []byte(strings.Repeat("e", 64)+"\t1\t../escape.tar\n")...))
		}},
		{name: "unsorted", mutate: func(t *testing.T, _, manifest string) {
			t.Helper()
			lines := strings.Split(strings.TrimSpace(string(l5ReadRequiredFile(t, manifest))), "\n")
			sort.Sort(sort.Reverse(sort.StringSlice(lines)))
			l5WriteTestFile(t, manifest, []byte(strings.Join(lines, "\n")+"\n"))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := t.TempDir()
			if err := os.Chmod(cache, 0o700); err != nil {
				t.Fatalf("Chmod(cache) error = %v", err)
			}
			a := []byte("cache-a")
			b := []byte("cache-b")
			l5WriteTestFile(t, filepath.Join(cache, "dep-a.tar"), a)
			l5WriteTestFile(t, filepath.Join(cache, "dep-b.tar"), b)
			manifest := filepath.Join(t.TempDir(), "cache.manifest")
			lines := []string{
				fmt.Sprintf("%s\t%d\t%s", l5Digest(a), len(a), "dep-a.tar"),
				fmt.Sprintf("%s\t%d\t%s", l5Digest(b), len(b), "dep-b.tar"),
			}
			l5WriteTestFile(t, manifest, []byte(strings.Join(lines, "\n")+"\n"))
			if tt.mutate != nil {
				tt.mutate(t, cache, manifest)
			}

			command := exec.Command("sh", script, "--manifest", manifest, "--cache", cache)
			output, err := command.CombinedOutput()
			if tt.wantOK && err != nil {
				t.Fatalf("verify-cache.sh error = %v, output = %q", err, output)
			}
			if !tt.wantOK && err == nil {
				t.Fatalf("verify-cache.sh accepted invalid cache, output = %q", output)
			}
		})
	}
}

func TestL5BuildScriptsLockOfflineReproducibleContainerOrchestration(t *testing.T) {
	required := map[string][]string{
		"fetch.sh": {
			"sources.lock.json",
			"cache.manifest",
			"gpg",
			"--status-fd",
			l5BuildrootSigner,
			l5BuildrootTagObject,
			l5BuildrootCommit,
			"verify-cache.sh",
		},
		"build.sh": {
			l5BuildImage,
			"docker image inspect",
			"--pull=never",
			`--user="$current_uid:$current_gid"`,
			"--platform=linux/amd64",
			"--hostname=hal-l5-build",
			"--network=none",
			"/src",
			"/cache",
			"/build/output",
			`mktemp -d --tmpdir="$output_parent"`,
			"chmod -R u+w",
			"readonly",
			"SOURCE_DATE_EPOCH",
		},
		"build-in-container.sh": {
			"BR2_PRIMARY_SITE_ONLY=y",
			"BR2_DOWNLOAD_FORCE_CHECK_HASHES=y",
			"BR2_PACKAGE_UTIL_LINUX=y",
			"BR2_PACKAGE_UTIL_LINUX_SETPRIV=y",
			"CONFIG_HYPERVISOR_GUEST=y",
			"CONFIG_PARAVIRT=y",
			"CONFIG_KVM_GUEST=y",
			"CONFIG_SMP=y",
			"# CONFIG_DEVTMPFS_MOUNT is not set",
			"BR2_CCACHE=",
			"O=/build/output",
			"DL_DIR=/build/download",
			"GOCACHE=/build/gocache",
			"GOMODCACHE=/build/gomodcache",
			"GOTOOLCHAIN=local",
			"GOPROXY=off",
			"GOSUMDB=off",
			"CGO_ENABLED=0",
			"-mod=readonly",
			"-trimpath",
			"-buildvcs=false",
			"-ldflags=-buildid=",
			"KBUILD_BUILD_USER",
			"KBUILD_BUILD_HOST",
			"KBUILD_BUILD_TIMESTAMP",
			"KBUILD_BUILD_VERSION",
			"lazy_itable_init=0",
			"lazy_journal_init=0",
			"e2fsck -fn",
			"distribution-manifest.json",
			"provenance.json",
			"SHA256SUMS",
		},
		"verify-reproducible.sh": {
			"mktemp -d",
			"build-a",
			"build-b",
			`mktemp -d --tmpdir="$output_parent"`,
			"/src",
			"/cache",
			"/build/output",
			"vmlinux",
			"rootfs.ext4",
			"distribution-manifest.json",
			"provenance.json",
			"SHA256SUMS",
			"cmp",
		},
	}

	root := filepath.Join("..", "tools", "microvm", "l5")
	for name, markers := range required {
		t.Run(name, func(t *testing.T) {
			source := string(l5ReadRequiredFile(t, filepath.Join(root, name)))
			for _, marker := range markers {
				if !strings.Contains(source, marker) {
					t.Errorf("%s missing reproducibility marker %q", name, marker)
				}
			}
			for _, forbidden := range []string{
				"--network=host",
				"--privileged",
				"/var/run/docker.sock",
				"BR2_FORCE_CHECK_HASHES",
				"FORCE_UNSAFE_CONFIGURE",
				"latest",
				"ccache",
			} {
				if name == "build-in-container.sh" && forbidden == "ccache" {
					continue
				}
				if strings.Contains(strings.ToLower(source), strings.ToLower(forbidden)) {
					t.Errorf("%s contains forbidden build marker %q", name, forbidden)
				}
			}
		})
	}
}

func TestL5BuildRootsAndCacheUseCanonicalPrivateTrustBoundaries(t *testing.T) {
	root := filepath.Join("..", "tools", "microvm", "l5")
	for _, name := range []string{"fetch.sh", "build.sh", "verify-reproducible.sh"} {
		source := string(l5ReadRequiredFile(t, filepath.Join(root, name)))
		for _, marker := range []string{"realpath", "stat -c %u", "stat -c %a", "0700"} {
			if !strings.Contains(source, marker) {
				t.Errorf("%s missing private filesystem trust marker %q", name, marker)
			}
		}
	}
	verifier := string(l5ReadRequiredFile(t, filepath.Join(root, "verify-cache.sh")))
	for _, marker := range []string{"--expected-owner", "mode 0700", "-mindepth 1", "! -type f"} {
		if !strings.Contains(verifier, marker) {
			t.Errorf("verify-cache.sh missing exact-set trust marker %q", marker)
		}
	}
}

func TestL5KernelBuildrootAndGuestInitLockIsolationContract(t *testing.T) {
	root := filepath.Join("..", "tools", "microvm", "l5")
	kernel := string(l5ReadRequiredFile(t, filepath.Join(root, "linux.config")))
	for _, setting := range []string{
		"CONFIG_64BIT=y",
		"CONFIG_X86_64=y",
		"CONFIG_SMP=y",
		"CONFIG_ACPI=y",
		"CONFIG_BLK_MQ_PCI=y",
		"CONFIG_PCI=y",
		"CONFIG_PCI_MMCONFIG=y",
		"CONFIG_PCI_MSI=y",
		"CONFIG_PCIEPORTBUS=y",
		"CONFIG_MODULES=n",
		"CONFIG_X86_MPPARSE=n",
		"CONFIG_VIRTIO_MMIO=n",
		"CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=n",
		"CONFIG_VIRTIO_PCI=y",
		"CONFIG_VIRTIO_BLK=y",
		"CONFIG_HYPERVISOR_GUEST=y",
		"CONFIG_PARAVIRT=y",
		"CONFIG_KVM_GUEST=y",
		"CONFIG_VSOCKETS=y",
		"CONFIG_VIRTIO_VSOCKETS=y",
		"CONFIG_HW_RANDOM_VIRTIO=y",
		"CONFIG_EXT4_FS=y",
		"CONFIG_TMPFS=y",
		"CONFIG_DEVTMPFS=y",
		"# CONFIG_DEVTMPFS_MOUNT is not set",
		"CONFIG_PROC_FS=y",
		"CONFIG_SYSFS=y",
		"CONFIG_INET=n",
		"CONFIG_NETDEVICES=n",
	} {
		if !strings.Contains(kernel, setting) {
			t.Errorf("linux.config missing %q", setting)
		}
	}

	builder := string(l5ReadRequiredFile(t, filepath.Join(root, "build-in-container.sh")))
	for _, marker := range []string{
		`CONFIG_ACPI=y`,
		`CONFIG_PCI=y`,
		`CONFIG_VIRTIO_PCI=y`,
		`CONFIG_X86_MPPARSE=n`,
		`CONFIG_VIRTIO_MMIO=n`,
		`! grep -Eq '^CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=(y|m)$' "$kernel_config"`,
		`! grep -Eq '^CONFIG_DEVTMPFS_MOUNT=(y|m)$' "$kernel_config"`,
		`$buildroot_output/build/linux-6.1.178/.config`,
	} {
		if !strings.Contains(builder, marker) {
			t.Errorf("build-in-container.sh missing effective-kernel preflight %q", marker)
		}
	}

	buildroot := string(l5ReadRequiredFile(t, filepath.Join(root, "buildroot.config")))
	for _, setting := range []string{
		`BR2_x86_64=y`,
		`BR2_LINUX_KERNEL=y`,
		`BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.1.178"`,
		`BR2_KERNEL_HEADERS_AS_KERNEL=y`,
		`BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_1=y`,
		`BR2_LINUX_KERNEL_NEEDS_HOST_LIBELF=y`,
		`BR2_PACKAGE_BUSYBOX=y`,
		`BR2_PACKAGE_UTIL_LINUX=y`,
		`BR2_PACKAGE_UTIL_LINUX_SETPRIV=y`,
		`BR2_INIT_NONE=y`,
		`BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y`,
		`BR2_ROOTFS_DEVICE_TABLE="system/device_table.txt /src/tools/microvm/l5/permissions.txt"`,
		`BR2_TARGET_ROOTFS_EXT2=y`,
		`BR2_TARGET_ROOTFS_EXT2_4=y`,
	} {
		if !strings.Contains(buildroot, setting) {
			t.Errorf("buildroot.config missing %q", setting)
		}
	}

	agentSource := string(l5ReadRequiredFile(t, filepath.Join("hal-guest-agent", "main.go")))
	if !strings.Contains(agentSource, `GuestRoot:     "/workspace"`) {
		t.Error("hal-guest-agent does not map guest paths from the locked /workspace root")
	}
	if strings.Contains(agentSource, `GuestRoot:     "/"`) {
		t.Error("hal-guest-agent maps workspace requests from the guest filesystem root")
	}

	users := strings.TrimSpace(string(l5ReadRequiredFile(t, filepath.Join(root, "users.txt"))))
	if users != "agent 1000 agent 1000 ! /workspace /bin/sh - Agent" {
		t.Fatalf("users.txt = %q, want exact agent UID/GID 1000 with a disabled password", users)
	}

	postBuild := string(l5ReadRequiredFile(t, filepath.Join(root, "post-build.sh")))
	for _, marker := range []string{
		`chmod 0755 "$target/bin/busybox"`,
		`ln -snf /bin/busybox "$target/bin/sh"`,
		`ln -snf /bin/busybox "$target/usr/bin/env"`,
		`test -x "$target/usr/bin/setpriv"`,
		`test ! -L "$target/usr/bin/setpriv"`,
	} {
		if !strings.Contains(postBuild, marker) {
			t.Errorf("post-build.sh missing locked applet materialization %q", marker)
		}
	}
	if strings.Contains(postBuild, `ln -snf /bin/busybox "$target/usr/bin/setpriv"`) {
		t.Error("post-build.sh overrides the util-linux setpriv privilege-drop implementation")
	}
	permissions := strings.TrimSpace(string(l5ReadRequiredFile(t, filepath.Join(root, "permissions.txt"))))
	if permissions != "/bin/busybox f 0755 0 0 - - - - -" {
		t.Fatalf("permissions.txt does not override the package setuid BusyBox mode")
	}

	initSource := string(l5ReadRequiredFile(t, filepath.Join(root, "rootfs-overlay", "sbin", "init")))
	for _, marker := range []string{
		"mount -t proc",
		"mount -t devtmpfs",
		"mount -t sysfs",
		"mount -t tmpfs",
		"/run",
		"/tmp",
		"/workspace",
		"size=",
		"uid=1000",
		"gid=1000",
		"mode=0700",
		"--reuid 1000",
		"--regid 1000",
		"--clear-groups",
		"--no-new-privs",
		"/usr/bin/hal-guest-agent",
	} {
		if !strings.Contains(initSource, marker) {
			t.Errorf("guest init missing %q", marker)
		}
	}
	for _, forbidden := range []string{
		"udhcpc",
		"dhclient",
		"ifconfig",
		"ip link",
		"ip addr",
		"getty",
		"login",
		"sshd",
		"authorized_keys",
		"password",
		"token",
	} {
		if strings.Contains(strings.ToLower(initSource), forbidden) {
			t.Errorf("guest init contains forbidden network/login/credential marker %q", forbidden)
		}
	}
}

func TestL5PreparedLinuxImagePrerequisiteTestCannotSkip(t *testing.T) {
	source := l5PreparedLinuxImagePrerequisiteSource(t)
	for _, required := range []string{
		"//go:build l5_firecracker_vsock_integration",
		"TestL5PreparedLinuxImagePrerequisites",
		"HAL_L5_DISTRIBUTION_DIR",
		"runtime.GOOS",
		"runtime.GOARCH",
		"ResolveDistribution",
		"ValidateProvenanceAgainstManifest",
		"provenance.json",
		"SHA256SUMS",
		"l5RequiredDistributionOutputs",
		"debugfs",
		"/usr/bin/setpriv",
		"/usr/bin/env",
		"/bin/sh",
		"/sbin/init",
		"/sbin/hal-init",
		"/usr/bin/hal-guest-agent",
		"/etc/shadow",
		"1000",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("prepared-Linux image prerequisite test missing %q", required)
		}
	}
	for _, forbidden := range []string{"t.Skip(", "t.Skipf(", "t.SkipNow("} {
		if strings.Contains(source, forbidden) {
			t.Errorf("prepared-Linux image prerequisite test contains forbidden skip %q", forbidden)
		}
	}
}

func TestL5PreparedLinuxImageInspectionNeverExecutesRootfsContent(t *testing.T) {
	source := l5PreparedLinuxImagePrerequisiteSource(t)
	for _, required := range []string{"l5DebugfsOperationCat", "\"/usr/bin/setpriv\""} {
		if !strings.Contains(source, required) {
			t.Fatalf("prepared-Linux image prerequisite test must inspect setpriv without extracting it: %q", required)
		}
	}
	for _, forbidden := range []string{
		"exec.Command(setprivPath",
		"os.Chmod(setprivPath",
		"dump /usr/bin/setpriv",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("prepared-Linux image prerequisite test contains host-execution marker %q", forbidden)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "l5_prepared_linux_integration_test.go", source, 0)
	if err != nil {
		t.Fatalf("parse prepared-Linux image prerequisite test: %v", err)
	}
	commandContextCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !l5ASTIdentifier(selector.X, "exec") {
			return true
		}
		switch selector.Sel.Name {
		case "Command":
			t.Error("prepared-Linux image prerequisite test must not use exec.Command")
		case "CommandContext":
			commandContextCalls++
			if len(call.Args) != 5 ||
				!l5ASTIdentifier(call.Args[0], "ctx") ||
				!l5ASTIdentifier(call.Args[1], "debugfs") ||
				!l5ASTString(call.Args[2], "-R") ||
				!l5ASTIdentifier(call.Args[3], "commandText") ||
				!l5ASTIdentifier(call.Args[4], "rootfs") {
				t.Error("prepared-Linux image prerequisite test may run only fixed read-only debugfs inspection")
			}
		case "LookPath":
			if len(call.Args) != 1 || !l5ASTString(call.Args[0], "debugfs") {
				t.Error("prepared-Linux image prerequisite test may look up only debugfs")
			}
		}
		return true
	})
	rootfsAssignments := 0
	debugfsCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, left := range value.Lhs {
				if !l5ASTIdentifier(left, "rootfs") {
					continue
				}
				rootfsAssignments++
				if len(value.Lhs) != len(value.Rhs) || !l5ASTPinnedRootfsCopy(value.Rhs[index]) {
					t.Error("prepared-Linux image prerequisite test must assign rootfs only from the verified private copy")
				}
			}
		case *ast.CallExpr:
			if !l5ASTIdentifier(value.Fun, "l5DebugfsCommand") {
				break
			}
			debugfsCalls++
			if len(value.Args) != 5 ||
				!l5ASTIdentifier(value.Args[0], "t") ||
				!l5ASTIdentifier(value.Args[1], "debugfs") ||
				!l5ASTIdentifier(value.Args[2], "rootfs") ||
				!l5ASTReadOnlyDebugfsOperation(value.Args[3]) {
				t.Error("prepared-Linux image prerequisite test may inspect only the pinned rootfs through stat/cat")
			}
		}
		return true
	})
	if commandContextCalls != 1 {
		t.Fatalf("prepared-Linux image prerequisite test debugfs command count = %d, want 1", commandContextCalls)
	}
	if rootfsAssignments != 1 {
		t.Fatalf("prepared-Linux image prerequisite test rootfs assignment count = %d, want 1", rootfsAssignments)
	}
	if debugfsCalls != 6 {
		t.Fatalf("prepared-Linux image prerequisite test inspect call count = %d, want 6", debugfsCalls)
	}
}

func l5ASTIdentifier(expression ast.Expr, want string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == want
}

func l5ASTString(expression ast.Expr, want string) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == want
}

func l5ASTPinnedRootfsCopy(expression ast.Expr) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok &&
		l5ASTIdentifier(call.Fun, "l5CopyVerifiedRootfsForInspection") &&
		len(call.Args) == 3 &&
		l5ASTIdentifier(call.Args[0], "t") &&
		l5ASTIdentifier(call.Args[1], "request") &&
		l5ASTSelector(call.Args[2], "verified", "Descriptor")
}

func l5ASTReadOnlyDebugfsOperation(expression ast.Expr) bool {
	return l5ASTIdentifier(expression, "l5DebugfsOperationStat") ||
		l5ASTIdentifier(expression, "l5DebugfsOperationCat")
}

func l5ASTSelector(expression ast.Expr, receiver string, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && l5ASTIdentifier(selector.X, receiver) && selector.Sel.Name == name
}

func TestL5PreparedLinuxImageInspectionBoundsUntrustedOutput(t *testing.T) {
	source := l5PreparedLinuxImagePrerequisiteSource(t)
	for _, required := range []string{
		"l5DebugfsOutputLimit",
		"context.WithTimeout",
		"exec.CommandContext",
		"io.LimitReader",
		"l5DebugfsOutputLimit+1",
		"command.Process.Kill()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("prepared-Linux image inspection missing bounded-output guard %q", required)
		}
	}
	if strings.Contains(source, ".CombinedOutput()") {
		t.Fatal("prepared-Linux image inspection buffers untrusted debugfs output")
	}
}

func TestL5PreparedLinuxImageInspectionPinsVerifiedRootfs(t *testing.T) {
	source := l5PreparedLinuxImagePrerequisiteSource(t)
	for _, required := range []string{
		"l5CopyVerifiedRootfsForInspection",
		"verified.Descriptor",
		"openRequestedDistributionRoot",
		"openDistributionFileNoFollow",
		"io.MultiWriter",
		"sha256.New",
		"rootfs.ext4",
		"l5DebugfsOperationStat",
		"l5DebugfsOperationCat",
		"l5DebugfsAllowedPaths",
		"l5DebugfsAllowedPaths[operation]",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("prepared-Linux image inspection missing verified-rootfs guard %q", required)
		}
	}
	for _, forbidden := range []string{"\"-w\"", "write /usr/bin/setpriv"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("prepared-Linux image inspection contains writable debugfs marker %q", forbidden)
		}
	}
}

func l5PreparedLinuxImagePrerequisiteSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join(
		"..",
		"internal",
		"sandboxruntime",
		"microvm",
		"assets",
		"localresolver",
		"l5_prepared_linux_integration_test.go",
	)
	return string(l5ReadRequiredFile(t, path))
}

func l5ReadRequiredFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read required L5 file %s: %v", filepath.Base(path), err)
	}
	return data
}

func l5WriteTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test file %s: %v", filepath.Base(path), err)
	}
}

func l5Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
