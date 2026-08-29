package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

const (
	nativeSourceRel      = "tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S"
	nativeCallsitesRel   = "tools/microvm/l8/role-bootstrap/callsites.v1"
	launchBaseFilterRel  = "tools/microvm/l8/role-bootstrap/launch_base_filter.inc"
	policyArtifactRel    = "tools/microvm/l8/policy/verified-syscall-policy.hl8q"
	policyDigestRel      = "tools/microvm/l8/policy/verified-syscall-policy.hl8q.sha256"
	generatedArtifactRel = "internal/sandboxruntime/microvm/guestagent/rolebootstrap/generated_artifact_d7_gen.go"
	sourceDomain         = "hal/l8/native-role-bootstrap-source/linux-amd64/v1"
	callsiteDomain       = "hal/l8/native-role-bootstrap-callsites/linux-amd64/v1"
	installTableDomain   = "hal/l8/d4-native-install-table/linux-amd64/v1"
	callsiteFormat       = "hal-l8-native-callsite-inventory-v1"
)

type nativeCallsite struct {
	index   int
	name    string
	number  uint32
	scope   string
	insnHex string
}

type generatedIdentities struct {
	source             []byte
	filter             []byte
	policySHA256       [32]byte
	sourceSHA256       [32]byte
	callsiteSHA256     [32]byte
	installTableSHA256 [32]byte
}

func (identities generatedIdentities) files() map[string][]byte {
	return map[string][]byte{
		generatedArtifactRel: identities.source,
		launchBaseFilterRel:  identities.filter,
	}
}

func main() {
	rootFlag := flag.String("root", "", "repository root (defaults to discovery from the current directory)")
	check := flag.Bool("check", false, "verify checked-in outputs without writing")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		var err error
		root, err = discoverRepositoryRoot()
		if err != nil {
			fatal(err)
		}
	}
	identities, err := generate(root)
	if err != nil {
		fatal(err)
	}
	if *check {
		if err := checkFileMap(root, identities.files()); err != nil {
			fatal(err)
		}
		return
	}
	if err := writeFileMap(root, identities.files()); err != nil {
		fatal(err)
	}
}

func generate(root string) (generatedIdentities, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("resolve root: %w", err)
	}
	policySHA256, err := readDigestFile(filepath.Join(root, policyDigestRel))
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("issued policy identity: %w", err)
	}
	policyBytes, err := readBounded(filepath.Join(root, policyArtifactRel), 1<<22)
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("issued policy artifact: %w", err)
	}
	compiled, err := syscallpolicy.CompileIssuedRoleFilter(policyBytes, policySHA256, syscallpolicy.RoleLaunchBase)
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("compile launch-base filter: %w", err)
	}
	filterBytes := encodeLaunchBaseFilterInc(compiled)
	sourceBytes, err := readBounded(filepath.Join(root, nativeSourceRel), 1<<20)
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("native source: %w", err)
	}
	callsiteBytes, err := readBounded(filepath.Join(root, nativeCallsitesRel), 1<<20)
	if err != nil {
		return generatedIdentities{}, fmt.Errorf("native callsite inventory: %w", err)
	}
	if err := validateNativeSource(sourceBytes); err != nil {
		return generatedIdentities{}, err
	}
	if err := validateCallsiteInventory(callsiteBytes); err != nil {
		return generatedIdentities{}, err
	}
	sourceSHA256 := framedSHA256(sourceDomain, encodeNativeSourcePreimage(nativeSourceRel, sourceBytes))
	callsiteSHA256 := framedSHA256(callsiteDomain, callsiteBytes)
	installTableSHA256 := nativeInstallTableSHA256()
	source, err := encodeGeneratedArtifactSource(policySHA256, sourceSHA256, callsiteSHA256, installTableSHA256)
	if err != nil {
		return generatedIdentities{}, err
	}
	return generatedIdentities{
		source:             source,
		filter:             filterBytes,
		policySHA256:       policySHA256,
		sourceSHA256:       sourceSHA256,
		callsiteSHA256:     callsiteSHA256,
		installTableSHA256: installTableSHA256,
	}, nil
}

func exactNativeCallsites() []nativeCallsite {
	return []nativeCallsite{
		{index: 0, name: "getuid", number: 102, scope: "shared", insnHex: "0f05"},
		{index: 1, name: "geteuid", number: 107, scope: "shared", insnHex: "0f05"},
		{index: 2, name: "getgid", number: 104, scope: "shared", insnHex: "0f05"},
		{index: 3, name: "getegid", number: 108, scope: "shared", insnHex: "0f05"},
		{index: 4, name: "capget", number: 125, scope: "shared", insnHex: "0f05"},
		{index: 5, name: "prlimit64", number: 302, scope: "shared", insnHex: "0f05"},
		{index: 6, name: "socket", number: 41, scope: "pid1", insnHex: "0f05"},
		{index: 7, name: "bind", number: 49, scope: "pid1", insnHex: "0f05"},
		{index: 8, name: "listen", number: 50, scope: "pid1", insnHex: "0f05"},
		{index: 9, name: "dup3", number: 292, scope: "pid1", insnHex: "0f05"},
		{index: 10, name: "close", number: 3, scope: "pid1", insnHex: "0f05"},
		{index: 11, name: "prctl", number: 157, scope: "pid1", insnHex: "0f05"},
		{index: 12, name: "seccomp", number: 317, scope: "pid1", insnHex: "0f05"},
		{index: 13, name: "clone3", number: 435, scope: "pid1", insnHex: "0f05"},
		{index: 14, name: "execveat", number: 322, scope: "pid1", insnHex: "0f05"},
		{index: 15, name: "recvmsg", number: 47, scope: "pid1", insnHex: "0f05"},
		{index: 16, name: "exit_group", number: 231, scope: "shared", insnHex: "0f05"},
	}
}

func exactD4InstallBindings() [5][3]byte {
	return [5][3]byte{
		{1, 1, 1},
		{2, 3, 1},
		{3, 5, 1},
		{4, 7, 1},
		{5, 9, 1},
	}
}

func nativeInstallTableSHA256() [32]byte {
	bindings := exactD4InstallBindings()
	preimage := make([]byte, 4+len(bindings)*4)
	binary.BigEndian.PutUint16(preimage[:2], uint16(len(bindings)))
	for index, binding := range bindings {
		offset := 4 + index*4
		preimage[offset] = binding[0]
		preimage[offset+1] = binding[1]
		preimage[offset+2] = binding[2]
	}
	return framedSHA256(installTableDomain, preimage)
}

func encodeNativeSourcePreimage(path string, encoded []byte) []byte {
	preimage := new(bytes.Buffer)
	normalized := filepath.ToSlash(path)
	writeUint16(preimage, uint16(len(normalized)))
	preimage.WriteString(normalized)
	writeUint64(preimage, uint64(len(encoded)))
	preimage.Write(encoded)
	return preimage.Bytes()
}

func validateNativeSource(encoded []byte) error {
	if len(encoded) == 0 || bytes.ContainsRune(encoded, '\r') {
		return errors.New("native source must be nonempty LF-only bytes")
	}
	want := exactNativeCallsites()
	count := bytes.Count(encoded, []byte("\tsyscall\n"))
	if count != len(want) {
		return fmt.Errorf("native source has %d syscall instructions, want %d", count, len(want))
	}
	for _, required := range []string{
		".Lpid1_vsock:",
		".Lpid1_seccomp:",
		".Lpid1_clone3:",
		".Lpid1_execveat:",
		".Lpid1_scm_rights:",
		".Lcontroller_unimpl:",
		".Lagent_unimpl:",
		".Lmonitor_unimpl:",
		".Lshim_unimpl:",
		".Lfail_closed:",
		"movq\t$157, %rax",
		"movq\t$317, %rax",
		"movq\t$435, %rax",
		"movq\t$322, %rax",
		"movq\t$47, %rax",
		"movq\t$16, %rdi",
		"movq\t$0x40000040, %rdx",
		"movq\t$88, %rsi",
		"movq\t$0x5100, %r13",
		"movq\t$0x25100, %r13",
		"movq\t$0x200005100, %r13",
		"movq\t$9, 80(%rsp)",
		"movq\t$17, 32(%rsp)",
		"movq\t$5, %rdi",
		"movq\t$6, %rdi",
		"movq\t$0x1000, %r8",
		"empty_path",
		"launch_base_filter",
	} {
		if !bytes.Contains(encoded, []byte(required)) {
			return fmt.Errorf("native source is missing fail-closed stage label %s", required)
		}
	}
	for _, forbidden := range []string{
		"__libc", "main.main", "runtime.main", "dlopen", "getenv", "malloc",
		"movq\t$59, %rax", // pathname execve
		"movq\t$46, %rax", // sendmsg
		"movl\t$0, %edi",
		"/usr/bin/hal-guest-credential-helper",
		"/usr/bin/hal-guest-agent",
		"/usr/bin/hal-guest-mount-monitor",
		"/usr/bin/hal-guest-workload-shim",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			return fmt.Errorf("native source contains forbidden marker %q", forbidden)
		}
	}
	return nil
}

func validateCallsiteInventory(encoded []byte) error {
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.ContainsRune(encoded, '\r') {
		return errors.New("callsite inventory must end in one LF and contain no CR")
	}
	lines := strings.Split(string(encoded[:len(encoded)-1]), "\n")
	want := exactNativeCallsites()
	if len(lines) != 2+len(want) {
		return fmt.Errorf("callsite inventory has %d lines, want %d", len(lines), 2+len(want))
	}
	if lines[0] != "format="+callsiteFormat {
		return errors.New("callsite inventory format is not the exact native catalog")
	}
	if lines[1] != fmt.Sprintf("count=%d", len(want)) {
		return errors.New("callsite inventory count does not match the exact native catalog")
	}
	for index, site := range want {
		wantLine := fmt.Sprintf("%d=%s:%d:%s:%s", site.index, site.name, site.number, site.scope, site.insnHex)
		if lines[index+2] != wantLine {
			return fmt.Errorf("callsite inventory row %d is not the exact native catalog", index)
		}
	}
	return nil
}

func encodeGeneratedArtifactSource(policy, source, callsite, install [32]byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("// Code generated by tools/microvm/l8/role-bootstrap/generate; DO NOT EDIT.\n")
	buf.WriteString("//go:build l8_verified_native_artifact\n\n")
	buf.WriteString("package rolebootstrap\n\n")
	fmt.Fprintf(&buf, "var embeddedNativePolicySHA256 = %#v\n\n", policy)
	fmt.Fprintf(&buf, "var embeddedNativeSourceSHA256 = %#v\n\n", source)
	fmt.Fprintf(&buf, "var embeddedNativeCallsiteSHA256 = %#v\n\n", callsite)
	fmt.Fprintf(&buf, "var embeddedNativeInstallTableSHA256 = %#v\n\n", install)
	buf.WriteString("func EmbeddedGeneratedArtifact() (GeneratedArtifact, error) {\n")
	buf.WriteString("\treturn NewGeneratedArtifact(embeddedNativePolicySHA256, embeddedNativeSourceSHA256, embeddedNativeCallsiteSHA256, embeddedNativeInstallTableSHA256)\n")
	buf.WriteString("}\n")
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated native artifact source: %w", err)
	}
	return formatted, nil
}

func encodeLaunchBaseFilterInc(filter syscallpolicy.CompiledFilter) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Code generated by tools/microvm/l8/role-bootstrap/generate; DO NOT EDIT.\n")
	buf.WriteString("\t.section .rodata, \"a\", @progbits\n")
	buf.WriteString("\t.align 8\n")
	buf.WriteString("\t.type\tlaunch_base_filter, @object\n")
	buf.WriteString("launch_base_filter:\n")
	for _, insn := range filter.Instructions() {
		fmt.Fprintf(&buf, "\t.short\t0x%04x\n", insn.Code)
		fmt.Fprintf(&buf, "\t.byte\t%d\n", insn.Jt)
		fmt.Fprintf(&buf, "\t.byte\t%d\n", insn.Jf)
		fmt.Fprintf(&buf, "\t.long\t0x%08x\n", insn.K)
	}
	buf.WriteString("\t.size\tlaunch_base_filter, .-launch_base_filter\n")
	buf.WriteString("\t.type\tlaunch_base_filter_len, @object\n")
	buf.WriteString("launch_base_filter_len:\n")
	fmt.Fprintf(&buf, "\t.short\t%d\n", filter.Len())
	return buf.Bytes()
}

func discoverRepositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("repository root not found")
		}
		current = parent
	}
}

func readBounded(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("file %s has an invalid read bound", path)
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() || initial.Size() <= 0 || initial.Size() > maximum {
		return nil, fmt.Errorf("file %s is outside bounds", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open no-follow %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open no-follow %s returned no file", path)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > maximum || !os.SameFile(initial, opened) {
		return nil, fmt.Errorf("file %s changed identity or is outside bounds", path)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(encoded)) != opened.Size() || int64(len(encoded)) > maximum {
		return nil, fmt.Errorf("file %s changed size or has trailing bytes", path)
	}
	return encoded, nil
}

func readDigestFile(path string) ([32]byte, error) {
	encoded, err := readBounded(path, 65)
	if err != nil {
		return [32]byte{}, err
	}
	if len(encoded) != 65 || encoded[64] != '\n' {
		return [32]byte{}, errors.New("digest file must be 64 lowercase hexadecimal bytes plus LF")
	}
	return parseDigest(string(encoded[:64]))
}

func parseDigest(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != 64 || strings.ToLower(value) != value {
		return result, errors.New("digest must be 64 lowercase hexadecimal bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, errors.New("digest must be lowercase hexadecimal")
	}
	copy(result[:], decoded)
	if result == ([32]byte{}) {
		return [32]byte{}, errors.New("digest must be nonzero")
	}
	return result, nil
}

func framedSHA256(domain string, preimage []byte) [32]byte {
	encoded := make([]byte, 2, 2+len(domain)+len(preimage))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(domain)))
	encoded = append(encoded, domain...)
	encoded = append(encoded, preimage...)
	return sha256.Sum256(encoded)
}

func writeUint16(buffer *bytes.Buffer, value uint16) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func checkFileMap(root string, files map[string][]byte) error {
	for path, want := range files {
		if len(want) == 0 {
			return fmt.Errorf("native identity output %s is unexpectedly empty", path)
		}
		got, err := readBounded(filepath.Join(root, path), int64(len(want)))
		if err != nil {
			return fmt.Errorf("read output %s: %w", path, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("native identity output %s is stale", path)
		}
	}
	return nil
}

func writeFileMap(root string, files map[string][]byte) error {
	for path, encoded := range files {
		absolute := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		temporary, err := os.CreateTemp(filepath.Dir(absolute), ".l8-d7-native-*")
		if err != nil {
			return fmt.Errorf("create temporary output: %w", err)
		}
		temporaryPath := temporary.Name()
		cleanup := func() { _ = os.Remove(temporaryPath) }
		if _, err := temporary.Write(encoded); err != nil {
			_ = temporary.Close()
			cleanup()
			return fmt.Errorf("write temporary output: %w", err)
		}
		if err := temporary.Chmod(0o644); err != nil {
			_ = temporary.Close()
			cleanup()
			return fmt.Errorf("chmod temporary output: %w", err)
		}
		if err := temporary.Close(); err != nil {
			cleanup()
			return fmt.Errorf("close temporary output: %w", err)
		}
		if err := os.Rename(temporaryPath, absolute); err != nil {
			cleanup()
			return fmt.Errorf("replace output %s: %w", path, err)
		}
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "l8 native role-bootstrap identity generation failed:", err)
	os.Exit(1)
}
