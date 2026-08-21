package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const l8D6RuntimeOwnerSupervisorProtocolDocBlock = `const (
	l8RuntimeOwnerProtocolMagic = "HL8OWNR1"
	l8RuntimeOwnerProtocolVersion uint16 = 1
	l8RuntimeOwnerPacketHeaderSize = 24
	l8RuntimeOwnerPacketLimit = 512
	l8RuntimeOwnerHandshakeTimeout = 5 * time.Second

	l8RuntimeOwnerOpcodeReject uint16 = 0
	l8RuntimeOwnerOpcodeBootstrapStart uint16 = 1
	l8RuntimeOwnerOpcodeBootstrapPublished uint16 = 2
	l8RuntimeOwnerOpcodeChildArmed uint16 = 3
	l8RuntimeOwnerOpcodeChildRelease uint16 = 4
	l8RuntimeOwnerOpcodeHandshake uint16 = 5
	l8RuntimeOwnerOpcodeAbortStart uint16 = 6
	l8RuntimeOwnerOpcodeInspect uint16 = 7
	l8RuntimeOwnerOpcodeStopReap uint16 = 8
	l8RuntimeOwnerOpcodeAcquireNamespaces uint16 = 9
	l8RuntimeOwnerOpcodeFinalize uint16 = 10
	l8RuntimeOwnerOpcodeCommit uint16 = 11
	l8RuntimeOwnerOpcodeClose uint16 = 12

	l8RuntimeOwnerStatusOK uint16 = 0
	l8RuntimeOwnerStatusRejected uint16 = 1
	l8RuntimeOwnerStatusInvalidState uint16 = 2
	l8RuntimeOwnerStatusUncertain uint16 = 3
	l8RuntimeOwnerStatusUnsupported uint16 = 4
)

type l8RuntimeOwnerPacketHeaderV1 struct {
	Magic [8]byte
	Version uint16
	Opcode uint16
	Status uint16
	BodyLength uint16
	Sequence uint64
}`

func TestL8D6RuntimeOwnerSupervisorContractIsExact(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	if err := validateL8D6RuntimeOwnerSupervisorContract(doc); err != nil {
		t.Fatal(err)
	}
}

func validateL8D6RuntimeOwnerSupervisorContract(doc string) error {
	if strings.Count(doc, "```go\n"+l8D6RuntimeOwnerSupervisorProtocolDocBlock+"\n```") != 1 {
		return fmt.Errorf("L8 D6 runtime-owner supervisor protocol block is not exact")
	}
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, marker := range []string{
		"The default-off owner executable is exactly `hal-firecracker-runtime-owner`", "`supervise` and `child-gate`",
		"bootstrap `SOCK_SEQPACKET` socket as fd 3", "owner directory as fd 4",
		"configuration memfd as fd 5", "fd 6 then fd 7 in kernel-then-rootfs order",
		"Fd 8 is an already-open read-only handle to the stable owner-root",
		"`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`", "read exactly 32 bytes by `pread`",
		"user-namespace, network-namespace, kernel, and rootfs order",
		"`[resolved-binary-path, \"supervise\"]`", "`[resolved-binary-path, \"child-gate\"]`",
		"user, network, kernel, and rootfs sources from fds 5, 6, 7, and 8",
		"collision-free private `F_DUPFD_CLOEXEC` temporaries at fd 9 or higher",
		"maps those temporaries to fds 3, 4, 5, and 6 with `dup3`",
		"exact namespace wrapper through `execve`",
		"`F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`",
		"regular anonymous zero-link descriptors with `FD_CLOEXEC`",
		"exactly two `SCM_RIGHTS` descriptors in user-then-network order",
		"`NSFS_MAGIC`", "sets `FD_CLOEXEC`", "sequence starts at one",
		"byte-identical body plus fresh duplicates", "current one-use secret in that order",
		"`SO_PEERCRED`", "direct-child `Wait`", "double-`/proc` absence",
		"No packet transports an absence proof", "Finalize is accepted only",
		"atomically persists `finalizing`", "only then persists `finalized`",
		"Commit is accepted only for `finalized`", "Controller Close is distinct",
		"requires its observed parent PID to be exactly one",
		"stable owner-root HMAC key is not a per-runtime artifact",
		"Non-Linux builds return exit code 127 before reading an inherited descriptor",
	} {
		if !strings.Contains(normalized, marker) {
			return fmt.Errorf("L8 D6 supervisor contract omits %q", marker)
		}
	}
	return nil
}

func TestL8D6RuntimeOwnerSupervisorContractMutationGuards(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, mutation := range []struct{ name, before, after string }{
		{"stream socket", "daemon bootstrap\n`SOCK_SEQPACKET` socket as fd 3", "daemon bootstrap stream socket as fd 3"},
		{"namespace order", "user-then-network order", "network-then-user order"},
		{"reusable secret", "current one-use secret in\nthat order", "current reusable secret in that order"},
		{"proof packet", "No packet transports an absence proof", "A packet may transport an absence proof"},
		{"close implies finalization", "Controller Close is distinct", "Controller Close finalizes the runtime"},
		{"default command", "The default-off owner executable is exactly", "The default-wired owner executable is exactly"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if strings.Count(doc, mutation.before) == 0 {
				t.Fatalf("missing mutation source %q", mutation.before)
			}
			if err := validateL8D6RuntimeOwnerSupervisorContract(strings.ReplaceAll(doc, mutation.before, mutation.after)); err == nil {
				t.Fatal("weakened supervisor contract passed")
			}
		})
	}
}

func TestL8D6RuntimeOwnerSupervisorExecutableIsIsolated(t *testing.T) {
	allowed := map[string]bool{
		filepath.ToSlash(filepath.Join("cmd", "hal-firecracker-runtime-owner", "main.go")):                                            true,
		filepath.ToSlash(filepath.Join("internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_runtime_owner_executable.go")): true,
	}
	uses := 0
	declarations := 0
	calls := 0
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source := readL8CredentialDeliveryFile(t, path)
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if parseErr != nil {
			return parseErr
		}
		relative, relErr := filepath.Rel("..", path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncDecl:
				if value.Name.Name == "RunPrivateL8RuntimeOwnerExecutable" {
					declarations++
					if relative != filepath.ToSlash(filepath.Join("internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_runtime_owner_executable.go")) {
						t.Errorf("private owner executable declaration in %s", relative)
					}
				}
			case *ast.CallExpr:
				name := ""
				switch called := value.Fun.(type) {
				case *ast.Ident:
					name = called.Name
				case *ast.SelectorExpr:
					name = called.Sel.Name
				}
				if name == "RunPrivateL8RuntimeOwnerExecutable" {
					calls++
					if relative != filepath.ToSlash(filepath.Join("cmd", "hal-firecracker-runtime-owner", "main.go")) {
						t.Errorf("private owner executable called from %s", relative)
					}
				}
			}
			return true
		})
		if strings.Contains(source, "RunPrivateL8RuntimeOwnerExecutable") {
			uses++
			if !allowed[relative] {
				t.Errorf("private owner executable wired from %s", relative)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if uses != 2 {
		t.Fatalf("private owner executable production references = %d, want 2", uses)
	}
	if declarations != 1 || calls != 1 {
		t.Fatalf("private owner executable AST declarations/calls = %d/%d, want 1/1", declarations, calls)
	}
}
