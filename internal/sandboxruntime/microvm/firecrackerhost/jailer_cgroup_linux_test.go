//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestJailerCgroupLinuxRefusesOrdinaryFilesystem(t *testing.T) {
	for _, path := range []string{"", "/", t.TempDir(), "/proc"} {
		fs, err := newLinuxJailerCgroupFilesystem(path)
		if err == nil || fs != nil {
			if fs != nil {
				_ = fs.close()
			}
			t.Fatalf("ordinary anchor accepted: %q", path)
		}
	}
}

func TestJailerCgroupLinuxDirectoryOwnershipAndIdentity(t *testing.T) {
	valid := unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: 0, Dev: 10, Ino: 20}
	if !validLinuxJailerCgroupDirectory(valid) {
		t.Fatal("valid root-owned observation rejected")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1000 }, func(s *unix.Stat_t) { s.Mode |= 0o020 }, func(s *unix.Stat_t) { s.Mode |= 0o002 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0o755 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0o700 }} {
		bad := valid
		change(&bad)
		if validLinuxJailerCgroupDirectory(bad) {
			t.Fatal("unsafe owner/type/mode accepted")
		}
	}
	before := linuxJailerCgroupNode{stat: valid, fsType: unix.CGROUP2_SUPER_MAGIC}
	for _, change := range []func(*linuxJailerCgroupNode){func(n *linuxJailerCgroupNode) { n.stat.Dev++ }, func(n *linuxJailerCgroupNode) { n.stat.Ino++ }, func(n *linuxJailerCgroupNode) { n.stat.Uid++ }, func(n *linuxJailerCgroupNode) { n.stat.Gid++ }, func(n *linuxJailerCgroupNode) { n.stat.Mode++ }, func(n *linuxJailerCgroupNode) { n.fsType++ }} {
		after := before
		change(&after)
		if sameLinuxJailerCgroupNode(before, after) {
			t.Fatal("changed retained identity accepted")
		}
	}
}

func TestJailerCgroupExistingStarterConsumesExactLaunchFD(t *testing.T) {
	for _, name := range []string{"valid", "missing", "wrong runtime", "late cancellation"} {
		t.Run(name, func(t *testing.T) {
			network, writer := atomicJailerTestPipe(t)
			_ = writer.Close()
			defer network.Close()
			request := atomicJailerTestPlan(t, "run-alpha").processRequest()
			lease := testJailerCgroupLease(t, "run-alpha")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			var usedFD int
			starter := OSExecNamespaceProcessStarter{startCommand: func(command *exec.Cmd) error {
				calls++
				if command.SysProcAttr == nil || !command.SysProcAttr.UseCgroupFD || len(command.ExtraFiles) != 0 || len(command.Env) != 0 {
					t.Fatal("uncontained or inherited-FD launch")
				}
				usedFD = command.SysProcAttr.CgroupFD
				flags, err := unix.FcntlInt(uintptr(usedFD), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("missing live CLOEXEC duplicate")
				}
				armStrictJailerParentDeathSignal(command)
				if !command.SysProcAttr.UseCgroupFD || command.SysProcAttr.CgroupFD != usedFD || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
					t.Fatal("parent-death erased placement")
				}
				if name == "late cancellation" {
					cancel()
				}
				return errors.New("injected clone refusal")
			}}
			if name == "missing" {
				lease = nil
			}
			if name == "wrong runtime" {
				lease.request.runtimeID = "other"
			}
			_, err := starter.startStrictJailerNamespaceProcess(ctx, strictJailerNamespaceProcessStartRequest{executable: request.Executable, args: request.Args, networkNamespace: network, executables: strictJailerTestExecutablePair(t, request.Executable, request.Args[3]), cgroup: lease})
			if err == nil {
				t.Fatal("clone refusal returned success")
			}
			expected := 1
			if name == "missing" || name == "wrong runtime" {
				expected = 0
			}
			if calls != expected {
				t.Fatalf("start calls=%d", calls)
			}
			if calls > 0 {
				if _, err := unix.FcntlInt(uintptr(usedFD), unix.F_GETFD, 0); err == nil {
					t.Fatal("launch duplicate leaked")
				}
			}
		})
	}
}

func TestJailerCgroupPlacementRejectsClosedOrNonCLOEXECDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fd := reader.Fd()
	if _, err := unix.FcntlInt(fd, unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if configureStrictJailerCgroup(&exec.Cmd{}, reader) == nil {
		t.Fatal("inheritable cgroup FD accepted")
	}
	_ = reader.Close()
	if configureStrictJailerCgroup(&exec.Cmd{}, reader) == nil {
		t.Fatal("closed cgroup FD accepted")
	}
}
