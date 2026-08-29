# Freestanding static Linux-amd64 _start for hal-guest-role-bootstrap.
# No libc, dynamic loader, Go runtime, allocator, TLS, signals, or threads.
# Pointers address only this image's read-only tokens, compiled launch-base
# filter, image-pinned role pathnames, or bounded stack objects. Child roles
# are selected only by the supervisor's closed argv token catalog. PID1 mode
# is image init (argc < 2). Native PID1 is the image-init supervisor.
# Go PID1 remains ForkExec-free. After shared identity preflight each role enters
# explicit remaining stages. PID1 attempts the exact D2 socket/bind/listen/
# dup3/close subset, then prctl(NO_NEW_PRIVS) and seccomp(SECCOMP_SET_MODE_FILTER)
# for launch-base, then exact clone3 plus pathname execve of image-pinned
# role children. Negative syscall results fail-closed. SCM_RIGHTS monitor-ready
# stays unimplemented and exit 127.

	.section .note.GNU-stack,"",@progbits
	.include "launch_base_filter.inc"
	.section .text
	.globl	_start
	.type	_start, @function
_start:
	movq	(%rsp), %rbx
	cmpq	$2, %rbx
	jb	.Lrole_pid1
	jne	.Lfail_closed
	movq	16(%rsp), %rsi
	testq	%rsi, %rsi
	jz	.Lfail_closed

	leaq	token_controller(%rip), %rdi
	call	exact_token
	testq	%rax, %rax
	jnz	.Lrole_controller

	leaq	token_agent(%rip), %rdi
	call	exact_token
	testq	%rax, %rax
	jnz	.Lrole_agent

	leaq	token_monitor(%rip), %rdi
	call	exact_token
	testq	%rax, %rax
	jnz	.Lrole_monitor

	leaq	token_workload_shim(%rip), %rdi
	call	exact_token
	testq	%rax, %rax
	jnz	.Lrole_workload_shim
	jmp	.Lfail_closed

.Lrole_pid1:
	movl	$1, %r12d
	jmp	.Lpreflight
.Lrole_controller:
	movl	$2, %r12d
	jmp	.Lpreflight
.Lrole_agent:
	movl	$3, %r12d
	jmp	.Lpreflight
.Lrole_monitor:
	movl	$4, %r12d
	jmp	.Lpreflight
.Lrole_workload_shim:
	movl	$5, %r12d

.Lpreflight:
	# Shared identity preflight uses only the documented native syscall
	# union. Live vsock proof, live cgroup fd 9, host-path exec, and
	# SCM_RIGHTS monitor-ready are not claimed.
	movq	$102, %rax		# getuid
	syscall
	movq	$107, %rax		# geteuid
	syscall
	movq	$104, %rax		# getgid
	syscall
	movq	$108, %rax		# getegid
	syscall

	subq	$64, %rsp
	movl	$0x20080522, (%rsp)	# _LINUX_CAPABILITY_VERSION_3
	movl	$0, 4(%rsp)		# pid 0
	movq	$125, %rax		# capget
	movq	%rsp, %rdi
	leaq	16(%rsp), %rsi
	syscall

	xorl	%edi, %edi		# pid 0
	movl	$7, %esi		# RLIMIT_NOFILE
	xorl	%edx, %edx		# new_limit NULL (read-only)
	leaq	48(%rsp), %r10		# old_limit
	movq	$302, %rax		# prlimit64
	syscall
	addq	$64, %rsp

	cmpl	$1, %r12d
	je	.Lpid1_vsock
	cmpl	$2, %r12d
	je	.Lcontroller_unimpl
	cmpl	$3, %r12d
	je	.Lagent_unimpl
	cmpl	$4, %r12d
	je	.Lmonitor_unimpl
	jmp	.Lshim_unimpl

.Lpid1_vsock:
	# PID1-only exact D2 listen-table subset. AF_VSOCK, CID any, ports
	# 1024/1025/1026, backlogs 64/1/4, then dup3 onto FDs 12/13/14.
	# Ports, backlogs, and FDs are compiled immediates. Any error
	# fail-closes. A successful bind is not live vsock proof.
	xorl	%ebx, %ebx
.Lpid1_vsock_loop:
	movq	$41, %rax		# socket
	movq	$40, %rdi		# AF_VSOCK
	movq	$0x80801, %rsi		# SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC
	xorl	%edx, %edx
	syscall
	testq	%rax, %rax
	js	.Lfail_closed
	movq	%rax, %r14

	movl	$1024, %r13d
	movl	$64, %r15d
	testq	%rbx, %rbx
	jz	.Lpid1_vsock_args
	movl	$1025, %r13d
	movl	$1, %r15d
	cmpq	$1, %rbx
	je	.Lpid1_vsock_args
	movl	$1026, %r13d
	movl	$4, %r15d
.Lpid1_vsock_args:
	subq	$16, %rsp
	movl	$40, (%rsp)		# svm_family=AF_VSOCK, svm_reserved1=0
	movl	%r13d, 4(%rsp)		# svm_port
	movl	$0xffffffff, 8(%rsp)	# svm_cid=VMADDR_CID_ANY
	movl	$0, 12(%rsp)		# svm_flags plus svm_zero

	movq	$49, %rax		# bind
	movq	%r14, %rdi
	movq	%rsp, %rsi
	movq	$16, %rdx
	syscall
	testq	%rax, %rax
	js	.Lfail_closed

	movq	$50, %rax		# listen
	movq	%r14, %rdi
	movq	%r15, %rsi
	syscall
	testq	%rax, %rax
	js	.Lfail_closed
	addq	$16, %rsp

	movl	$12, %esi
	testq	%rbx, %rbx
	jz	.Lpid1_vsock_dup
	movl	$13, %esi
	cmpq	$1, %rbx
	je	.Lpid1_vsock_dup
	movl	$14, %esi
.Lpid1_vsock_dup:
	movq	$292, %rax		# dup3
	movq	%r14, %rdi
	movq	$0x80000, %rdx		# O_CLOEXEC
	syscall
	testq	%rax, %rax
	js	.Lfail_closed

	movq	$3, %rax		# close
	movq	%r14, %rdi
	syscall
	testq	%rax, %rax
	js	.Lfail_closed

	incq	%rbx
	cmpq	$3, %rbx
	jb	.Lpid1_vsock_loop

	# Launch-base ancestor filter after a successful listen-table.
	# prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) then
	# seccomp(SECCOMP_SET_MODE_FILTER, 0, sock_fprog). The sock_fprog
	# lives on this stack and points at image RO filter bytes. Negative
	# results fail-closed. Exact clone3 plus pathname execve follow;
	# SCM_RIGHTS stays unimplemented.
.Lpid1_seccomp:
	movq	$157, %rax		# prctl
	movq	$38, %rdi		# PR_SET_NO_NEW_PRIVS
	movq	$1, %rsi
	xorl	%edx, %edx
	xorl	%r10d, %r10d
	xorl	%r8d, %r8d
	syscall
	testq	%rax, %rax
	js	.Lfail_closed

	subq	$16, %rsp
	movq	$0, (%rsp)
	movq	$0, 8(%rsp)
	movzwq	launch_base_filter_len(%rip), %rax
	movw	%ax, (%rsp)
	leaq	launch_base_filter(%rip), %rax
	movq	%rax, 8(%rsp)

	movq	$317, %rax		# seccomp
	movq	$1, %rdi		# SECCOMP_SET_MODE_FILTER
	xorl	%esi, %esi
	movq	%rsp, %rdx
	syscall
	testq	%rax, %rax
	js	.Lfail_closed
	addq	$16, %rsp

	# Exact clone3 of image-pinned role children after launch-base.
	# clone_args size is the pinned Go 1.25.7 ABI (88). pidfd pointer
	# is the clone_args.pidfd field. Negative clone3/execve results
	# fail-closed. Missing cgroup fd 9 or image path is not success.
.Lpid1_clone3:
	subq	$112, %rsp
	xorl	%ebx, %ebx
.Lpid1_clone3_loop:
	movl	$14, %ecx
	movq	%rsp, %r8
.Lpid1_clone3_zero:
	movq	$0, (%r8)
	addq	$8, %r8
	decl	%ecx
	jnz	.Lpid1_clone3_zero

	# Boot-only controller/agent: CLONE_VFORK|CLONE_VM|CLONE_PIDFD,
	# exit_signal=SIGCHLD, no namespace/cgroup flag.
	movq	$0x5100, %r13
	testq	%rbx, %rbx
	jz	.Lpid1_clone3_store
	cmpq	$1, %rbx
	je	.Lpid1_clone3_store
	# Monitor: CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD, SIGCHLD.
	movq	$0x25100, %r13
	cmpq	$2, %rbx
	je	.Lpid1_clone3_store
	# Shim: CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP,
	# exit_signal=SIGCHLD, cgroup=9, every other field zero.
	movq	$0x200005100, %r13
	movq	$9, 80(%rsp)
.Lpid1_clone3_store:
	movq	%r13, (%rsp)
	leaq	88(%rsp), %r13
	movq	%r13, 8(%rsp)
	movq	$17, 32(%rsp)
	movq	%rsp, %rdi
	movq	$88, %rsi
	movq	$435, %rax		# clone3
	syscall
	testq	%rax, %rax
	js	.Lfail_closed
	jz	.Lpid1_execve
	incq	%rbx
	cmpq	$4, %rbx
	jb	.Lpid1_clone3_loop
	addq	$112, %rsp
	jmp	.Lpid1_unimpl_scm_rights

.Lpid1_execve:
	# Pathname execve of the image-pinned Go role child. argv is the
	# closed path token only. envp is NULL. execve failure exits 127.
	leaq	path_controller(%rip), %rdi
	testq	%rbx, %rbx
	jz	.Lpid1_execve_do
	leaq	path_agent(%rip), %rdi
	cmpq	$1, %rbx
	je	.Lpid1_execve_do
	leaq	path_monitor(%rip), %rdi
	cmpq	$2, %rbx
	je	.Lpid1_execve_do
	leaq	path_shim(%rip), %rdi
.Lpid1_execve_do:
	movq	%rdi, 96(%rsp)
	movq	$0, 104(%rsp)
	leaq	96(%rsp), %rsi
	xorl	%edx, %edx
	movq	$59, %rax		# execve
	syscall
	jmp	.Lfail_closed

.Lpid1_unimpl_scm_rights:
	# Unimplemented: SCM_RIGHTS monitor-ready.
	jmp	.Lfail_closed

.Lcontroller_unimpl:
	# Unimplemented: pivot_root, cap drop, seccomp, execve.
	jmp	.Lfail_closed
.Lagent_unimpl:
	# Unimplemented: setresuid/setresgid, cap drop, execve.
	jmp	.Lfail_closed
.Lmonitor_unimpl:
	# Unimplemented: SCM_RIGHTS monitor-ready, execve.
	jmp	.Lfail_closed
.Lshim_unimpl:
	# Unimplemented: setns/ioctl, execveat.
	jmp	.Lfail_closed

.Lfail_closed:
	movq	$231, %rax		# exit_group
	movl	$127, %edi
	syscall
	jmp	.Lfail_closed

# exact_token compares rdi (read-only image token) to rsi (bounded stack
# candidate) without mutating the caller pointers. It is not a general
# argv/env/path parser and issues no syscall.
	.type	exact_token, @function
exact_token:
	movq	%rdi, %r8
	movq	%rsi, %r9
	movl	$32, %ecx
.Ltoken_loop:
	movzbl	(%r8), %eax
	movzbl	(%r9), %edx
	cmpl	%edx, %eax
	jne	.Ltoken_miss
	testl	%eax, %eax
	jz	.Ltoken_hit
	incq	%r8
	incq	%r9
	decl	%ecx
	jnz	.Ltoken_loop
.Ltoken_miss:
	xorl	%eax, %eax
	ret
.Ltoken_hit:
	movl	$1, %eax
	ret

	.section .rodata, "a", @progbits
	.type	token_controller, @object
token_controller:
	.asciz	"controller"
	.type	token_agent, @object
token_agent:
	.asciz	"agent"
	.type	token_monitor, @object
token_monitor:
	.asciz	"monitor"
	.type	token_workload_shim, @object
token_workload_shim:
	.asciz	"workload-shim"
	.type	path_controller, @object
path_controller:
	.asciz	"/usr/bin/hal-guest-credential-helper"
	.type	path_agent, @object
path_agent:
	.asciz	"/usr/bin/hal-guest-agent"
	.type	path_monitor, @object
path_monitor:
	.asciz	"/usr/bin/hal-guest-mount-monitor"
	.type	path_shim, @object
path_shim:
	.asciz	"/usr/bin/hal-guest-workload-shim"
