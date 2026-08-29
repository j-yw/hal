# Freestanding static Linux-amd64 _start for hal-guest-role-bootstrap.
# No libc, dynamic loader, Go runtime, allocator, TLS, signals, or threads.
# Pointers address only this image's read-only tokens or bounded stack objects.
# Child roles are selected only by the supervisor's closed argv token catalog.
# PID1 mode is image init (argc < 2). Live supervisor behavior is unimplemented.

	.section .note.GNU-stack,"",@progbits
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
.Lrole_controller:
.Lrole_agent:
.Lrole_monitor:
.Lrole_workload_shim:
	# Shared preflight uses only the documented native syscall union, then
	# fail-closes. Live vsock/clone3/seccomp/execve paths are not implemented.
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
