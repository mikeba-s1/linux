// SPDX-License-Identifier: GPL-2.0

#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/nospec-branch.h>

	.code64
	.section .text, "ax"

/* Called from rewritten BPF insns: preserve every register a BPF program can have live. */
SYM_FUNC_START(arch_bpf_pcpu_guard)
	ANNOTATE_NOENDBR

	pushq %rbp
	movq %rsp, %rbp

	/* r0-r5, stack argument 6, AX and the JIT's scratch register */
	pushq %rax
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11

	CALL_DEPTH_ACCOUNT
	call bpf_pcpu_guard

	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
	popq %rax

	leave
	RET
SYM_FUNC_END(arch_bpf_pcpu_guard)
