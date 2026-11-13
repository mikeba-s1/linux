// SPDX-License-Identifier: GPL-2.0
/*
 * Per-CPU data of a run while another task runs the same program on the same CPU.
 *
 * Task A fills this CPU's scratch buffer, wakes task B (SCHED_FIFO, same CPU) with a signal, and
 * checks its buffer. B renames itself, which runs the program again on the CPU. A must find its
 * own data, and B must run (after A's per-CPU section, not inside it).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_task(struct task_struct *task, int sig, enum pid_type type, u64 value) __ksym;

struct scratch_buf {
	__u64 v[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct scratch_buf);
} scratch SEC(".maps");

__u64 pv[8] SEC(".percpu");

int tid_a;
int tid_b;
int sig;
int runs_a;
int runs_b;
int b_inside_a;
int corrupted;
int sig_err;
int thrown;
__u64 a_spin_ns;

static void signal_b(void)
{
	struct task_struct *task;

	bpf_rcu_read_lock();
	task = bpf_task_from_pid(tid_b);
	if (!task) {
		sig_err = 1;
		bpf_rcu_read_unlock();
		return;
	}
	if (bpf_send_signal_task(task, sig, PIDTYPE_PID, 0))
		sig_err = 1;
	bpf_task_release(task);
	bpf_rcu_read_unlock();
}

static __always_inline void fill(__u64 *v, __u32 tid)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < 8; i++)
		v[i] = ((__u64)tid << 32) | i;
}

static __always_inline void check(const __u64 *v)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

#pragma clang loop unroll(full)
	for (int i = 0; i < 8; i++) {
		if (v[i] != (((__u64)tid << 32) | i)) {
			corrupted++;
			break;
		}
	}
}

/* A: fill, let B in, check. B: fill. */
static __always_inline int body(__u64 *v)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	int runs_b_before;

	fill(v, tid);
	if (tid != tid_a) {
		runs_b++;
		return 0;
	}
	runs_a++;
	runs_b_before = *(volatile int *)&runs_b;
	signal_b();
	if (*(volatile int *)&runs_b != runs_b_before)
		b_inside_a++;
	check(v);
	return 0;
}

static __always_inline int map_body(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct scratch_buf *b;
	int zero = 0;

	if (tid != tid_a && tid != tid_b)
		return 0;
	b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;
	return body(b->v);
}

SEC("?raw_tp/task_rename")
int on_raw_tp(void *ctx)
{
	return map_body();
}

SEC("?fentry/__set_task_comm")
int BPF_PROG(on_fentry)
{
	return map_body();
}

SEC("?tp/syscalls/sys_enter_prctl")
int on_tp_syscall(void *ctx)
{
	return map_body();
}

SEC("?raw_tp/task_rename")
int on_pcpu_var(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (tid != tid_a && tid != tid_b)
		return 0;
	return body(pv);
}

/* the dispatcher touches no per-CPU data, its tail-call target does */
SEC("?raw_tp")
int tail_target(void *ctx)
{
	return map_body();
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__array(values, int (void *));
} jmp SEC(".maps") = {
	.values = { [0] = (void *)&tail_target },
};

SEC("?raw_tp/task_rename")
int on_dispatch(void *ctx)
{
	bpf_tail_call(ctx, &jmp, 0);
	return 0;
}

SEC("?raw_tp/task_rename")
int on_throw(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (tid != tid_a && tid != tid_b)
		return 0;
	map_body();
	thrown++;
	bpf_throw(0);
	return 0;
}

#define timed_can_loop ({ __label__ l_break, l_continue; bool ret = true;	\
	asm volatile goto("may_goto %l[l_break]" :::: l_break);			\
	goto l_continue;							\
	l_break: ret = false;							\
	l_continue:;								\
	ret; })

/* A spins on may_goto and lets B in 100 ms into its time slice: B must not renew it */
SEC("?raw_tp/task_rename")
int on_may_goto(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 start, iters = 0;
	int runs_b_before;
	bool sent = false;

	if (tid == tid_b) {
		runs_b++;
		return 0;
	}
	if (tid != tid_a)
		return 0;
	runs_a++;
	runs_b_before = *(volatile int *)&runs_b;
	start = bpf_ktime_get_ns();
	while (timed_can_loop) {
		iters++;
		if (!sent && !(iters & 0xffff) && bpf_ktime_get_ns() - start > 100000000ULL) {
			sent = true;
			signal_b();
		}
	}
	a_spin_ns = bpf_ktime_get_ns() - start;
	if (*(volatile int *)&runs_b != runs_b_before)
		b_inside_a++;
	return 0;
}
