// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
int bpf_send_signal_task(struct task_struct *task, int sig, enum pid_type type, u64 value) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} wakeup_map SEC(".maps");

int tid_a;
int tid_b;
int sig;
int runs_a;
int runs_b;
int sig_err;
int stack_corrupt;

static __always_inline void fill_stack(__u64 *buf, __u32 tid)
{
	#pragma unroll
	for (int i = 0; i < 8; i++)
		buf[i] = ((__u64)tid << 32) | (0x5a5a0000U + i);
}

static __always_inline void check_stack(const __u64 *buf, __u32 tid)
{
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		if (buf[i] != (((__u64)tid << 32) | (0x5a5a0000U + i)))
			stack_corrupt = 1;
	}
}

static void signal_worker_b(void)
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

static __always_inline int handle_comm(bool via_map)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 stack_buf[8];
	int zero = 0;

	if (tid != tid_a && tid != tid_b)
		return 0;

	fill_stack(stack_buf, tid);
	asm volatile("" : "+m"(stack_buf));

	if (tid == tid_a) {
		runs_a++;
		if (via_map)
			bpf_map_delete_elem(&wakeup_map, &zero);
		else
			signal_worker_b();
	} else {
		runs_b++;
	}

	asm volatile("" : "+m"(stack_buf));
	check_stack(stack_buf, tid);
	return 0;
}

SEC("fentry/__set_task_comm")
int BPF_PROG(on_fentry)
{
	return handle_comm(false);
}

SEC("fexit/__set_task_comm")
int BPF_PROG(on_fexit)
{
	return handle_comm(false);
}

SEC("fentry.s/" SYS_PREFIX "sys_prctl")
int BPF_PROG(on_fentry_s)
{
	return handle_comm(false);
}

SEC("fexit.s/" SYS_PREFIX "sys_prctl")
int BPF_PROG(on_fexit_s)
{
	return handle_comm(false);
}

SEC("fentry/htab_map_delete_elem")
int BPF_PROG(on_wakeup_delete, struct bpf_map *map)
{
	if (map == (struct bpf_map *)&wakeup_map)
		signal_worker_b();
	return 0;
}

SEC("raw_tp/task_rename")
int BPF_PROG(on_raw_tp)
{
	return handle_comm(true);
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(on_raw_tp_s, struct pt_regs *regs, long id)
{
	if (id != __NR_prctl)
		return 0;
	return handle_comm(true);
}
