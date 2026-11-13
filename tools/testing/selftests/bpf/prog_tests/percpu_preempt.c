// SPDX-License-Identifier: GPL-2.0
/*
 * A run that uses this CPU's data while another task runs the same program on the CPU, see
 * progs/percpu_preempt.c. Task A (SCHED_OTHER) and task B (SCHED_FIFO) are pinned to one CPU; each
 * round A renames itself and its program signals B, which preempts A at once and renames itself.
 * A's per-CPU data must stay its own, and B's run must happen, after A's per-CPU section.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "percpu_preempt.skel.h"

#define NR_ROUNDS 20

struct ctx {
	int cpu;
	volatile int tid_b;
	volatile int renames_b;
	volatile int stop;
};

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set) ? -errno : 0;
}

static void *worker_b(void *arg)
{
	struct sched_param sp = { .sched_priority = 1 };
	struct ctx *c = arg;
	sigset_t set;

	if (pin_to_cpu(c->cpu) || sched_setscheduler(0, SCHED_FIFO, &sp)) {
		c->tid_b = -1;
		return NULL;
	}
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	c->tid_b = (int)syscall(SYS_gettid);
	while (!c->stop) {
		struct timespec ts = { .tv_nsec = 100 * 1000 * 1000 };

		if (sigtimedwait(&set, NULL, &ts) != SIGUSR1)
			continue;
		prctl(PR_SET_NAME, "percpu-b", 0, 0, 0);
		c->renames_b++;
	}
	return NULL;
}

static __u64 recursion_misses(struct bpf_program *prog)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len))
		return -1ULL;
	return info.recursion_misses;
}

static void run_subtest(const char *name)
{
	struct ctx c = { .cpu = sched_getcpu() };
	struct percpu_preempt *skel;
	struct bpf_program *prog;
	sigset_t set, oldset;
	bool started = false;
	pthread_t tb;
	int i, t;

	skel = percpu_preempt__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, "find prog"))
		goto out;
	bpf_program__set_autoload(prog, true);
	/* the prog array is initialized with it */
	bpf_program__set_autoload(skel->progs.tail_target, true);
	if (!ASSERT_OK(percpu_preempt__load(skel), "load"))
		goto out;
	if (!ASSERT_OK_PTR(bpf_program__attach(prog), "attach"))
		goto out;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &set, &oldset);
	if (!ASSERT_OK(pin_to_cpu(c.cpu), "pin A") ||
	    !ASSERT_OK(pthread_create(&tb, NULL, worker_b, &c), "create B"))
		goto restore;
	started = true;
	while (!c.tid_b)
		usleep(1000);
	if (!ASSERT_GT(c.tid_b, 0, "B setup"))
		goto restore;

	skel->bss->tid_b = c.tid_b;
	skel->bss->sig = SIGUSR1;
	skel->bss->tid_a = (int)syscall(SYS_gettid);
	for (i = 0; i < NR_ROUNDS; i++) {
		int before = c.renames_b;

		prctl(PR_SET_NAME, "percpu-a", 0, 0, 0);
		for (t = 0; t < 10000 && c.renames_b == before; t++)
			usleep(100);
	}
	skel->bss->tid_a = 0;
	skel->bss->tid_b = 0;

	ASSERT_EQ(skel->bss->sig_err, 0, "sig_err");
	ASSERT_EQ(skel->bss->runs_a, NR_ROUNDS, "runs_a");
	ASSERT_EQ(c.renames_b, NR_ROUNDS, "renames_b");
	ASSERT_EQ(skel->bss->corrupted, 0, "corrupted");
	ASSERT_EQ(skel->bss->b_inside_a, 0, "b_inside_a");
	ASSERT_EQ(skel->bss->runs_b, NR_ROUNDS, "runs_b");
	ASSERT_EQ(recursion_misses(prog), 0, "recursion_misses");
	if (prog == skel->progs.on_throw)
		ASSERT_EQ(skel->bss->thrown, 2 * NR_ROUNDS, "thrown");
	if (prog == skel->progs.on_may_goto)
		ASSERT_LT(skel->bss->a_spin_ns, 300 * 1000 * 1000ULL, "may_goto time slice");
restore:
	c.stop = 1;
	if (started)
		pthread_join(tb, NULL);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
out:
	percpu_preempt__destroy(skel);
}

void test_percpu_preempt(void)
{
	if (test__start_subtest("raw_tp"))
		run_subtest("on_raw_tp");
	if (test__start_subtest("fentry"))
		run_subtest("on_fentry");
	if (test__start_subtest("tp_syscall"))
		run_subtest("on_tp_syscall");
	if (test__start_subtest("pcpu_var"))
		run_subtest("on_pcpu_var");
	if (test__start_subtest("tail_call"))
		run_subtest("on_dispatch");
	if (test__start_subtest("throw"))
		run_subtest("on_throw");
	if (test__start_subtest("may_goto"))
		run_subtest("on_may_goto");
}
