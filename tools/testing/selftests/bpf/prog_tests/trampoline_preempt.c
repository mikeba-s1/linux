// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "trampoline_preempt.skel.h"

#define NR_ROUNDS 20

/* The kernel's own "not supported" error, which the libc headers don't have */
#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

/*
 * Threads A and B are pinned to one CPU. B is SCHED_FIFO and waits for a signal:
 *
 *   A: prctl() -> enters the program under test
 *                 the program sends B the signal
 *   B:            wakes up and preempts A, which is still inside the program
 *                 prctl() -> enters the same program on the same CPU
 *
 * A program without per-CPU state runs for B too, while A is preempted inside
 * it. A program with per-CPU state runs with preemption disabled: B wakes up
 * only when A has left the program, and then runs it. A sleepable program has
 * to disable preemption itself, so B runs inside it too.
 */

/* The per-CPU state that a program touches, see progs/trampoline_preempt.c */
enum { NO_PERCPU, PERCPU_MAP, PERCPU_VAR, THIS_CPU_PTR, CPU_ID };

enum expect {
	B_RUNS,		/* B runs the program while A is preempted inside it */
	B_AFTER,	/* B runs the program after A has left it */
};

/* What threads A and B share */
struct ctx {
	struct trampoline_preempt *skel;
	sigset_t sigset;
	int cpu, err_a, err_b;
	int overlaps;	/* rounds in which B found A still inside the program */
};

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set) ? -errno : 0;
}

/* A enters the program under test, which wakes B from inside it */
static void *worker_a(void *arg)
{
	struct ctx *c = arg;
	int i;

	c->err_a = pin_to_cpu(c->cpu);
	c->skel->bss->tid_a = syscall(SYS_gettid);
	for (i = 0; i < NR_ROUNDS && !c->err_a; i++) {
		/* Passes every hook that the programs under test are attached to */
		if (prctl(PR_SET_NAME, "worker_a"))
			c->err_a = -errno;
	}
	return NULL;
}

/* B is SCHED_FIFO on A's CPU: A runs only while B waits, and B preempts A as soon as A wakes it */
static void *worker_b(void *arg)
{
	struct sched_param sp = { .sched_priority = 1 };
	struct timespec ts = { .tv_sec = 5 };	/* give up if the signal never comes */
	struct ctx *c = arg;
	int i;

	c->err_b = pin_to_cpu(c->cpu);
	if (!c->err_b && sched_setscheduler(0, SCHED_FIFO, &sp))
		c->err_b = -errno;
	c->skel->bss->tid_b = syscall(SYS_gettid);
	for (i = 0; i < NR_ROUNDS && !c->err_b; i++) {
		while (sigtimedwait(&c->sigset, NULL, &ts) < 0) {
			if (errno != EINTR) {
				c->err_b = -errno;
				return NULL;
			}
		}
		/* B preempted A only if A is still inside the program */
		if (*(volatile int *)&c->skel->bss->a_inside)
			c->overlaps++;
		/* B's own run of the program, while A is preempted inside it */
		if (prctl(PR_SET_NAME, "worker_b"))
			c->err_b = -errno;
	}
	return NULL;
}

/* Load and attach only programs @a, @b and @c. NULL after a failure or a skip. */
static struct trampoline_preempt *load_progs(const char *a, const char *b, const char *c,
					     int percpu)
{
	struct trampoline_preempt *skel = trampoline_preempt__open();
	struct bpf_program *p;
	const char *name;
	int err;

	if (!ASSERT_OK_PTR(skel, "open"))
		return NULL;
	bpf_object__for_each_program(p, skel->obj) {
		name = bpf_program__name(p);
		bpf_program__set_autoload(p, !strcmp(name, a) || (b && !strcmp(name, b)) ||
					  (c && !strcmp(name, c)));
	}
	skel->bss->sig = SIGUSR1;
	skel->rodata->percpu = percpu;
	err = trampoline_preempt__load(skel);
	/* The kernel or its JIT doesn't support one of the programs */
	if (err == -EOPNOTSUPP || err == -ENOTSUPP)
		test__skip();
	else if (ASSERT_OK(err, "load") && ASSERT_OK(trampoline_preempt__attach(skel), "attach"))
		return skel;
	trampoline_preempt__destroy(skel);
	return NULL;
}

static const struct subtest {
	const char *name;
	const char *prog;	/* A enters it; its recursion misses are checked */
	int percpu;		/* the per-CPU state that the program touches */
	enum expect expect;
	const char *prog_b;	/* two_dispatchers: B reaches the handler through this one */
	const char *handler;	/* two_dispatchers: the target of both tail calls */
} subtests[] = {
	/* Each kind of program, without per-CPU state and with a per-CPU map lookup */
	{ "fentry",		"on_fentry",		NO_PERCPU,	B_RUNS },
	{ "fentry_percpu",	"on_fentry",		PERCPU_MAP,	B_AFTER },
	{ "fexit",		"on_fexit",		NO_PERCPU,	B_RUNS },
	{ "fexit_percpu",	"on_fexit",		PERCPU_MAP,	B_AFTER },
	{ "fmod_ret",		"on_fmod_ret",		NO_PERCPU,	B_RUNS },
	{ "fmod_ret_percpu",	"on_fmod_ret",		PERCPU_MAP,	B_AFTER },
	{ "fentry_s",		"on_fentry_s",		NO_PERCPU,	B_RUNS },
	{ "fentry_s_percpu",	"on_fentry_s",		PERCPU_MAP,	B_RUNS },
	{ "raw_tp",		"on_raw_tp",		NO_PERCPU,	B_RUNS },
	{ "raw_tp_percpu",	"on_raw_tp",		PERCPU_MAP,	B_AFTER },
	{ "raw_tp_s",		"on_raw_tp_s",		NO_PERCPU,	B_RUNS },
	{ "raw_tp_s_percpu",	"on_raw_tp_s",		PERCPU_MAP,	B_RUNS },
	{ "tp_syscall",		"on_tp_syscall",	NO_PERCPU,	B_RUNS },
	{ "tp_syscall_percpu",	"on_tp_syscall",	PERCPU_MAP,	B_AFTER },
	/* The other things that mark a program */
	{ "percpu_var",		"on_raw_tp",		PERCPU_VAR,	B_AFTER },
	{ "this_cpu_ptr",	"on_raw_tp",		THIS_CPU_PTR,	B_AFTER },
	{ "smp_processor_id",	"on_raw_tp",		CPU_ID,		B_AFTER },
	{ "tail_call",		"on_tail_call",		NO_PERCPU,	B_AFTER },
	/* Timed may_goto doesn't mark a program: B runs while A is inside the loop */
	{ "may_goto",		"on_may_goto",		NO_PERCPU,	B_RUNS },
	/* B runs the handler through the other dispatcher after A; A's stack stays intact */
	{ "two_dispatchers",	"dispatcher_a",		NO_PERCPU,	B_AFTER,
	  "dispatcher_b", "handler" },
};

static void run_subtest(const struct subtest *t)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info), zero = 0;
	struct ctx c = {};
	sigset_t oldset;
	pthread_t ta, tb;
	int err, fd;

	c.skel = load_progs(t->prog, t->prog_b, t->handler, t->percpu);
	if (!c.skel)
		return;
	if (t->handler) {
		/* Both dispatchers tail-call the handler through the prog array */
		fd = bpf_program__fd(bpf_object__find_program_by_name(c.skel->obj, t->handler));
		err = bpf_map_update_elem(bpf_map__fd(c.skel->maps.prog_array), &zero, &fd,
					  BPF_ANY);
		if (!ASSERT_OK(err, "prog_array_update"))
			goto out;
	}

	/* Both threads go on this CPU. B takes the signal with sigtimedwait(), so block it. */
	c.cpu = sched_getcpu();
	sigemptyset(&c.sigset);
	sigaddset(&c.sigset, SIGUSR1);
	if (!ASSERT_OK(pthread_sigmask(SIG_BLOCK, &c.sigset, &oldset), "sigmask"))
		goto out;
	if (ASSERT_OK(pthread_create(&tb, NULL, worker_b, &c), "pthread_b")) {
		/* A's program needs tid_b to wake B */
		while (!c.skel->bss->tid_b)
			usleep(1000);
		if (ASSERT_OK(pthread_create(&ta, NULL, worker_a, &c), "pthread_a"))
			pthread_join(ta, NULL);
		pthread_join(tb, NULL);
	}
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);

	/* B may not be allowed to become SCHED_FIFO */
	if (c.err_b == -EPERM || c.err_b == -EACCES) {
		test__skip();
		goto out;
	}
	ASSERT_OK(c.err_a, "worker_a");
	ASSERT_OK(c.err_b, "worker_b");
	ASSERT_EQ(c.skel->bss->sig_err, 0, "sig_err");
	if (t->expect == B_RUNS && !c.overlaps) {
		/* B never preempted A inside the program, so nothing was tested */
		test__skip();
		goto out;
	}
	ASSERT_EQ(c.overlaps, t->expect == B_RUNS ? NR_ROUNDS : 0, "overlaps");
	ASSERT_EQ(c.skel->bss->runs_a, NR_ROUNDS, "runs_a");
	ASSERT_EQ(c.skel->bss->runs_b, NR_ROUNDS, "runs_b");
	if (t->handler)
		ASSERT_EQ(c.skel->bss->stack_corrupt, 0, "stack_corrupt");
	fd = bpf_program__fd(bpf_object__find_program_by_name(c.skel->obj, t->prog));
	err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
	if (!ASSERT_OK(err, "prog_info"))
		goto out;
	ASSERT_EQ(info.recursion_misses, 0, "recursion_misses");
out:
	trampoline_preempt__destroy(c.skel);
}

/*
 * The program calls bpf_printk(), which fires the bpf_trace_printk tracepoint
 * that it is attached to: the nested run must be rejected as recursion. With a
 * hop, a second program runs in between, so the check has to look past the
 * frame right below.
 */
static const struct recursion {
	const char *name, *prog, *hop;
	bool test_run;	/* Start the outer run with BPF_PROG_TEST_RUN of @prog */
} recursions[] = {
	{ "recursion_raw_tp", "recur_raw_tp" },
	{ "recursion_two_hops", "recur_two_hops", "recur_hop" },
	{ "recursion_test_run", "recur_raw_tp", .test_run = true },
};

static void run_recursion(const struct recursion *t)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct trampoline_preempt *skel = load_progs(t->prog, t->hop, "recur_trigger", NO_PERCPU);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int err, fd, run_fd;

	if (!skel)
		return;
	fd = bpf_program__fd(bpf_object__find_program_by_name(skel->obj, t->prog));
	/* The outer run: of @prog itself, or of a program that fires its tracepoint */
	run_fd = t->test_run ? fd : bpf_program__fd(skel->progs.recur_trigger);
	skel->bss->recur_tid = syscall(SYS_gettid);
	err = bpf_prog_test_run_opts(run_fd, &opts);
	skel->bss->recur_tid = 0;
	/* The outer run got in; the nested one was dropped and counted */
	if (ASSERT_OK(err, "test_run")) {
		ASSERT_EQ(skel->bss->recur_runs, 1, "recur_runs");
		ASSERT_EQ(skel->bss->hop_runs, t->hop ? 1 : 0, "hop_runs");
		err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
		if (ASSERT_OK(err, "prog_info"))
			ASSERT_EQ(info.recursion_misses, 1, "recursion_misses");
	}
	trampoline_preempt__destroy(skel);
}

/*
 * An extension runs under the recursion check of its target. A target that
 * keeps no per-CPU state is checked per task, so an extension that does keep
 * such state can't be attached to it.
 */
static void run_ext_subtest(void)
{
	static const struct {
		const char *prog;
		int err;
	} exts[] = {
		{ "ext_plain", 0 },		/* no per-CPU state: attaches */
		{ "ext_percpu", -EINVAL },	/* a per-CPU map lookup: rejected */
	};
	struct trampoline_preempt *tgt_skel, *skel = NULL;
	struct bpf_program *ext, *p;
	struct bpf_link *link;
	int i, err, tgt_fd;

	tgt_skel = trampoline_preempt__open();
	if (!ASSERT_OK_PTR(tgt_skel, "open_tgt"))
		return;
	bpf_object__for_each_program(p, tgt_skel->obj)
		bpf_program__set_autoload(p, p == tgt_skel->progs.ext_target);
	if (!ASSERT_OK(trampoline_preempt__load(tgt_skel), "load_tgt"))
		goto out;
	tgt_fd = bpf_program__fd(tgt_skel->progs.ext_target);

	for (i = 0; i < ARRAY_SIZE(exts); i++) {
		skel = trampoline_preempt__open();
		if (!ASSERT_OK_PTR(skel, "open_ext"))
			goto out;
		ext = bpf_object__find_program_by_name(skel->obj, exts[i].prog);
		bpf_object__for_each_program(p, skel->obj)
			bpf_program__set_autoload(p, p == ext);
		err = bpf_program__set_attach_target(ext, tgt_fd, "ext_target");
		if (!ASSERT_OK(err, "set_attach_target"))
			goto out;
		if (!ASSERT_OK(trampoline_preempt__load(skel), "load_ext"))
			goto out;

		link = bpf_program__attach_freplace(ext, tgt_fd, "ext_target");
		ASSERT_EQ(libbpf_get_error(link), exts[i].err, "attach_ext");
		bpf_link__destroy(link);
		trampoline_preempt__destroy(skel);
		skel = NULL;
	}
out:
	trampoline_preempt__destroy(skel);
	trampoline_preempt__destroy(tgt_skel);
}

void test_trampoline_preempt(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(subtests); i++) {
		if (test__start_subtest(subtests[i].name))
			run_subtest(&subtests[i]);
	}
	for (i = 0; i < ARRAY_SIZE(recursions); i++) {
		if (test__start_subtest(recursions[i].name))
			run_recursion(&recursions[i]);
	}
	if (test__start_subtest("ext_attach"))
		run_ext_subtest();
}
