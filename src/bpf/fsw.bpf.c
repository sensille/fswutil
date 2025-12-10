// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fsw.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define LOG(...) bpf_printk(__VA_ARGS__)

/*
 * maps
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);		/* adjusted by user mode */
	__type(key, uint32_t);
	__type(value, struct mapping);
} mappings SEC(".maps");

static long
vma_cb(struct task_struct *task, struct vm_area_struct *vma, void *ctx)
{
	//bpf_printk("vma: vm_start %lx", BPF_CORE_READ(vma, vm_start));

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_add)
{
	struct task_struct *task;

	task = bpf_get_current_task_btf();
	if (task == NULL) {
		LOG("no task struct\n");
		return 0;
	}

	bpf_printk("ctx is %p", ctx);
#if 0
	/*
	 * is this a 64 or a 32 bit thread?
	 */
	//struct thread_info *ti = (struct thread_info *)BPF_CORE_READ(task, thread_info);
	struct thread_info *ti = NULL;
	bpf_probe_read_kernel(&ti, 8, &task->thread_info);
	if (ti == NULL) {
		LOG("no thread info\n");
		return 0;
	}
	unsigned long ti_flags = BPF_CORE_READ(ti, flags);
	bpf_printk("thread flags: %x", ti_flags);
#endif

	bpf_printk("kernel stack: %p", BPF_CORE_READ(task, stack));
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm == NULL) {
		LOG("no mm struct\n");
		return 0;
	}
	bpf_printk("mm: %p", mm);
	bpf_printk("start stack: %p", BPF_CORE_READ(mm, start_stack));
	/*
	 * user mode regs are passed in as ctx. We fetch
	 * them anyway, so that it also works when called from
	 * kernel probes
	 */
	struct pt_regs *pregs = (struct pt_regs *)bpf_task_pt_regs(task);
	if (pregs == NULL) {
		LOG("no pt_regs\n");
		return 0;
	}
	bpf_printk("pt_regs is %lx", pregs);
	// XXX differentiate between 32 and 64 bit?

	// XXX just read all as a block and sort later?
	// XXX not all needed for stack walk without params
	u64 regs[17];
	regs[0] = BPF_CORE_READ(pregs, ax);
	regs[1] = BPF_CORE_READ(pregs, dx);
	regs[2] = BPF_CORE_READ(pregs, cx);
	regs[3] = BPF_CORE_READ(pregs, bx);
	regs[4] = BPF_CORE_READ(pregs, si);
	regs[5] = BPF_CORE_READ(pregs, di);
	regs[6] = BPF_CORE_READ(pregs, bp);
	regs[7] = BPF_CORE_READ(pregs, sp);
	regs[8] = BPF_CORE_READ(pregs, r8);
	regs[9] = BPF_CORE_READ(pregs, r9);
	regs[10] = BPF_CORE_READ(pregs, r10);
	regs[11] = BPF_CORE_READ(pregs, r11);
	regs[12] = BPF_CORE_READ(pregs, r12);
	regs[13] = BPF_CORE_READ(pregs, r13);
	regs[14] = BPF_CORE_READ(pregs, r14);
	regs[15] = BPF_CORE_READ(pregs, r15);
	regs[16] = BPF_CORE_READ(pregs, ip);
	bpf_printk("rsp %lx ip %lx r8 %lx", regs[7], regs[16], regs[8]);

	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t pid = pid_tgid & 0xffffffff;
	uint32_t tgid = pid_tgid >> 32;
	bpf_printk("pid %d tgid %d", pid, tgid);

#if 0
	// unfortunately this does not seem to be present in ubuntu2204lts
	long ret = bpf_find_vma(task, regs[16], vma_cb, NULL, 0);
	bpf_printk("find_vma returned %d\n", ret);
#else
	/*
	 * load mapping for pid
	 */
	struct mapping *m = bpf_map_lookup_elem(&mappings, &tgid);
	if (m == NULL) {
		LOG("no mapping found\n");
		return 0;
	}
	bpf_printk("nmappings %d", m->nmappings);

#endif

	return 0;
}
