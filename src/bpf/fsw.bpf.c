// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fsw.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile uint32_t targ_pid = 0;

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);		/* adjusted by user mode */
	__type(key, uint32_t);
	__type(value, struct offsetmap);
} offsetmaps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);		/* adjusted by user mode */
	__type(key, uint32_t);
	__type(value, struct cft);
} cfts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);		/* adjusted by user mode */
	__type(key, uint32_t);
	__type(value, struct expression);
} expressions SEC(".maps");

static long
vma_cb(struct task_struct *task, struct vm_area_struct *vma, void *ctx)
{
	//bpf_printk("vma: vm_start %lx", BPF_CORE_READ(vma, vm_start));

	return 0;
}

// see https://lore.kernel.org/bpf/874jci5l3f.fsf@taipei.mail-host-address-is-not-set/
static uint32_t __attribute__((optnone)) scramble(uint32_t val) {
        return val ^ 0xFFFFFFFF;
}

static struct map_entry *
find_mapping(struct mapping *m, uint64_t ip)
{
	int i;
	uint32_t n = m->nentries;
	if (n > MAX_MAPPINGS)
		n = MAX_MAPPINGS;

	uint32_t left = 0;
	uint32_t right = n;
	uint32_t mid = 0;
	for (i = 0; i < MAX_MAPPINGS_BISECT_STEPS && left < right; ++i) {
		mid = (left + right) / 2;
		// XXX TODO expensive
		mid = scramble(scramble(mid));
		if (mid >= MAX_MAPPINGS)
			break;
		struct map_entry *me = &m->entries[mid];

		bpf_printk("bisection step %d: left %d right %d mid %d vma_start %lx",
			i, left, right, mid, me->vma_start);
		if (me->vma_start <= ip)
			left = mid + 1;
		else
			right = mid;
	}
	if (left == 0) {
		LOG("ip %lx below first vma_start\n", ip);
		return NULL;
	}
	--left;
	if (left >= MAX_MAPPINGS)
		return NULL;
	struct map_entry *me = &m->entries[left];
	bpf_printk("ip %lx found in mapping %d: %lx obj %d off %lx map %d",
		ip, left, me->vma_start, me->obj_id_offset >> 48,
		me->obj_id_offset & 0xffffffffffff, me->offsetmap_id);
	// safety check
	if (left + 1 < n) {
		struct map_entry *nme = &m->entries[left + 1];
		if (ip >= nme->vma_start) {
			bpf_printk("BAD: ip %lx >= next vma_start %lx, no match",
				ip, nme->vma_start);
			return NULL;
		}
	}
	return me;
}

static struct offsetmap_entry *
find_cft(struct offsetmap *om, uint16_t obj_id, uint64_t offset)
{
	uint64_t key = (uint64_t)obj_id << 48 | offset;
	int i;
	uint32_t n = om->nentries;
	if (n > MAX_OFFSETS)
		n = MAX_OFFSETS;

	uint32_t left = 0;
	uint32_t right = n;
	uint32_t mid = 0;
	for (i = 0; i < MAX_OFFSETS_BISECT_STEPS && left <= right; ++i) {
		mid = left + (right - left) / 2;
		// XXX TODO expensive
		mid = scramble(scramble(mid));
		if (mid >= MAX_OFFSETS)
			break;
		struct offsetmap_entry *ome = &om->entries[mid];

		if (ome->obj_id_offset <= key)
			right = mid - 1;
		else
			left = mid;

	}
	--left;
	if (left >= MAX_OFFSETS)
		return NULL;

	struct offsetmap_entry *ome = &om->entries[left];
	bpf_printk("key %lx found in offsets %d: %lx ctf %d",
		key, left, ome->obj_id_offset, ome->cft_id);
	// safety check
	if (left + 1 < n) {
		struct offsetmap_entry *nome = &om->entries[left + 1];
		if (key >= nome->obj_id_offset) {
			bpf_printk("BAD: key %lx >= next key %lx, no match",
				key, nome->obj_id_offset);
			return NULL;
		}
	}

	return ome;
}

SEC("perf_event")
int BPF_KPROBE(uprobe_add)
{
	struct task_struct *task;

	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t pid = pid_tgid & 0xffffffff;
	uint32_t tgid = pid_tgid >> 32;

	if (targ_pid != tgid) {
		return 0;
	}

	task = bpf_get_current_task_btf();
	if (task == NULL) {
		LOG("no task struct\n");
		return 0;
	}

	bpf_printk("ctx is %lx", ctx);
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

	bpf_printk("kernel stack: %lx", BPF_CORE_READ(task, stack));
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm == NULL) {
		LOG("no mm struct\n");
		return 0;
	}
	bpf_printk("mm: %lx", mm);
	bpf_printk("start stack: %lx", BPF_CORE_READ(mm, start_stack));
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
	bpf_printk("nmappings %d", m->nentries);
	struct map_entry *me = find_mapping(m, regs[16]);
	if (me == NULL) {
		LOG("no map entry found\n");
		return 0;
	}

	struct offsetmap *om = bpf_map_lookup_elem(&offsetmaps, &me->offsetmap_id);
	if (om == NULL) {
		LOG("offsetmap not found\n");
		return 0;
	}
	uint64_t offset = regs[16] - me->vma_start;
	bpf_printk("r16 %lx vma_start %lx offset %lx", regs[16], me->vma_start, offset);
	find_cft(om, me->obj_id_offset >> 48, offset);
#endif

	bpf_printk("\n");
	return 0;
}
