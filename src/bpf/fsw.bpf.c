// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fsw.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile uint32_t targ_pid = 0;

#define LOG(...)  //bpf_printk(__VA_ARGS__)
#define DBG(...) // bpf_printk(__VA_ARGS__)
#undef SAFETY_CHECK
#define APPEASE_VERIFIER

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 4096);
} rb SEC(".maps");

/*
 * output structure
 */
struct stack_out {
	uint32_t nframes;
	uint64_t frames[MAX_STACK_FRAMES];
};

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

/*
TODO: see if we need to acutally check return values of uw_read_*, error returns
TODO: fewer bounds checks if we can convince the verifier
TODO: find_ctf non-static
*/
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

		DBG("bisection step %d: left %d right %d mid %d vma_start %lx",
			i, left, right, mid, me->vma_start);
		if (me->vma_start <= ip)
			left = mid + 1;
		else
			right = mid;
	}
	if (left == 0) {
		LOG("ip %lx below first vma_start", ip);
		return NULL;
	}
	--left;
#ifdef APPEASE_VERIFIER
	left = scramble(scramble(left));
#endif
	if (left >= MAX_MAPPINGS)
		return NULL;
	struct map_entry *me = &m->entries[left];
	bpf_printk("ip %lx found in mapping %d: %lx", ip, left, me->vma_start);
	bpf_printk("    obj %d off %lx map %d",
		me->offset >> 48, me->offset & 0xffffffffffff, me->offsetmap_id);
#ifdef SAFETY_CHECK
	// safety check
	if (left + 1 < n) {
		struct map_entry *nme = &m->entries[left + 1];
		if (ip >= nme->vma_start) {
			bpf_printk("BAD: ip %lx >= next vma_start %lx, no match",
				ip, nme->vma_start);
			return NULL;
		}
	}
#endif
	return me;
}

// encoding:
// ptrs: we limit the table size to 2MB, so 21 bits
//   00-CF: encode as 1 byte
//   D0-D8: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
// leaf ptrs:
//   D8-DF: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//   E0-FF: ptr as 1 byte
// values:
//   00-F7: encode as 1 byte
//   F8-FF: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
// RelKey:
//   00-DE: 1 byte, val + 111
//   DF   : followed by 8 bytes i64 (little-endian)
//   E0-FF: lower 5 bits, followed by 1 byte (little-endian)
static uint64_t
uw_read_key(uint8_t *ptr, uint32_t *pos)
{
	uint64_t key = 0;
	if (*pos >= OFFSETMAP_SIZE - 9) {
		LOG("uw_read_key: pos %d out of bounds", *pos);
		return 0;
	}
	uint8_t b = ptr[(*pos)++];
	if (b <= 0xde) {
		key = (uint64_t)b - 111;
	} else if (b == 0xdf) {
		/* 8 byte */
		key = *(uint64_t *)&ptr[*pos];
		*pos += 8;
	} else {
		/* 5 bit + 1 byte */
		key = ((b & 0x1f) << 8) | ptr[(*pos)++];
		/* sign extend */
		if (key & 0x1000) {
			key |= ~0x1ffful;
		}
	}

	return key;
}

static uint32_t
uw_read_rel_ptr(uint8_t *ptr, uint32_t *pos, int *is_leaf)
{
	uint32_t rel_ptr = 0;
	if (*pos >= OFFSETMAP_SIZE - 3) {
		LOG("uw_read_rel_ptr: pos %d out of bounds", *pos);
		return -1;
	}
	uint8_t b = ptr[(*pos)++];
	if (b <= 0xcf) {
		rel_ptr = b;
		*is_leaf = 0;
	} else if (b >= 0xd0 && b <= 0xd8) {
		/* 3 bit + 2 byte */
		rel_ptr = ((b & 0x07) << 16) | *(uint16_t *)&ptr[*pos];
		*pos += 2;
		*is_leaf = 0;
	} else if (b >= 0xd8 && b <= 0xdf) {
		/* leaf ptr: 3 bit + 2 byte */
		rel_ptr = ((b & 0x07) << 16) | *(uint16_t *)&ptr[*pos];
		*pos += 2;
		*is_leaf = 1;
	} else {
		/* leaf ptr: 1 byte */
		rel_ptr = b & 0x1f;
		*is_leaf = 1;
	}
	return rel_ptr;
}

static uint64_t
uw_read_value(uint8_t *ptr, uint32_t *pos)
{
	uint64_t val = 0;
	if (*pos >= OFFSETMAP_SIZE - 3) {
		LOG("uw_read_value: pos %d out of bounds", *pos);
		return -1;
	}
	uint8_t b = ptr[(*pos)++];
	if (b <= 0xf7) {
		val = b;
	} else {
		/* 3 bit + 2 byte */
		val = ((b & 0x07) << 8) | *(uint16_t *)&ptr[*pos];
		*pos += 2;
	}
	return val;
}

// returns entry_id
int
find_cft(uint32_t offsetmap_id, uint64_t start_in_map, uint64_t search_key)
{
	struct offsetmap *om = bpf_map_lookup_elem(&offsetmaps, &offsetmap_id);
	if (om == NULL) {
		bpf_printk("offsetmap lookup failed for id %d", offsetmap_id);
		LOG("offsetmap not found");
		return 1;
	}
bpf_printk("offsetmap found, id %d, start %d offset %x", offsetmap_id, start_in_map, search_key);
	uint8_t *ptr = om->map;
	int is_leaf = 0;
	uint64_t parent_key = 0;
	uint32_t pos = start_in_map;
	int best = -1;
	int depth = 0;

	while (depth++ < MAX_OFFSETS_BISECT_STEPS) {
		uint64_t current_key = uw_read_key(ptr, &pos);
		bpf_printk(" read key %ld abs %lx at pos %d", current_key, current_key + parent_key, pos);
		if (current_key == 0) { /* final empty node */
			return best;
		}
		current_key += parent_key;
		current_key = scramble(scramble(current_key)); // XXX
		parent_key = current_key;

		if (is_leaf) {
			/* leaf node reached */
			break;
		}

		if (!is_leaf && ptr[pos] == 0) {
			/* unmarked leaf node */
			++pos;
			break;
		}

		uint32_t rel_ptr = uw_read_rel_ptr(ptr, &pos, &is_leaf);
		if (search_key < current_key) {
bpf_printk(" go left at key %lx", current_key);
			/* go to left child */
			pos += rel_ptr;
		} else {
			best = uw_read_value(ptr, &pos);
bpf_printk(" go right: best %d at key %lx", best, current_key);
			/* continue with right child */
		}
	}

	/* leaf node case */

	/* left key/value */
	uint64_t left_key = uw_read_key(ptr, &pos);
	uint64_t left_value = uw_read_value(ptr, &pos);
bpf_printk(" leaf left key %lx value %d", left_key + parent_key, left_value);

	/* own value */
	uint64_t own_value = uw_read_value(ptr, &pos);
bpf_printk(" leaf own value %d", own_value);

	if (search_key < parent_key) {
		if (left_key != 0 && search_key >= (left_key + parent_key)) {
bpf_printk(" leaf left match: key %lx value %d", left_key + parent_key, left_value);
			return left_value;
		}
		return best;
	}

	/* right key/value */
	uint64_t right_key = uw_read_key(ptr, &pos);
	uint64_t right_value = uw_read_value(ptr, &pos);

	if (right_key != 0 && search_key >= (right_key + parent_key)) {
bpf_printk(" leaf right match: key %lx value %d", right_key + parent_key, right_value);
		return right_value;
	}

	return own_value;
}

struct fsw_state {
	struct mapping *m;
	u64 regs[NUM_REGISTERS];
	u64 regs_valid;
	int steps;
};

static int
unwind_step(int ix, struct fsw_state *s) {
	if ((s->regs_valid & (1 << RIP)) == 0) {
		LOG("Stack walk: PC is None, stopping");
		return 1;
	}

	struct map_entry *me = find_mapping(s->m, s->regs[RIP]);
	if (me == NULL) {
		LOG("no map entry found");
		return 1;
	}

	uint64_t offset = s->regs[RIP] - me->vma_start + me->offset;
	DBG("rip %lx vma_start %lx offset %lx", s->regs[RIP], me->vma_start, offset);
	int32_t cft_id = find_cft(me->offsetmap_id, me->start_in_map, offset);
	bpf_printk(" found cft entry id %d", cft_id);

	if (cft_id <= 0) {
		LOG("no offsetmap entry found");
		return 1;
	}

	struct cft *cf = bpf_map_lookup_elem(&cfts, &cft_id);
	if (cf == NULL) {
		LOG("cft not found");
		return 1;
	}
	bpf_printk("cft %d found", cft_id);
	if (cft_id == 0) {
		LOG("no mapping for address");
		return 1;
	}

	// XXX only copy when needed, invent a flag in cft
	u64 old_regs[NUM_REGISTERS];
	for (int i = 0; i < NUM_REGISTERS; ++i)
		old_regs[i] = s->regs[i];

	/* compute CFA */
	uint64_t cfa;
	if (cf->cfa.rtype == CFA_RULE_UNINITIALIZED) {
		LOG("Stack walk: CFA uninitialized, stopping");
		return 1;
	} else if (cf->cfa.rtype == CFA_RULE_EXPRESSION) {
		LOG("Stack walk: CFA expression not yet supported, stopping");
		return 1;
	} else if (cf->cfa.rtype == CFA_RULE_REG_OFFSET) {
		u32 r = cf->cfa.data.reg_offset.reg;
		s64 o = cf->cfa.data.reg_offset.offset;
		if ((s->regs_valid & (1 << r)) == 0) {
			LOG("Stack walk: CFA register r%d not valid, stopping", r);
			return 1;
		}
		if (r >= NUM_REGISTERS) {
			LOG("Stack walk: CFA register r%d out of range, stopping", r);
			return 1;
		}
		cfa = s->regs[r] + o;
		bpf_printk("  CFA = r%d (%lx) + %lld = %lx", r, s->regs[r], o);
		bpf_printk("  new CFA = %lx", cfa);
	} else {
		LOG("Stack walk: unknown CFA rule type %d, stopping", cf->cfa.rtype);
		return 1;
	}

        // unwind stack pointer
        s->regs[RSP] = cfa;

	for (int reg = 0; reg < NUM_REGISTERS; ++reg) {
		s->regs_valid = scramble(scramble(s->regs_valid));
		if (cf->rules[reg].rtype == REGISTER_RULE_UNINITIALIZED ||
		    cf->rules[reg].rtype == REGISTER_RULE_SAME_VALUE) {
			// register is unchanged
			DBG("  r%d: same value %lx", reg, s->regs[reg]);
		} else if (cf->rules[reg].rtype == REGISTER_RULE_UNDEFINED) {
			// register is undefined
			DBG("  r%d: undefined", reg);
			s->regs_valid &= ~(1 << reg);
		} else if (cf->rules[reg].rtype == REGISTER_RULE_OFFSET) {
			// register is at CFA + offset
			s64 off = cf->rules[reg].data.offset;
			u64 addr = cfa + off;
			// read value from user stack
			u64 val = 0;
			int ret = bpf_probe_read_user(&val, sizeof(val), (void *)addr);
			if (ret < 0) {
				LOG("Stack walk: failed to read r%d at addr %lx, stopping",
					reg, addr);
				return 1;
			}
			DBG("  r%d: at addr %lx value %lx", reg, addr, val);
			s->regs[reg] = val;
			s->regs_valid |= (1 << reg);
                // XXX use old_regs for register to register copy
		} else {
			LOG("Stack walk: unsupported register rule type %d for r%d, stopping",
				cf->rules[reg].rtype, reg);
			return 1;
		}
	}

	bpf_printk("After unwind step: next PC %lx", s->regs[RIP]);
	for (int reg = 0; reg < NUM_REGISTERS; ++reg) {
		if (s->regs_valid & (1 << reg)) {
			LOG("  r%d: %lx", reg, s->regs[reg]);
		} else {
			LOG("  r%d: <invalid>", reg);
		}
	}

	s->steps += 1;
	return 0;
}

SEC("perf_event")
int BPF_KPROBE(ustack)
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
		LOG("no task struct");
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
		LOG("no thread info");
		return 0;
	}
	unsigned long ti_flags = BPF_CORE_READ(ti, flags);
	bpf_printk("thread flags: %x", ti_flags);
#endif

	bpf_printk("kernel stack: %lx", BPF_CORE_READ(task, stack));
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm == NULL) {
		LOG("no mm struct");
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
		LOG("no pt_regs");
		return 0;
	}
	bpf_printk("pt_regs is %lx", pregs);
	// XXX differentiate between 32 and 64 bit?

	// XXX just read all as a block and sort later?
	// XXX not all needed for stack walk without params
	struct fsw_state s;
	s.regs[0] = BPF_CORE_READ(pregs, ax);
	s.regs[1] = BPF_CORE_READ(pregs, dx);
	s.regs[2] = BPF_CORE_READ(pregs, cx);
	s.regs[3] = BPF_CORE_READ(pregs, bx);
	s.regs[4] = BPF_CORE_READ(pregs, si);
	s.regs[5] = BPF_CORE_READ(pregs, di);
	s.regs[6] = BPF_CORE_READ(pregs, bp);
	s.regs[7] = BPF_CORE_READ(pregs, sp);
	s.regs[8] = BPF_CORE_READ(pregs, r8);
	s.regs[9] = BPF_CORE_READ(pregs, r9);
	s.regs[10] = BPF_CORE_READ(pregs, r10);
	s.regs[11] = BPF_CORE_READ(pregs, r11);
	s.regs[12] = BPF_CORE_READ(pregs, r12);
	s.regs[13] = BPF_CORE_READ(pregs, r13);
	s.regs[14] = BPF_CORE_READ(pregs, r14);
	s.regs[15] = BPF_CORE_READ(pregs, r15);
	s.regs[16] = BPF_CORE_READ(pregs, ip);
	bpf_printk("rsp %lx ip %lx r8 %lx", s.regs[7], s.regs[16], s.regs[8]);

	bpf_printk("pid %d tgid %d", pid, tgid);

	/*
	 * load mapping for pid
	 * eventually we might want to use bpf_find_vma if it is widely available
	 */
	struct mapping *m = bpf_map_lookup_elem(&mappings, &tgid);
	if (m == NULL) {
		bpf_printk("no mapping found");
		return 0;
	}
	bpf_printk("nmappings %d", m->nentries);
	s.m = m;
	s.regs_valid = 0x1ffff;
	s.steps = 0;

	struct stack_out *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
	if (out == NULL) {
		LOG("ringbuf reserve failed");
		return 0;
	}
	out->frames[0] = s.regs[RIP];
#if 1
	// pre-5.17 without bpf_loop
	for (int i = 1; i < 25 /*MAX_STACK_FRAMES*/; ++i) {
		if (unwind_step(i, &s) != 0)
			goto done;
		out->frames[i] = s.regs[RIP];
	}

#else
	bpf_loop(MAX_STACK_FRAMES, unwind_step, &s, 0);
#endif

done:
	out->nframes = s.steps;
	bpf_ringbuf_submit(out, 0);

	bpf_printk("walked %d steps", s.steps);
	bpf_printk("\n");
	return 0;
}
