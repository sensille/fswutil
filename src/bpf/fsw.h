#ifndef __fsw_h__
#define __fsw_h__

#define MAX_MAPPINGS	1000
#define MAX_MAPPINGS_BISECT_STEPS	10

#define MAX_OFFSETS	130000
#define MAX_OFFSETS_BISECT_STEPS	17

#define MAX_CFT_ENTRIES	1000

#define MAX_EXPRESSION_LEN 255
#define NUM_REGISTERS 17		// 16 + RIP

#define RSP 7
#define RIP 16
#define MAX_STACK_FRAMES 64

#pragma pack(1)
struct mapping {
	uint64_t	nentries;
	struct map_entry {
		uint64_t	vma_start;
		uint64_t	obj_id_offset;
		uint32_t	offsetmap_id;
	} entries[MAX_MAPPINGS];
};

struct offsetmap {
	uint64_t	nentries;
	struct offsetmap_entry {
		uint64_t	obj_id_offset;
		uint32_t	cft_id;
	} entries[MAX_OFFSETS];
};

enum register_rule_type {
	REGISTER_RULE_UNINITIALIZED = 0,
	REGISTER_RULE_UNDEFINED = 1,
	REGISTER_RULE_SAME_VALUE = 2,
	REGISTER_RULE_OFFSET = 3,
	REGISTER_RULE_VAL_OFFSET = 4,
	REGISTER_RULE_REGISTER = 5,
	REGISTER_RULE_EXPRESSION = 6,
	REGISTER_RULE_VAL_EXPRESSION = 7,
};

struct register_rule {
	enum register_rule_type	rtype;
	union register_rule_data {
		uint64_t	reg;
		int64_t		offset;
		uint32_t	expression_id;
	} data;
};

enum cfa_rule_type {
	CFA_RULE_UNINITIALIZED = 0,
	CFA_RULE_REG_OFFSET = 1,
	CFA_RULE_EXPRESSION = 2,
};

struct cfa_rule {
	enum cfa_rule_type	rtype;
	union cfa_rule_data {
	struct reg_offset {
		uint32_t	reg;
		int64_t		offset;
	} reg_offset;
		uint32_t	expression_id;
	} data;
};

struct cft {
	uint64_t arg_size; /* 8 bytes */
	struct cfa_rule cfa; /* 16 bytes */
	struct register_rule rules[NUM_REGISTERS];	/* 17 * 12 = 204 bytes */
	/* total: 225 bytes */
};

struct expression {
	uint8_t ninstructions;
	uint8_t instructions[MAX_EXPRESSION_LEN];
};

#pragma pack()

//
// taken from parca-agent bpf code
//
// Hack to thwart the verifier's detection of variable bounds.
//
// In recent kernels (6.8 and above) the verifier has gotten smarter
// in its tracking of variable bounds. For example, after an if statement like
// `if (v1 < v2)`,
// if it already had computed bounds for v2, it can infer bounds
// for v1 in each side of the branch (and vice versa). This means it can verify more
// programs successfully, which doesn't matter to us because our program was
// verified successfully before. Unfortunately it has a downside which
// _does_ matter to us: it increases the number of unique verifier states,
// which can cause the same instructions to be explored many times, especially
// in cases where a value is carried through a loop and possibly has
// multiple sets of different bounds on each iteration of the loop, leading to
// a combinatorial explosion. This causes us to blow out the kernel's budget of
// maximum number of instructions verified on program load (currently 1M).
//
// `opaquify32` is a no-op; thus `opaquify32(x, anything)` has the same value as `x`.
// However, the verifier is fortunately not smart enough to realize this,
// and will not realize the result has the same bounds as `x`, subverting the feature
// described above.
//
// For further discussion, see:
// https://lore.kernel.org/bpf/874jci5l3f.fsf@taipei.mail-host-address-is-not-set/
//
// if the verifier knows `val` is constant, you must set `seed`
// to something the verifier has no information about
// (if you don't have something handy, you can use `bpf_get_prandom_u32`).
// Otherwise, if the verifier knows bounds on `val` but not its exact value,
// it's fine to just use -1.
static __always_inline u32 opaquify32(u32 val, u32 seed) {
    // We use inline asm to make sure clang doesn't optimize it out
    asm volatile(
        "%0 ^= %1\n"
        "%0 ^= %1\n"
        : "+&r"(val)
        : "r"(seed)
    );
    return val;
}

// like opaquify32, but for u64.
static __always_inline u64 opaquify64(u64 val, u64 seed) {
    asm volatile(
        "%0 ^= %1\n"
        "%0 ^= %1\n"
        : "+&r"(val)
        : "r"(seed)
    );
    return val;
}
#endif
