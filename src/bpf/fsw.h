#ifndef __fsw_h__
#define __fsw_h__

#define MAX_MAPPINGS	1000
#define MAX_MAPPINGS_BISECT_STEPS	10

struct mapping {
	uint64_t	nmappings;
	struct map_entry {
		uint64_t	vma_start;
		uint64_t	vma_end;
		uint64_t	offset;
		uint64_t	obj_id;
	} mappings[MAX_MAPPINGS];
};

#endif
