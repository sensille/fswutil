#ifndef __fsw_h__
#define __fsw_h__

#define MAX_MAPPINGS	500

struct mapping {
	int	nmappings;
	struct {
		void		*vma;
		uint64_t	*file;
	} mappings[MAX_MAPPINGS];
};

#endif
