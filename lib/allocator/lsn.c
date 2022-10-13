#include "lsn.h"
#include <stdint.h>

inline size_t get_lsn_size(void)
{
	return sizeof(struct lsn);
}

inline int64_t compare_lsns(struct lsn *left, struct lsn *right)
{
	return left->uuid - right->uuid;
}

inline int64_t lsn_to_int64(struct lsn *lsn)
{
	return lsn->uuid;
}

inline struct lsn increase_lsn(struct lsn *lsn)
{
	__sync_fetch_and_add(&lsn->uuid, 1);
	return *lsn;
}

inline void reset_lsn(struct lsn *lsn)
{
	lsn->uuid = 0;
}
