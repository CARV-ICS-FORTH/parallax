#include "lsn.h"
#include <stdint.h>

inline size_t get_lsn_size(void)
{
	return sizeof(struct lsn);
}

inline int64_t compare_lsns(struct lsn *left, struct lsn *right)
{
	return left->id - right->id;
}

inline int64_t get_lsn_id(struct lsn *lsn)
{
	return lsn->id;
}

inline void set_lsn_id(struct lsn *lsn, int64_t ticket)
{
	lsn->id = ticket;
}

inline void reset_lsn(struct lsn *lsn)
{
	lsn->id = 0;
}

struct lsn_factory lsn_factory_init(int64_t starting_ticket)
{
	struct lsn_factory new_lsn_factory = { .ticket_id = starting_ticket };
	return new_lsn_factory;
}

inline int64_t lsn_factory_increase_ticket(struct lsn_factory *lsn_factory)
{
	return __sync_fetch_and_add(&lsn_factory->ticket_id, 1);
}

inline struct lsn increase_lsn(struct lsn_factory *lsn_factory)
{
	struct lsn new_lsn = { .id = lsn_factory_increase_ticket(lsn_factory) };
	return new_lsn;
}

inline int64_t lsn_factory_get_ticket(struct lsn_factory *lsn_factory)
{
	return lsn_factory->ticket_id;
}

