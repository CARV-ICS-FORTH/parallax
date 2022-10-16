#ifndef _LSN_H
#define _LSN_H
#include <stdint.h>
#include <stdlib.h>

struct lsn {
	int64_t id;
};

size_t get_lsn_size(void);
int64_t compare_lsns(struct lsn *left, struct lsn *right);
int64_t lsn_to_int64(struct lsn *lsn);
struct lsn increase_lsn(struct lsn *lsn);
void reset_lsn(struct lsn *lsn);
#endif
