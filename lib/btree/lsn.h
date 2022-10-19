#ifndef LSN_H
#define LSN_H
#include <stdint.h>
#include <stdlib.h>

struct lsn {
	int64_t id;
};

/**
 * returns the size of lsn struct
 * */
size_t get_lsn_size(void);
/**
 * returns the difference of left_lsn - right_lsn value
 * @param left: a ptr to struct lsn
 * @param right: a ptr to struct lsn
 * */
int64_t compare_lsns(struct lsn *left, struct lsn *right);
/**
 * returns the ticket(id) of the lsn
 * @param lsn: a ptr to a struct lsn
 * */
int64_t get_lsn_id(struct lsn *lsn);
/**
 * atomically increase the lsn ticket(id) by one and returns the previus lsn
 * @param lsn: a ptr to a struct lsn
 * */
struct lsn increase_lsn(struct lsn *lsn);
/**
 * reset the lsn ticket(id) to 0
 * */
void reset_lsn(struct lsn *lsn);
#endif
