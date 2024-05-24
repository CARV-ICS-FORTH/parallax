// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef LSN_H
#define LSN_H
#include <stdint.h>
#include <stdlib.h>

struct lsn_factory {
	int64_t ticket_id;
};

struct lsn {
	int64_t id;
} __attribute__((packed));

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
/** set the lsn id to be equal to ticket
 * @param lsn: a ptr to a struct lsn
 * */
void set_lsn_id(struct lsn *lsn, int64_t ticket);
/**
 * reset the lsn ticket(id) to 0
 * @param lsn: a ptr to a struct lsn
 * */
void reset_lsn(struct lsn *lsn);
/**
 * reset the lsn_factory ticket(id) to 0
 * @param lsn_factory: a ptr to a struct lsn_factory
 * */
void reset_lsn_factory(struct lsn_factory *lsn_factory);
/**
 * creates an lsn_factory object and initializes its starting ticket value with the param
 * @param starting_ticket: the starting point from which the factory will continue producing new tickets(id)
 * */
struct lsn_factory lsn_factory_init(int64_t starting_ticket);
/**
 * atomically increase the lsn ticket(id) by one and returns an lsn object which has the previous id as a ticket
 * @param lsn: a ptr to a struct lsn
 * */
struct lsn increase_lsn(struct lsn_factory *lsn_factory);
/**
 * returns the current ticket(id) value of the lsn_factory
 * @param lsn_factory: a ptr to the lsn_factory from which we are retrieving its current value
 * */
int64_t lsn_factory_get_ticket(struct lsn_factory *lsn_factory);
/**
  * returns an lsn object containing the biggest lsn possible
  * */
struct lsn get_max_lsn(void);
#endif
