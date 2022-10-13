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

#define _GNU_SOURCE
#include "gc.h"
#include "../allocator/log_structures.h"
#include "../allocator/volume_manager.h"
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "btree.h"
#include "conf.h"
#include "set_options.h"
#include <assert.h>
#include <list.h>
#include <log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <uthash.h>

extern pthread_mutex_t init_lock;
static uint8_t gc_executed = 0;
static uint8_t gc_active = 1;

struct gc_segment_descriptor {
	char *log_segment_in_memory;
	uint64_t segment_dev_offt;
};

uint8_t is_gc_executed(void)
{
	return gc_executed;
}

void disable_gc(void)
{
	gc_active = 0;
}

void push_stack(stack *marks, void *addr)
{
	marks->valid_pairs[marks->size++] = addr;
	assert(marks->size != STACK_SIZE);
}
void move_kv_pairs_to_new_segment(struct db_handle handle, stack *marks)
{
	bt_insert_req ins_req;
	char *kv_address;
	int i;

	for (i = 0; i < marks->size; ++i, ++handle.db_desc->gc_keys_transferred) {
		kv_address = marks->valid_pairs[i];
		// struct splice *key = (struct splice *)kv_address;
		// struct splice *value = (struct splice *)(kv_address +
		// VALUE_SIZE_OFFSET(key->size));
		ins_req.metadata.handle = &handle;
		ins_req.key_value_buf = kv_address;
		ins_req.metadata.append_to_log = 1;
		ins_req.metadata.gc_request = 1;
		ins_req.metadata.recovery_request = 0;
		ins_req.metadata.level_id = 0;
		ins_req.metadata.special_split = 0;
		ins_req.metadata.tombstone = 0;
		ins_req.metadata.key_format = KV_FORMAT;
		ins_req.metadata.cat = BIG_INLOG;
		const char *error_message = btree_insert_key_value(&ins_req);

		if (error_message) {
			log_fatal("Insert failed %s", error_message);
			BUG_ON();
		}
	}
}

int8_t find_deleted_kv_pairs_in_segment(struct db_handle handle, struct gc_segment_descriptor *log_seg, stack *marks)
{
	struct gc_segment_descriptor iter_log_segment = *log_seg;
	char *log_segment_in_device = REAL_ADDRESS(log_seg->segment_dev_offt);
	struct splice *kv = NULL;
	uint64_t checked_segment_chunk = get_lsn_size();
	uint64_t segment_data = LOG_DATA_OFFSET;
	int garbage_collect_segment = 0;

	iter_log_segment.log_segment_in_memory += get_lsn_size();
	log_segment_in_device += get_lsn_size();

	uint32_t key_value_size = get_kv_metadata_size();
	marks->size = 0;

	while (checked_segment_chunk < segment_data) {
		kv = (struct splice *)iter_log_segment.log_segment_in_memory;

		if (!kv->key_size)
			break;

		struct lookup_operation get_op = { .db_desc = handle.db_desc,
						   .found = 0,
						   .size = 0,
						   .buffer_to_pack_kv = NULL,
						   .buffer_overflow = 0,
						   .key_buf = (char *)kv,
						   .retrieve = 0 };
		find_key(&get_op);

		if (!get_op.found || log_segment_in_device != get_op.key_device_address)
			garbage_collect_segment = 1;
		else
			push_stack(marks, iter_log_segment.log_segment_in_memory);

		if (kv->key_size) {
			uint32_t bytes_to_move = kv->key_size + kv->value_size + key_value_size + get_lsn_size();
			iter_log_segment.log_segment_in_memory += bytes_to_move;
			log_segment_in_device += bytes_to_move;
			checked_segment_chunk += kv->key_size + kv->value_size + key_value_size + get_lsn_size();
		} else
			break;
	}

	assert(marks->size < STACK_SIZE);

	if (garbage_collect_segment) {
		move_kv_pairs_to_new_segment(handle, marks);
		gc_executed = 1;
		return 1;
	}
	return 0;
}

// read a segment and store it into segment_buf
static void fetch_segment(struct log_segment *segment_buf, uint64_t segment_offt)
{
	off_t dev_offt = segment_offt;
	ssize_t bytes_to_read = 0;

	assert(segment_offt % SEGMENT_SIZE == 0);

	while (bytes_to_read < SEGMENT_SIZE) {
		ssize_t bytes =
			pread(FD, &segment_buf[bytes_to_read], SEGMENT_SIZE - bytes_to_read, dev_offt + bytes_to_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			BUG_ON();
		}
		bytes_to_read += bytes;
	}
}

void scan_db(db_descriptor *db_desc, volume_descriptor *volume_desc, stack *marks)
{
	struct accum_segments {
		unsigned *segment_moved;
		uint64_t segment_dev_offt;
		unsigned garbage_bytes;
	};
	struct accum_segments *segments_toreclaim = calloc(SEGMENTS_TORECLAIM, sizeof(struct accum_segments));
	struct db_handle temp_handle = { .db_desc = db_desc, .volume_desc = volume_desc };
	struct log_segment *segment;
	uint32_t segment_count = 0;

	if (posix_memalign((void **)&segment, ALIGNMENT_SIZE, SEGMENT_SIZE) != 0) {
		log_fatal("MEMALIGN FAILED");
		BUG_ON();
	}

	log_segment *last_segment = (log_segment *)REAL_ADDRESS(db_desc->big_log.tail_dev_offt);
	struct large_log_segment_gc_entry *current_segment = NULL, *tmp, *segment_ht = db_desc->segment_ht;

	MUTEX_LOCK(&db_desc->segment_ht_lock);
	HASH_ITER(hh, segment_ht, current_segment, tmp)
	{
		assert(current_segment);
		if (REAL_ADDRESS(current_segment->segment_dev_offt) != last_segment) {
			// If we get a segment with 0 garbage bytes it is fatal! The gc thread should only check for segments that contain invalid data.
			assert(current_segment->garbage_bytes > 0);

			if (!current_segment->segment_moved) {
				segments_toreclaim[segment_count].segment_dev_offt = current_segment->segment_dev_offt;
				segments_toreclaim[segment_count].segment_moved = &current_segment->segment_moved;
				segments_toreclaim[segment_count++].garbage_bytes = current_segment->garbage_bytes;
			}

			if (segment_count == SEGMENTS_TORECLAIM)
				break;
		}
	}
	MUTEX_UNLOCK(&db_desc->segment_ht_lock);

	temp_handle.db_desc = db_desc;

	for (uint32_t i = 0; i < segment_count; ++i) {
		uint64_t segment_dev_offt = segments_toreclaim[i].segment_dev_offt;

		fetch_segment(segment, segment_dev_offt);

		if (*segments_toreclaim[i].segment_moved)
			continue;

		struct gc_segment_descriptor gc_segment = { .log_segment_in_memory = segment->data,
							    .segment_dev_offt = segment_dev_offt };
		int ret = find_deleted_kv_pairs_in_segment(temp_handle, &gc_segment, marks);

		if (ret)
			*segments_toreclaim[i].segment_moved = 1;
	}

	free(segment);
	free(segments_toreclaim);
}

void *gc_log_entries(void *hd)
{
	struct timespec ts;
	uint64_t gc_interval;
	stack *marks;
	struct db_handle *handle = (struct db_handle *)hd;
	db_descriptor *db_desc;
	volume_descriptor *volume_desc = handle->volume_desc;
	struct klist_node *region;

	if (!gc_active)
		pthread_exit(NULL);

	marks = calloc(1, sizeof(stack));
	if (!marks) {
		log_error("ERROR i could not allocate stack");
		BUG_ON();
	}

	pthread_setname_np(pthread_self(), "gcd");

	gc_interval = handle->db_options.options[GC_INTERVAL].value;

	log_debug("Starting garbage collection thread");

	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("FATAL: clock_gettime failed)\n");
			_Exit(-1);
		}
		ts.tv_sec += (gc_interval / 1000000L);
		ts.tv_nsec += (gc_interval % 1000000L) * 1000L;
		sleep(gc_interval);

		if (volume_desc->state == VOLUME_IS_CLOSING || volume_desc->state == VOLUME_IS_CLOSED) {
			log_debug("GC thread exiting %s", volume_desc->volume_id);
			free(marks);
			pthread_exit(NULL);
		}

		int init_loop_condition = 1;
		while (1) {
			if (init_loop_condition) {
				MUTEX_LOCK(&init_lock);
				region = klist_get_first(volume_desc->open_databases);
				init_loop_condition = 0;
			} else
				region = region->next;

			if (!region) {
				MUTEX_UNLOCK(&init_lock);
				break;
			}

			db_desc = (db_descriptor *)region->data;
			++db_desc->reference_count;
			db_desc->gc_scanning_db = true;
			MUTEX_UNLOCK(&init_lock);

			scan_db(db_desc, volume_desc, marks);

			MUTEX_LOCK(&init_lock);
			--db_desc->reference_count;
			db_desc->gc_scanning_db = false;
		}
	}

	pthread_exit(NULL);
}
