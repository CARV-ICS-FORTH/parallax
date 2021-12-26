#define _GNU_SOURCE
#include "gc.h"
#include "../allocator/log_structures.h"
#include "../allocator/volume_manager.h"
#include "btree.h"
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
		int key_size = *(uint32_t *)kv_address;
		int value_size = *(uint32_t *)(kv_address + 4 + key_size);
		/* assert(key_size > 5 && key_size < 27); */
		/* assert(value_size > 5 && value_size < 1500); */
		ins_req.metadata.kv_size = key_size + 8 + value_size;
		ins_req.metadata.key_format = KV_FORMAT;
		ins_req.metadata.cat = BIG_INLOG;
		_insert_key_value(&ins_req);
	}
}

int8_t find_deleted_kv_pairs_in_segment(struct db_handle handle, char *log_seg, stack *marks)
{
	struct splice *key;
	struct splice *value;
	void *value_as_pointer;
	char *start_of_log_segment = log_seg;
	uint64_t size_of_log_segment_checked = 8;
	uint64_t log_data_without_metadata = LOG_DATA_OFFSET;
	uint64_t remaining_space = LOG_DATA_OFFSET;
	int key_value_size;
	int garbage_collect_segment = 0;

	log_seg += 8;
	key = (struct splice *)log_seg;
	key_value_size = sizeof(key->size) * 2;
	marks->size = 0;

	while (size_of_log_segment_checked < log_data_without_metadata && remaining_space >= 18) {
		key = (struct splice *)log_seg;
		value = (struct splice *)(VALUE_SIZE_OFFSET(key->size, log_seg));
		value_as_pointer = (VALUE_SIZE_OFFSET(key->size, log_seg));

		if (!key->size)
			break;

		assert(key->size > 0 && key->size < 28);
		assert(value->size > 5 && value->size <= 2000);
		struct lookup_operation get_op = { .db_desc = handle.db_desc,
						   .found = 0,
						   .size = 0,
						   .buffer_to_pack_kv = NULL,
						   .buffer_overflow = 1,
						   .kv_buf = (char *)key,
						   .retrieve = 0 };
		find_key(&get_op);
		/* assert(find_value); */
		/* assert(value_as_pointer == find_value); */
		if (remaining_space >= 18 && (!get_op.found || value_as_pointer != get_op.value_device_address))
			garbage_collect_segment = 1;
		else if (remaining_space >= 18 && (get_op.found && value_as_pointer == get_op.value_device_address))
			push_stack(marks, log_seg);

		if (key->size != 0 && remaining_space >= 18) {
			log_seg += key->size + value->size + key_value_size + 8;
			size_of_log_segment_checked += key->size + value->size + key_value_size + 8;
			remaining_space = LOG_DATA_OFFSET - (uint64_t)(log_seg - start_of_log_segment);
		} else
			break;
	}

	assert(marks->size < STACK_SIZE);

	if (garbage_collect_segment) {
		move_kv_pairs_to_new_segment(handle, marks);
		return 1;
	}
	return 0;
}

// read a segment and store it into segment_buf
static void fetch_segment(struct log_segment *segment_buf, uint64_t segment_offt)
{
	off_t dev_offt = segment_offt;
	ssize_t bytes_to_read = 0;
	ssize_t bytes = 0;

	assert(segment_offt % SEGMENT_SIZE == 0);

	while (bytes_to_read < SEGMENT_SIZE) {
		bytes = pread(FD, &segment_buf[bytes_to_read], SEGMENT_SIZE - bytes_to_read, dev_offt + bytes_to_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			assert(0);
			exit(EXIT_FAILURE);
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
	int segment_count = 0;

	if (posix_memalign((void **)&segment, ALIGNMENT_SIZE, SEGMENT_SIZE) != 0) {
		log_fatal("MEMALIGN FAILED");
		exit(EXIT_FAILURE);
	}

	log_segment *last_segment = (log_segment *)REAL_ADDRESS(db_desc->big_log.tail_dev_offt);
	struct large_log_segment_gc_entry *current_segment, *tmp, *segment_ht = db_desc->segment_ht;

	MUTEX_LOCK(&db_desc->segment_ht_lock);
	HASH_ITER(hh, segment_ht, current_segment, tmp)
	{
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

	for (int i = 0; i < segment_count; ++i) {
		fetch_segment(segment, segments_toreclaim[i].segment_dev_offt);

		if (*segments_toreclaim[i].segment_moved)
			continue;

		int ret = find_deleted_kv_pairs_in_segment(temp_handle, (char *)segment, marks);

		if (ret && !segments_toreclaim[i].segment_moved)
			*segments_toreclaim[i].segment_moved = 1;
	}

	free(segment);
	free(segments_toreclaim);
}

void *gc_log_entries(void *handle)
{
	struct timespec ts;
	uint64_t gc_interval;
	stack *marks;
	struct lib_option *option;
	struct db_handle *han = (struct db_handle *)handle;
	db_descriptor *db_desc = han->db_desc;
	volume_descriptor *volume_desc = han->volume_desc;
	struct klist_node *region;
	struct lib_option *dboptions = NULL;

	marks = calloc(1, sizeof(stack));
	if (!marks) {
		log_error("ERROR i could not allocate stack");
		exit(EXIT_FAILURE);
	}

	pthread_setname_np(pthread_self(), "gcd");

	parse_options(&dboptions);
	HASH_FIND_STR(dboptions, "gc_interval", option);
	check_option("gc_interval", option);
	gc_interval = option->value.count;

	log_debug("Starting garbage collection thread");

	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("FATAL: clock_gettime failed)\n");
			exit(-1);
		}
		ts.tv_sec += (gc_interval / 1000000L);
		ts.tv_nsec += (gc_interval % 1000000L) * 1000L;
		sleep(gc_interval);

		if (volume_desc->state == VOLUME_IS_CLOSING || volume_desc->state == VOLUME_IS_CLOSED) {
			log_debug("GC thread exiting %s", volume_desc->volume_id);
			free(marks);
			pthread_exit(NULL);
		}

		region = klist_get_first(volume_desc->open_databases);

		while (region != NULL) {
			db_desc = (db_descriptor *)region->data;
			scan_db(db_desc, volume_desc, marks);
			region = region->next;
		}
	}

	pthread_exit(NULL);
}
