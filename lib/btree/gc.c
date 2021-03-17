#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <log.h>
#include <list.h>
#include <uthash.h>
#include "gc.h"
#include "set_options.h"
#include "../allocator/allocator.h"

extern sem_t gc_daemon_interrupts;

char *pointer_to_kv_in_log = NULL;

void push_stack(stack *marks, void *addr)
{
	marks->valid_pairs[marks->size++] = addr;
	assert(marks->size != STACK_SIZE);
}

/* TODO use the marks stack instead of reiterating
   the whole segment to find the non deleted kv pairs. */
void move_kv_pairs_to_new_segment(volume_descriptor *volume_desc, db_descriptor *db_desc, stack *marks)
{
	bt_insert_req ins_req;
	db_handle handle = { .volume_desc = volume_desc, .db_desc = db_desc };
	char *kv_address;
	int i;

	for (i = 0; i < marks->size; ++i, ++db_desc->gc_keys_transferred) {
		kv_address = marks->valid_pairs[i];
		pointer_to_kv_in_log = kv_address;
		//struct splice *key = (struct splice *)kv_address;
		//struct splice *value = (struct splice *)(kv_address + VALUE_SIZE_OFFSET(key->size));
		handle.volume_desc = volume_desc;
		handle.db_desc = db_desc;
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
		//update_key_value_pointer(&handle, key->data, value->data, key->size, value->size);
	}
}

int8_t find_deleted_kv_pairs_in_segment(volume_descriptor *volume_desc, db_descriptor *db_desc, char *log_seg,
					stack *marks)
{
	struct db_handle handle = { .volume_desc = volume_desc, .db_desc = db_desc };
	struct splice *key;
	struct splice *value;
	void *value_as_pointer;
	void *find_value;
	char *start_of_log_segment = log_seg;
	uint64_t size_of_log_segment_checked = 8;
	uint64_t log_data_without_metadata = LOG_DATA_OFFSET;
	uint64_t remaining_space;
	int key_value_size;
	int garbage_collect_segment = 0;
	log_seg += 8;
	key = (struct splice *)log_seg;
	key_value_size = sizeof(key->size) * 2;
	marks->size = 0;
	remaining_space = LOG_DATA_OFFSET - (uint64_t)(log_seg - start_of_log_segment);

	while (size_of_log_segment_checked < log_data_without_metadata && remaining_space >= 18) {
		key = (struct splice *)log_seg;
		value = (struct splice *)(VALUE_SIZE_OFFSET(key->size, log_seg));
		value_as_pointer = (VALUE_SIZE_OFFSET(key->size, log_seg));
		if (!key->size)
			break;

		assert(key->size > 5 && key->size < 28);
		assert(value->size > 5 && value->size < 1500);
		/* log_info("looking up %*s",key->size,key->data); */

		find_value = find_key(&handle, key->data, key->size);
		/* assert(find_value); */
		/* assert(value_as_pointer == find_value); */
		if (remaining_space >= 18 && (find_value == NULL || value_as_pointer != find_value)) {
			garbage_collect_segment = 1;
		} else if (remaining_space >= 18 && (find_value != NULL && value_as_pointer == find_value)) {
			push_stack(marks, log_seg);
		}

		if (key->size != 0 && remaining_space >= 18) {
			log_seg += key->size + value->size + key_value_size + 8;
			size_of_log_segment_checked += key->size + value->size + key_value_size + 8;
			remaining_space = LOG_DATA_OFFSET - (uint64_t)(log_seg - start_of_log_segment);
		} else
			break;
	}

	assert(marks->size < STACK_SIZE);
	if (garbage_collect_segment) {
		move_kv_pairs_to_new_segment(volume_desc, db_desc, marks);
		return 1;
	}
	return 0;
}

void fix_nodes_in_log(volume_descriptor *volume_desc, db_descriptor *db_desc, log_segment *prev_node,
		      log_segment *curr_node)
{
	return;
	if (prev_node) {
		prev_node->metadata.next_segment = curr_node->metadata.next_segment;
		free_block(volume_desc, curr_node, BUFFER_SEGMENT_SIZE, -1);
	} else
		db_desc->big_log_head = (segment_header *)REAL_ADDRESS((uint64_t)curr_node->metadata.next_segment);
}

void iterate_log_segments(db_descriptor *db_desc, volume_descriptor *volume_desc, stack *marks)
{
	log_segment *last_segment = (log_segment *)db_desc->big_log_tail;
	log_segment *log_node = (log_segment *)db_desc->big_log_head;
	log_segment *prev_node = NULL;

	/* We are in the first segment of the log and is not yet full! */
	if (!log_node || log_node->metadata.next_segment == NULL) {
		log_debug("We reached at the last log segment");
		return;
	}

	while (REAL_ADDRESS(log_node->metadata.next_segment) != last_segment) {
		int8_t ret = find_deleted_kv_pairs_in_segment(volume_desc, db_desc, log_node->data, marks);

		if (ret == 1)
			fix_nodes_in_log(volume_desc, db_desc, prev_node, log_node);

		prev_node = log_node;
		log_node = (log_segment *)REAL_ADDRESS((uint64_t)log_node->metadata.next_segment);
	}

	/* while (log_node != (void *)db_desc->big_log_tail) { */
	/* 	uint64_t start_id = log_node->metadata.segment_id; */
	/* 	uint64_t end_id = db_desc->big_log_tail->segment_id; */

	/* 	while ((end_id - start_id) / 3 <= 0) { */
	/* 		sleep(1); */
	/* 		start_id = log_node->metadata.segment_id; */
	/* 		end_id = db_desc->big_log_tail->segment_id; */
	/* 	} */

	/* 	uint64_t num_segments_to_check = (end_id - start_id) / 3; */
	/* 	/\* log_warn("Num segments to check %llu start id %llu end id %llu",num_segments_to_check,start_id,end_id); *\/ */
	/* 	while (num_segments_to_check != 0 && log_node != (void *)db_desc->big_log_tail) { */
	/* 		db_desc->gc_last_segment_id = log_node->metadata.segment_id; */
	/* 		int8_t ret = find_deleted_kv_pairs_in_segment(volume_desc, db_desc, log_node->data, marks); */

	/* 		if (ret == 1) */
	/* 			fix_nodes_in_log(volume_desc, db_desc, prev_node, log_node); */

	/* 		prev_node = log_node; */
	/* 		log_node = (log_segment *)REAL_ADDRESS((uint64_t)log_node->metadata.next_segment); */
	/* 		--num_segments_to_check; */
	/* 	} */
	/* 	sleep(1); */
	/* } */

	/* The log had multiple nodes and we reached at the last one! */
	if (REAL_ADDRESS(log_node->metadata.next_segment) == last_segment) {
		log_debug("We reached at the last log segment");
		return;
	}

	log_fatal("Log is corrupted!");
	assert(0);
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
	NODE *region;
	/* int rc; */

	marks = malloc(sizeof(stack));
	if (!marks) {
		log_error("ERROR i could not allocate stack");
		exit(EXIT_FAILURE);
	}

	HASH_FIND_STR(dboptions, "gc_interval", option);
	check_option("gc_interval", option);
	gc_interval = option->value.count * SEC;

	log_debug("Starting garbage collection thread");
	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("FATAL: clock_gettime failed)\n");
			exit(-1);
		}
		ts.tv_sec += (gc_interval / 1000000L);
		ts.tv_nsec += (gc_interval % 1000000L) * 1000L;
		/* sleep(1); */
		sem_wait(&gc_daemon_interrupts);

		/* MUTEX_LOCK(&volume_desc->gc_mutex); */
		/* rc = pthread_cond_timedwait(&volume_desc->gc_cond, &volume_desc->gc_mutex, &ts); */
		/* MUTEX_UNLOCK(&volume_desc->gc_mutex); */

		/* if (rc != ETIMEDOUT) { */
		/* 	log_debug("Error in GC thread"); */
		/* 	exit(EXIT_FAILURE); */
		/* } */

		log_debug("Initiating garbage collection");

		if (volume_desc->state == VOLUME_IS_CLOSING || volume_desc->state == VOLUME_IS_CLOSED) {
			log_debug("GC thread exiting %s", volume_desc->volume_id);
			free(marks);
			pthread_exit(NULL);
		}

		iterate_log_segments(db_desc, volume_desc, marks);
		if (volume_desc->open_databases) {
			region = get_first(volume_desc->open_databases);

			while (region != NULL) {
				db_desc = (db_descriptor *)region->data;
				iterate_log_segments(db_desc, volume_desc, marks);
				region = region->next;
			}
			log_debug("Garbage Collection Finished");
		}
	}

	return NULL;
}
