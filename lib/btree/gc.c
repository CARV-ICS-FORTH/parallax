#define _GNU_SOURCE
#include "gc.h"
#include "../allocator/volume_manager.h"
#include "../scanner/scanner.h"
#include "set_options.h"
#include <assert.h>
#include <list.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <uthash.h>
extern sem_t gc_daemon_interrupts;

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
		// struct splice *key = (struct splice *)kv_address;
		// struct splice *value = (struct splice *)(kv_address +
		// VALUE_SIZE_OFFSET(key->size));
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
		// update_key_value_pointer(&handle, key->data, value->data, key->size,
		// value->size);
	}
}

int8_t find_deleted_kv_pairs_in_segment(volume_descriptor *volume_desc, db_descriptor *db_desc, char *log_seg,
					stack *marks)
{
	struct db_handle handle = { .volume_desc = volume_desc, .db_desc = db_desc };
	struct splice *key;
	struct splice *value;
	void *value_as_pointer;
	char *start_of_log_segment = log_seg;
	struct segment_header *segment = (struct segment_header *)start_of_log_segment;
	uint64_t size_of_log_segment_checked = 8;
	uint64_t log_data_without_metadata = LOG_DATA_OFFSET;
	uint64_t remaining_space;
	int key_value_size;
	int garbage_collect_segment = 0;
	log_seg += 8 + sizeof(segment_header);
	key = (struct splice *)log_seg;
	key_value_size = sizeof(key->size) * 2;
	marks->size = 0;
	remaining_space = LOG_DATA_OFFSET - (uint64_t)(log_seg - start_of_log_segment);

	if (((struct segment_header *)start_of_log_segment)->moved_kvs)
		return 0;

	while (size_of_log_segment_checked < log_data_without_metadata && remaining_space >= segment->segment_end &&
	       remaining_space >= 18) {
		key = (struct splice *)log_seg;
		value = (struct splice *)(VALUE_SIZE_OFFSET(key->size, log_seg));
		value_as_pointer = (VALUE_SIZE_OFFSET(key->size, log_seg));
		if (!key->size)
			break;

		assert(key->size > 0 && key->size < 28);
		assert(value->size > 5 && value->size < 1500);
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
		if (remaining_space >= 18 && (!get_op.found || value_as_pointer != get_op.kv_device_address)) {
			garbage_collect_segment = 1;
		} else if (remaining_space >= 18 && (get_op.found && value_as_pointer == get_op.kv_device_address)) {
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

static void free_block(struct volume_descriptor *v, void *addr, uint32_t size)
{
	(void)v;
	(void)addr;
	(void)size;
}
void fix_nodes_in_log(volume_descriptor *volume_desc, db_descriptor *db_desc, log_segment *prev_node,
		      log_segment *curr_node)
{
	return;
	if (prev_node) {
		prev_node->metadata.next_segment = curr_node->metadata.next_segment;
		free_block(volume_desc, curr_node, SEGMENT_SIZE);
	} else
		db_desc->big_log.head_dev_offt = (uint64_t)curr_node->metadata.next_segment;
}

void iterate_log_segments(db_descriptor *db_desc, volume_descriptor *volume_desc, stack *marks)
{
	log_segment *last_segment = (log_segment *)REAL_ADDRESS(db_desc->big_log.tail_dev_offt);
	log_segment *log_node = (log_segment *)REAL_ADDRESS(db_desc->big_log.head_dev_offt);
	log_segment *prev_node = NULL;
	log_info("last_segment %llu log_node %llu last_seg offt %llu log node offt %llu", last_segment, log_node,
		 db_desc->big_log.tail_dev_offt, db_desc->big_log.head_dev_offt);
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
	/* 	/\* log_warn("Num segments to check %llu start id %llu end id
   * %llu",num_segments_to_check,start_id,end_id); *\/ */
	/* 	while (num_segments_to_check != 0 && log_node != (void
   * *)db_desc->big_log_tail) { */
	/* 		db_desc->gc_last_segment_id = log_node->metadata.segment_id; */
	/* 		int8_t ret = find_deleted_kv_pairs_in_segment(volume_desc,
   * db_desc, log_node->data, marks); */

	/* 		if (ret == 1) */
	/* 			fix_nodes_in_log(volume_desc, db_desc, prev_node,
   * log_node);
   */

	/* 		prev_node = log_node; */
	/* 		log_node = (log_segment
   * *)REAL_ADDRESS((uint64_t)log_node->metadata.next_segment); */
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

static struct db_descriptor *find_dbdesc(volume_descriptor *volume_desc, int group_id, int index)
{
	struct klist_node *region;
	struct db_descriptor *db_desc;

	for (region = klist_get_first(volume_desc->open_databases); region; region = region->next) {
		db_desc = (db_descriptor *)region->data;
		if (db_desc->group_id == group_id && db_desc->group_index == index)
			return db_desc;
	}

	return NULL;
}

// read a segment and store it into segment_buf
static void fetch_segment(struct segment_header *segment_buf, uint64_t segment_offt)
{
	assert(segment_offt % SEGMENT_SIZE == 0);
	off_t dev_offt = segment_offt;
	ssize_t bytes_to_read = 0;
	ssize_t bytes = 0;
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
		uint64_t segment_offt;
		struct gc_value value;
	};
	struct accum_segments *segments_toreclaim = calloc(SEGMENTS_TORECLAIM, sizeof(struct accum_segments));
	struct db_handle handle = { .db_desc = db_desc, .volume_desc = volume_desc };
	struct db_handle temp_handle = { .volume_desc = volume_desc };
	struct db_descriptor *temp_db_desc;
	char start_key[5] = { 0 };
	uint64_t *key;
	int segment_count = 0;

	struct gc_value *value;
	struct segment_header *segment;

	if (posix_memalign((void **)&segment, ALIGNMENT_SIZE, SEGMENT_SIZE) != 0) {
		log_fatal("MEMALIGN FAILED");
		exit(EXIT_FAILURE);
	}

	*(uint32_t *)start_key = 1;
	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	sc->type_of_scanner = FORWARD_SCANNER;
	assert(segments_toreclaim);

	if (!sc) {
		log_fatal("Error calloc did not allocate memory!");
		exit(EXIT_FAILURE);
	}

	init_dirty_scanner(sc, &handle, start_key, GREATER_OR_EQUAL);

	while (isValid(sc)) {
		key = get_key_ptr(sc);
		value = get_value_ptr(sc);
		if (!value->moved) {
			segments_toreclaim[segment_count].segment_offt = *key;
			segments_toreclaim[segment_count++].value = *value;
		}
		if (segment_count == SEGMENTS_TORECLAIM)
			break;

		if (getNext(sc) == END_OF_DATABASE) {
			break;
		}
	}

	closeScanner(sc);
	assert(segment_count <= SEGMENTS_TORECLAIM);

	for (int i = 0; i < segment_count; ++i) {
		fetch_segment(segment, segments_toreclaim[i].segment_offt);
		temp_db_desc = find_dbdesc(volume_desc, segments_toreclaim[i].value.group_id,
					   segments_toreclaim[i].value.index);
		temp_handle.db_desc = temp_db_desc;
		assert(temp_db_desc);

		int ret = find_deleted_kv_pairs_in_segment(temp_handle.volume_desc, temp_handle.db_desc,
							   (char *)segment, marks);

		if (ret && !segments_toreclaim[i].value.moved) {
			segment->moved_kvs = 1;
			segments_toreclaim[i].value.moved = 1;
		}

		insert_key_value(&handle, &segments_toreclaim[i].segment_offt, &segments_toreclaim[i].value,
				 sizeof(segments_toreclaim[i].segment_offt), sizeof(segments_toreclaim[i].value));
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
			if (!strcmp(db_desc->my_superblock.region_name, SYSTEMDB)) {
				scan_db(db_desc, volume_desc, marks);
				break;
			}
			region = region->next;
		}
	}

	return NULL;
}
