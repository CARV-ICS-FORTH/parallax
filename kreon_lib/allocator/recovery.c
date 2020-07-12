#include <signal.h>
#include <assert.h>
#include <sys/mman.h>
#include "allocator.h"
#include "../btree/btree.h"
#include "dmap-ioctl.h"
#include <log.h>

void load_logs_torecover(recovery_request *recover_req, struct recovery_operator *replay)
{
	unsigned replay_onelog_atleast = 0;

	if (recover_req->db_desc->commit_log->big_log_size < recover_req->db_desc->big_log_size) {
		log_warn("warning commit log should be larger than in memory log");
		++replay_onelog_atleast;
	}

	if (recover_req->db_desc->commit_log->medium_log_size < recover_req->db_desc->medium_log_size) {
		log_warn("warning commit log should be larger than in memory log");
		++replay_onelog_atleast;
	}

	if (recover_req->db_desc->commit_log->small_log_size < recover_req->db_desc->small_log_size) {
		log_warn("warning commit log should be larger than in memory log");
		++replay_onelog_atleast;
	}

	assert(!replay_onelog_atleast);

	log_info("starting recovery for db %s first big log segment %llu last big log last segment %llu",
		 recover_req->db_desc->db_name, (LLU)recover_req->db_desc->big_log_head,
		 (LLU)recover_req->db_desc->big_log_tail);

	log_info("starting recovery for db %s first medium log segment %llu last medium log last segment %llu",
		 recover_req->db_desc->db_name, (LLU)recover_req->db_desc->medium_log_head,
		 (LLU)recover_req->db_desc->medium_log_tail);

	log_info("starting recovery for db %s first small log segment %llu last small log last segment %llu",
		 recover_req->db_desc->db_name, (LLU)recover_req->db_desc->small_log_head,
		 (LLU)recover_req->db_desc->small_log_tail);

	recover_req->db_desc->lsn = recover_req->db_desc->commit_log->lsn;
	log_info("LSN is %llu", recover_req->db_desc->lsn);

	/*first, we need to check the L0_start_offset to which segment points to*/
	replay->big.segment_id = recover_req->big_log_start_offset / BUFFER_SEGMENT_SIZE;
	replay->medium.segment_id = recover_req->medium_log_start_offset / BUFFER_SEGMENT_SIZE;
	replay->small.segment_id = recover_req->small_log_start_offset / BUFFER_SEGMENT_SIZE;

	log_info("Big log start offset %llu maps to segment id %llu", (LLU)recover_req->db_desc->big_log_head_offset,
		 (LLU)replay->big.segment_id);

	log_info("Medium start offset %llu maps to segment id %llu", (LLU)recover_req->db_desc->medium_log_head_offset,
		 (LLU)replay->medium.segment_id);

	log_info("Small start offset %llu maps to segment id %llu", (LLU)recover_req->db_desc->small_log_head_offset,
		 (LLU)replay->small.segment_id);

	replay->big.log_curr_segment = (segment_header *)REAL_ADDRESS(recover_req->db_desc->commit_log->big_log_tail);
	replay->medium.log_curr_segment =
		(segment_header *)REAL_ADDRESS(recover_req->db_desc->commit_log->medium_log_tail);
	replay->small.log_curr_segment =
		(segment_header *)REAL_ADDRESS(recover_req->db_desc->commit_log->small_log_tail);

	replay->big.prev_segment_id = replay->medium.prev_segment_id = replay->small.prev_segment_id = 0;
	replay->big.log_offset = recover_req->big_log_start_offset;
	replay->medium.log_offset = recover_req->medium_log_start_offset;
	replay->small.log_offset = recover_req->small_log_start_offset;
	replay->big.log_size = recover_req->db_desc->commit_log->big_log_size;
	replay->medium.log_size = recover_req->db_desc->commit_log->medium_log_size;
	replay->small.log_size = recover_req->db_desc->commit_log->small_log_size;
}

segment_header *find_replay_offset(segment_header *current_log_segment, uint64_t segment_id)
{
	uint64_t previous_segment_id = 0;
	log_info("Segment id %llu last segment_id %llu", segment_id, current_log_segment->segment_id);

	while (current_log_segment->segment_id != segment_id) {
		previous_segment_id = current_log_segment->segment_id;
		current_log_segment = (segment_header *)REAL_ADDRESS(current_log_segment->prev_segment);

		if (previous_segment_id != current_log_segment->segment_id + 1) {
			log_fatal(
				"FATAL corrupted segments, segment ids are not sequential previous = %llu current = %llu",
				(LLU)previous_segment_id, (LLU)current_log_segment->segment_id);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}

		if (current_log_segment->segment_id < segment_id) {
			log_fatal("KV log corrupted segment id %llu not found", (LLU)segment_id);
			exit(EXIT_FAILURE);
		}
	}

	log_info("Segment id %llu first segment_id %llu", segment_id, current_log_segment->segment_id);

	return current_log_segment;
}

void set_replay_offset(struct recovery_operator *replay)
{
	replay->big.log_curr_segment = find_replay_offset(replay->big.log_curr_segment, replay->big.segment_id);
	replay->medium.log_curr_segment =
		find_replay_offset(replay->medium.log_curr_segment, replay->medium.segment_id);
	replay->small.log_curr_segment = find_replay_offset(replay->small.log_curr_segment, replay->small.segment_id);
	log_info("starting segment of big log %llu medium log %llu small log %llu found starting recovery procedure",
		 (LLU)replay->big.log_curr_segment->segment_id, (LLU)replay->medium.log_curr_segment->segment_id,
		 (LLU)replay->small.log_curr_segment->segment_id);
}

void ommit_log_segment_header(struct recovery_operator *replay)
{
	assert(NUMBER_OF_LOGS == 3);
	struct log_recovery_metadata *iter_logs[NUMBER_OF_LOGS] = { &replay->big, &replay->medium, &replay->small };

	for (int i = 0; i < NUMBER_OF_LOGS; ++i)
		if (iter_logs[i]->log_offset == 0)
			iter_logs[i]->log_offset += sizeof(segment_header);
}

void ommit_padded_space(struct recovery_operator *replay)
{
	assert(NUMBER_OF_LOGS == 3);
	struct log_recovery_metadata *iter_logs[NUMBER_OF_LOGS] = { &replay->big, &replay->medium, &replay->small };
	uint64_t remaining_bytes;
	uint32_t padded;

	for (int i = 0; i < NUMBER_OF_LOGS; ++i) {
		remaining_bytes = BUFFER_SEGMENT_SIZE - iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE;
		padded = *(uint32_t *)((char *)iter_logs[i]->log_curr_segment +
				       (iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE));
		if (iter_logs[i]->log_offset < iter_logs[i]->log_size) {
			if (iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE == 0 ||
			    remaining_bytes <= sizeof(uint32_t) || !padded) {
				if (remaining_bytes <= sizeof(uint32_t) || !padded)
					iter_logs[i]->log_offset += remaining_bytes;

				if (iter_logs[i]->log_curr_segment->next_segment == NULL)
					continue;

				uint64_t segment_id = iter_logs[i]->log_curr_segment->segment_id;
				iter_logs[i]->log_curr_segment =
					REAL_ADDRESS(iter_logs[i]->log_curr_segment->next_segment);
				log_info(
					"recovering segment = %llu padded space = %llu log offset %llu commit log offset %llu",
					(LLU)iter_logs[i]->log_curr_segment->segment_id,
					(LLU)(BUFFER_SEGMENT_SIZE - (iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE)),
					(LLU)iter_logs[i]->log_offset, (LLU)iter_logs[i]->log_size);
				mprotect(iter_logs[i]->log_curr_segment, BUFFER_SEGMENT_SIZE, PROT_READ);
				assert(segment_id + 1 == iter_logs[i]->log_curr_segment->segment_id);
				iter_logs[i]->log_offset += sizeof(segment_header);
			}
		}
	}
}

void advance_log_offset(struct log_recovery_metadata *log, char *kv_addr)
{
	kv_addr += sizeof(struct log_sequence_number);
	uint32_t key_size = KEY_SIZE(kv_addr), value_size = VALUE_SIZE(kv_addr + sizeof(uint32_t) + key_size);
	/* log_info("key %u value %u", key_size, value_size); */
	/* log_info("key %*s", key_size, kv_addr + 4); */
	/* log_info("value %*s", value_size, (kv_addr + 4 + key_size + 4)); */
	log->log_offset += sizeof(struct log_sequence_number) + key_size + value_size + 2 * sizeof(uint32_t);
}

void *find_next_kventry(struct recovery_operator *replay, uint64_t max_lsn, uint64_t *prev_lsn)
{
	assert(NUMBER_OF_LOGS == 3);

	struct log_recovery_metadata *iter_logs[NUMBER_OF_LOGS] = { &replay->big, &replay->medium, &replay->small };
	char *tmp_kv_addr, *kv_addr = NULL;
	struct log_sequence_number tmp_lsn, lsn;
	int pick_log = -1;
	lsn.id = UINT64_MAX;

	for (int i = 0; i < NUMBER_OF_LOGS; ++i) {
		if (iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE != 0 &&
		    iter_logs[i]->log_offset < iter_logs[i]->log_size) {
			tmp_kv_addr = ((char *)iter_logs[i]->log_curr_segment +
				       (iter_logs[i]->log_offset % BUFFER_SEGMENT_SIZE));
			tmp_lsn = *(struct log_sequence_number *)tmp_kv_addr;

			if (tmp_lsn.id < lsn.id) {
				lsn = tmp_lsn;
				pick_log = i;
				kv_addr = tmp_kv_addr;
			}
		}
	}

	if (*prev_lsn == 0 && pick_log != -1) {
		*prev_lsn = *(uint64_t *)kv_addr;
	}
	log_info("Picked prev %llu lsn.id %llu", *prev_lsn, lsn.id);
	assert(lsn.id >= *prev_lsn);
	assert(lsn.id < max_lsn);

	if (pick_log != -1) {
		*prev_lsn = *prev_lsn + 1;
		advance_log_offset(iter_logs[pick_log], kv_addr);
		return kv_addr + sizeof(struct log_sequence_number);
	}

	return NULL;
}

void mark_log_segments_before_replay(volume_descriptor *volume_desc, segment_header *first_segment)
{
	segment_header *curr_segment = first_segment;
	log_info("----------------------------------------------------------------");
	while (curr_segment) {
		mark_block(volume_desc, curr_segment, BUFFER_SEGMENT_SIZE, 0x00, NULL);
		log_info("Segment id %llu", curr_segment->segment_id);
		if (curr_segment->next_segment == NULL)
			break;
		curr_segment = REAL_ADDRESS(curr_segment->next_segment);
	}
}

void replay_log(recovery_request *rh, struct recovery_operator *replay)
{
	bt_insert_req ins_req;
	db_handle handle;
	void *kv_addr;
	uint64_t last_lsn;
	uint64_t prev_lsn = 0;

	handle.volume_desc = rh->volume_desc;
	handle.db_desc = rh->db_desc;
	last_lsn = handle.db_desc->lsn;

	mark_log_segments_before_replay(rh->volume_desc, replay->big.log_curr_segment);
	mark_log_segments_before_replay(rh->volume_desc, replay->medium.log_curr_segment);
	mark_log_segments_before_replay(rh->volume_desc, replay->small.log_curr_segment);

	mprotect(replay->big.log_curr_segment, BUFFER_SEGMENT_SIZE, PROT_READ);
	mprotect(replay->medium.log_curr_segment, BUFFER_SEGMENT_SIZE, PROT_READ);
	mprotect(replay->small.log_curr_segment, BUFFER_SEGMENT_SIZE, PROT_READ);

	while (replay->big.log_offset < replay->big.log_size || replay->medium.log_offset < replay->medium.log_size ||
	       replay->small.log_offset < replay->small.log_size) {
		ommit_log_segment_header(replay);
		kv_addr = find_next_kventry(replay, rh->db_desc->lsn, &prev_lsn);

		if (prev_lsn == 3855 || prev_lsn == 38532 || prev_lsn == 38533 || prev_lsn == 38537) {
			log_info("POINTER IS %llu", kv_addr - MAPPED);
			/* BREAKPOINT; */
		}

		if (kv_addr) {
			ins_req.key_value_buf = kv_addr;
			ins_req.metadata.handle = &handle;
			ins_req.metadata.level_id = 0;
			ins_req.metadata.key_format = KV_FORMAT;
			ins_req.metadata.append_to_log = 0;
			ins_req.metadata.gc_request = 0;
			ins_req.metadata.recovery_request = 1;
			_insert_key_value(&ins_req);
		}
		/* if(prev_lsn == 5) */
		/* 	break; */

		if (prev_lsn == last_lsn)
			break;

		ommit_padded_space(replay);
	}
	/* exit(0); */
}

void recovery_worker(recovery_request *rh)
{
	db_handle handle;
	struct recovery_operator replay;
	handle.volume_desc = rh->volume_desc;
	handle.db_desc = rh->db_desc;
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle.db_desc->lock_log);
#else
	SPIN_LOCK(&handle.db_desc->lock_log);
#endif

	load_logs_torecover(rh, &replay);
	set_replay_offset(&replay);
	replay_log(rh, &replay);

#if LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle.db_desc->lock_log);
#else
	SPIN_UNLOCK(&handle.db_desc->lock_log);
#endif
}
