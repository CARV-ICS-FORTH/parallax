#include "level_write_appender.h"
#include "btree.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <string.h>
#include <unistd.h>

struct level_write_appender {
	uint64_t first_segment_offt[MAX_HEIGHT];
	uint64_t last_segment_offt[MAX_HEIGHT];
	struct db_handle *handle;
	uint32_t level_id;
	int fd;
};

level_write_appender_t wappender_init(struct db_handle *handle, uint8_t tree_id, uint8_t level_id)
{
	struct level_write_appender *appender = NULL;
	if (posix_memalign((void **)&appender, ALIGNMENT, sizeof(struct level_write_appender)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}
	memset(appender, 0x00, sizeof(struct level_write_appender));
	appender->level_id = level_id;
	appender->fd = handle->db_desc->db_volume->vol_fd;
	appender->handle = handle;

	for (uint32_t height = 0; height < MAX_HEIGHT; ++height) {
		struct segment_header *segment = get_segment_for_lsm_level_IO(handle->db_desc, level_id, tree_id);
		appender->last_segment_offt[height] = ABSOLUTE_ADDRESS(segment);
		assert(appender->last_segment_offt[height]);
		appender->first_segment_offt[height] = appender->last_segment_offt[height];
	}

	return appender;
}

static void wappender_write_segment(struct level_write_appender *appender,
				    struct wappender_append_index_segment_params params)
{
	ssize_t total_bytes_written = 0;
	while (total_bytes_written < params.buffer_size) {
		ssize_t bytes_written = pwrite(appender->fd, &params.buffer[total_bytes_written],
					       params.buffer_size - total_bytes_written,
					       appender->last_segment_offt[params.height] + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

uint64_t wappender_allocate_space(level_write_appender_t appender)
{
	assert(appender);

	struct segment_header *new_device_segment =
		get_segment_for_lsm_level_IO(appender->handle->db_desc, appender->level_id, 1);
	uint64_t new_device_segment_offt = ABSOLUTE_ADDRESS(new_device_segment);
	assert(new_device_segment && new_device_segment_offt);
	return new_device_segment_offt;
}

static void wappender_stich_level(level_write_appender_t appender, struct wappender_append_index_segment_params params)
{
	struct segment_header *curr_in_mem_segment = (struct segment_header *)params.buffer;

	if (MAX_HEIGHT - 1 == params.height) {
		appender->handle->db_desc->levels[appender->level_id].last_segment[1] =
			REAL_ADDRESS(appender->last_segment_offt[params.height]);
		assert(appender->last_segment_offt[params.height]);
		curr_in_mem_segment->next_segment = NULL;
		return;
	}
	assert(appender->last_segment_offt[params.height + 1]);
	curr_in_mem_segment->next_segment = (void *)appender->first_segment_offt[params.height + 1];
}

uint64_t wappender_get_last_segment_offt(level_write_appender_t appender, uint32_t height)
{
	return appender->last_segment_offt[height];
}

void wappender_append_index_segment(level_write_appender_t appender,
				    struct wappender_append_index_segment_params params)
{
	assert(appender);
	assert(params.buffer_size == SEGMENT_SIZE);
	if (params.is_last_segment) {
		wappender_stich_level(appender, params);
		wappender_write_segment(appender, params);
		return;
	}

	struct segment_header *current_in_mem_segment = (struct segment_header *)params.buffer;
	current_in_mem_segment->next_segment = (void *)params.next_device_offt;

	wappender_write_segment(appender, params);
	appender->last_segment_offt[params.height] = params.next_device_offt;
}

void wappender_close(level_write_appender_t appender)
{
	memset(appender, 0x00, sizeof(struct level_write_appender));
	free(appender);
}

int wappender_get_fd(level_write_appender_t appender)
{
	return appender->fd;
}
