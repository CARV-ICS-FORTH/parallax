#include "level_write_appender.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "btree.h"
#include "conf.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct level_write_appender {
	struct db_handle *handle;
	uint32_t level_id;
	int fd;
};

level_write_appender_t wappender_init(struct db_handle *handle, uint8_t level_id)
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

	return appender;
}

static void wappender_write_segment(struct level_write_appender *appender,
				    struct wappender_append_index_segment_params params)
{
	ssize_t total_bytes_written = 0;
	while (total_bytes_written < params.buffer_size) {
		ssize_t bytes_written = pwrite(appender->fd, &params.buffer[total_bytes_written],
					       params.buffer_size - total_bytes_written,
					       params.segment_offt + total_bytes_written);
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

void wappender_append_index_segment(level_write_appender_t appender,
				    struct wappender_append_index_segment_params params)
{
	assert(appender);
	assert(params.buffer_size == SEGMENT_SIZE);

	wappender_write_segment(appender, params);
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

uint32_t wappender_get_level_id(level_write_appender_t appender)
{
	assert(appender);
	return appender->level_id;
}
