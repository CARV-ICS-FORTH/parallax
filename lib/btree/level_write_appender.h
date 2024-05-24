#ifndef LEVEL_WRITE_APPENDER_H
#define LEVEL_WRITE_APPENDER_H
#include <stdint.h>
struct db_handle;
typedef struct level_write_appender *level_write_appender_t;

/**
 *@brief Initialize and return a new level_write_cursor object
 *@param handle: the handle of an initialized db
 *@param tree_id: the tree_id for which the allocations will take place
 *@level_id level_id: the level of the level write appender (the destination level of a "compaction")
*/
level_write_appender_t wappender_init(struct db_handle *handle, uint8_t level_id);

// parameters of function wappender_append_index_segment
struct wappender_append_index_segment_params {
	uint64_t segment_offt;
	char *buffer;
	uint32_t buffer_size;
};

/**
 *@brief Given a buffer, the function appends the buffer in the compaction index approprietly.
 *@oaram appender: An initialized level_write_appender object
 *@param params: an initialized struct wappender_appender_index_segment params with metadata for the buffer to be inserted in the compaction index
 */
void wappender_append_index_segment(level_write_appender_t appender, struct wappender_append_index_segment_params);

/**
 *@brief Closes and frees the space if an initialized level_write_appender object
 *@param appender: the object to be freed
 */
void wappender_close(level_write_appender_t appender);

/**
 *@brief Retrieves the file descriptor of an level_write_appender object
 *@param appender: the object from which the file descriptor is retrieved
 */
int wappender_get_fd(level_write_appender_t appender);

/**
 * @brief retursn the last segment offt for the specific height segment list. (which is the segment to be written)
 * @param appender: An initialized level_write_appender object
 * @param height: The height from which the last segment offt is retrieved
 */
uint64_t wappender_get_last_segment_offt(level_write_appender_t appender, uint32_t height);

uint64_t wappender_allocate_space(level_write_appender_t appender);

uint32_t wappender_get_level_id(level_write_appender_t appender);
#endif // LEVEL_WRITE_APPENDER_H
