#define STATS_NO

#define DIRTY_BYTES uint32_t dirty_bytes;

#define STATISTICS                                                                                                     \
	uint64_t leaf_cow_events;                                                                                      \
	uint64_t inner_cow_events;                                                                                     \
	uint64_t leaf_splits;                                                                                          \
	uint64_t index_splits;                                                                                         \
	uint64_t wasted_leaf_bytes;                                                                                    \
	uint64_t index_merge;                                                                                          \
	uint64_t leaf_merge;                                                                                           \
	uint64_t purges;                                                                                               \
	uint64_t leaf_collisions;

#define INIT_DB_STATS                                                                                                  \
	open_dbs[i].leaf_cow_events = 0;                                                                               \
	open_dbs[i].inner_cow_events = 0;                                                                              \
	open_dbs[i].leaf_splits = 0;                                                                                   \
	open_dbs[i].index_splits = 0;                                                                                  \
	open_dbs[i].purges = 0;                                                                                        \
	open_dbs[i].leaf_merge = 0;                                                                                    \
	open_dbs[i].index_merge = 0;                                                                                   \
	open_dbs[i].leaf_collisions = 0;

#define INC_MERGE                                                                                                      \
	if (type == internalNode) {                                                                                    \
		handle->index_merge++;                                                                                 \
	} else {                                                                                                       \
		handle->leaf_merge++;                                                                                  \
	}

#define INC_PURGE handle->purges++;

#define INC_LEAF_COW_EVENTS req->handle->leaf_cow_events++;

#define INC_INDEX_COW_EVENTS req->handle->inner_cow_events++;

#define INC_LEAF_SPLITS req->handle->leaf_splits++;

#define INC_INDEX_SPLITS req->handle->index_splits++;

#define INC_DIRTY_BYTES

#define INIT_DIRTY_BYTES

#define INC_LEAF_COLLISIONS req->handle->leaf_collisions++;
