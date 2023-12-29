#ifndef DEV_INDEX_H
#define DEV_INDEX_H
#include "device_level.h"
#include <stdbool.h>
struct level_index_api;

bool dev_idx_register(struct level_index_api *index_api);
#endif
