#ifndef DEV_LEAF_H
#define DEV_LEAF_H
#include "device_level.h"
#include <stdbool.h>
struct level_leaf_api;

bool dev_leaf_register(struct level_leaf_api *leaf_api);
#endif
